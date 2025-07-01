#!/bin/bash
scriptpath="$(cd "$(dirname "$BASH_SOURCE")";pwd -P)"

_common_cleanup_complete=

dry_run() {
  printf "%q " "$@" >&2
  echo >&2
}
if [ "${DRY_RUN:-}" = "y" ]; then
  maybe_dry_run=dry_run
  maybe_dry_run_ignore=true  # runs the command "true" which does and outputs nothing
else
  maybe_dry_run=
  maybe_dry_run_ignore=
fi

load_keymapper() {
  local keymapper_path
  if [ -n "${KEYMAPPER_FILE:-}" ]; then
    keymapper_path=$(cd "$scriptpath"; realpath -e "$KEYMAPPER_FILE") || return $?
  else
    local keymapper=${KEYMAPPER:-legacy}
    keymapper_path=$(cd "$scriptpath"; realpath -e "keymapper.$keymapper.include.sh" || true)
    if [ -z "$keymapper_path" ]; then
      echo "Could not find keymapper '$keymapper'." >&2
      return 1
    fi
  fi
  source "$keymapper_path" || {
    local err=$?
    echo "Loading keymapper script failed!" >&2
    return $?
  }
  initialize_keymapper || {
    local err=$?
    echo "Failed to initialize keymapper: $keymapper_path" >&2
    return $err
  }
}

initialize_keymapper() {
  # This method must be overridden by keymapper include.
  echo "Not a keymapper file or does not override initialize_keymapper" >&2
  return 1
}

initialize_vendor_interactive() {
  # This method may be overridden by vendor include.
  true
}

initialize_vendor() {
  # This method must be overridden by vendor include.
  echo "Not a vendor include file or does not override initialize_vendor" >&2
  return 1
}

initialize_vendor_release() {
  # This method must be overridden by vendor include.
  echo "Not a vendor include file or does not override initialize_vendor_release" >&2
  return 1
}

initialize_vendor_release_child() {
  # This method must be overridden by vendor include.
  echo "Not a vendor include file or does not override initialize_vendor_release_child" >&2
  return 1
}

finalize_vendor() {
  # This method may be overridden by vendor include.
  true
}

finalize_vendor_release() {
  # This method may be overridden by vendor include.
  true
}

maybe_initialize_vendor_interactive() {
  if is_vendor_initialization_needed && \
     [ "${PKCS11_VENDOR_INITIALIZED_INTERACTIVE:-}" != "y" ]; then
    initialize_vendor_interactive "$@" || return $?
    export PKCS11_VENDOR_INITIALIZED_INTERACTIVE=y
  fi
}

maybe_initialize_vendor() {
  if is_vendor_initialization_needed && \
     [ "${PKCS11_VENDOR_INITIALIZED:-}" != "y" ]; then
    initialize_vendor "$@" || return $?
    export PKCS11_VENDOR_INITIALIZED=y
  fi
}

maybe_initialize_vendor_release() {
  if is_vendor_initialization_needed && \
     [ "${PKCS11_VENDOR_INITIALIZED_RELEASE:-}" != "y" ]; then
    initialize_vendor_release "$@" || return $?
    export PKCS11_VENDOR_INITIALIZED_RELEASE=y
  fi
}

maybe_initialize_vendor_release_child() {
  if is_vendor_initialization_needed && \
     [ "${PKCS11_VENDOR_INITIALIZED_RELEASE_CHILD:-}" != "y" ]; then
    initialize_vendor_release_child "$@" || return $?
    export PKCS11_VENDOR_INITIALIZED_RELEASE_CHILD=y
  fi
}

prepare_for_signing_full() {
  load_keymapper_and_maybe_pkcs11 || return $?
  maybe_initialize_vendor_noninteractive || return $?
  maybe_initialize_vendor_release_child || return $?
  prepare_signing_args || return $?
}

is_vendor_initialization_needed() {
  if [ -n "${PKCS11_VENDOR:-}" ] || [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    return 0  # true
  else
    return 1  # false
  fi
}

load_keymapper_and_maybe_pkcs11() {
  if [ -n "${PKCS11_MODULE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ] || \
     [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    source "$scriptpath/pkcs11/include.sh"
    if [ -n "${PKCS11_VENDOR_FILE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ]; then
      if [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
        source "$PKCS11_VENDOR_FILE" || return $?
      elif [ -n "${PKCS11_VENDOR:-}" ]; then
        pkcs11_vendor_path=$(cd "$scriptpath"; realpath -e "pkcs11/vendor.${PKCS11_VENDOR}.include.sh" || true)
        if [ -z "$pkcs11_vendor_path" ]; then
          echo "Could not find PKCS#11 vendor include script for '$PKCS11_VENDOR'." >&2
          exit 1
        fi
        source "$pkcs11_vendor_path" || return $?
      fi
    fi
  fi
  load_keymapper || return $?
}

maybe_initialize_vendor_noninteractive() {
  $maybe_dry_run maybe_initialize_vendor || return $?
  $maybe_dry_run maybe_initialize_vendor_release || return $?
}

prepare_signing_args() {
  if [ -n "${PKCS11_MODULE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ] || \
     [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    tmpdir=$(mktemp -d -p "$TMPDIR")
    $maybe_dry_run generate_sunpkcs11_config \
      | $maybe_dry_run_ignore tee "$tmpdir/sunpkcs11.cfg" >/dev/null
    local tool=${SIGNING_HELPER_TOOL:-openssl}
    local signing_helper_tool=vendor/calyx/scripts/pkcs11/signing_helper.$tool.sh
    local payload_signer_tool=vendor/calyx/scripts/pkcs11/payload_signer.$tool.sh
    if [ ! -e "$signing_helper_tool" ] || [ ! -e "$payload_signer_tool" ]; then
      echo "Looking for SIGNING_HELPER_TOOL '$tool', missing '$signing_helper_tool' and/or '$payload_signer_tool'" >&2
      return 1
    fi
    EXTRA_RELEASETOOLS_ARGS+=(
      --verbose
      --pkcs11_config "$tmpdir/sunpkcs11.cfg"
      --extra_avbtool_signing_args "--signing_helper $signing_helper_tool"
    )
    common_args=(
      --payload_signer "$payload_signer_tool"
    )
    EXTRA_SIGNING_ARGS+=("${common_args[@]}")
    EXTRA_OTA_ARGS+=("${common_args[@]}")
  fi

  if [ -n "${SIGNING_COMMAND_INTERMEDIARY:-}" ]; then
    common_args=(
      --signing_command_intermediary "$SIGNING_COMMAND_INTERMEDIARY"
    )
    EXTRA_SIGNING_ARGS+=("${common_args[@]}")
    EXTRA_OTA_ARGS+=("${common_args[@]}")
  fi

  # Payload signer maximum signature size is set to 512 in the metadata file by default
  # to accommodate RSA4096 keys.
  if [ -n "${PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE:-}" ]; then
    common_args=(
      --payload_signer_maximum_signature_size "$PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE"
    )
    EXTRA_SIGNING_ARGS+=("${common_args[@]}")
    EXTRA_OTA_ARGS+=("${common_args[@]}")
  fi
}

ask_variable() {
  local var=$1
  local default_val=${2:-}
  local private=${3:-}
  local needs_val=${4:-y}
  if [ -n "${!var:-}" ] || { [ "$needs_val" != "y" ] && [ -n "${!var+x}" ]; }; then
    # Already set.
    if [ "$private" = "y" ]; then
      echo "Using $var from environment."
    else
      echo "Using $var=${!var} from environment."
    fi
    return 0
  fi
  if [ "$private" = "y" ]; then
    private=-s
  else
    private=
  fi
  local prompt="Enter $var"
  if [ -n "$default_val" ]; then
    prompt="$prompt [$default_val]"
    if [ "$needs_val" != "y" ]; then
      prompt="$prompt ("'""'" for none)"
    fi
  else
    if [ "$needs_val" != "y" ]; then
      prompt="$prompt (blank for none)"
    fi
  fi
  while [ -z "${!var:-}" ]; do
    read -r $private -p "$prompt: " "$var"
    if [ -n "$private" ]; then
      echo
    fi
    declare -g "$var=${!var:-$default_val}"
    if [ "$needs_val" != "y" ]; then
      if [ "${!var}" = '""' ]; then
        declare -g "$var="
      fi
      break
    fi
  done
}

run_logged_command() {
  if [ "${DRY_RUN:-}" != "y" ] && [ -n "${EXEC_LOG_PATH:-}" ]; then
    "$command_to_execute" "$@" 2>&1 | tee -a "$EXEC_LOG_PATH" || exit $?
  else
    "$command_to_execute" "$@" || exit $?
  fi
}

common_cleanup() {
  if [ "$_common_cleanup_complete" = "y" ]; then
    return 0
  fi
  local jobs=$(jobs -p) || true
  if [ -n "$jobs" ]; then
    kill $jobs 2>/dev/null || true
    jobs=$(jobs -p)
    if [ -n "$jobs" ]; then
      kill -9 $jobs 2>/dev/null || true
    fi
  fi
  _common_cleanup_complete=y
}

common_cleanup_with_vendor() {
  finalize_vendor || true
  finalize_vendor_release || true
  common_cleanup || true
}
