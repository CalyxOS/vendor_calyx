#!/bin/bash
scriptpath="$(cd "$(dirname "$BASH_SOURCE")";pwd -P)"

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

load_keymapper_and_maybe_pkcs11() {
  if [ -n "${PKCS11_MODULE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ] || [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    source "$scriptpath/pkcs11/include.sh"
    local should_initialize_vendor=n
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
      should_initialize_vendor=y
    fi
    load_keymapper || return $?
    if [ "$should_initialize_vendor" = "y" ]; then
      $maybe_dry_run initialize_vendor || return $?
      $maybe_dry_run initialize_vendor_release || return $?
    fi
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
  else
    # Not PKCS#11.
    load_keymapper || return $?
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
