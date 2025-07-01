#!/bin/bash
scriptpath="$(cd "$(dirname "$0")";pwd -P)"

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
  source "$keymapper_path" || return $?
}

initialize_release_vendor() {
  # This method is overridable by vendor include.
  true
}

load_keymapper_and_maybe_pkcs11() {
  if [ -n "${PKCS11_MODULE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ] || [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    source "$scriptpath/pkcs11/include.sh"
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
    load_keymapper || return $?
    initialize_release_vendor || return $?
    tmpdir=$(mktemp -d)
    cleanup() {
      rm -f "$tmpdir/sunpkcs11.cfg"
      rmdir "$tmpdir"
    }
    trap cleanup EXIT
    _generate_sunpkcs11_config > "$tmpdir/sunpkcs11.cfg"
    tool=pkcs11-tool
    if [ "${PREFER_OPENSSL:-n}" = "y" ]; then
      tool=openssl
    fi
    EXTRA_RELEASETOOLS_ARGS+=(
      --verbose
      --pkcs11_config "$tmpdir/sunpkcs11.cfg"
      --extra_avbtool_signing_args "--signing_helper vendor/calyx/scripts/pkcs11/signing_helper.${tool}.sh"
    )
    common_args=(
      --payload_signer "vendor/calyx/scripts/pkcs11/payload_signer.${tool}.sh"
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
