export KEYMAPPER=id2b
export USE_APKSIGNER=y
export FIND_KEYS_BY_ID=y
export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
export STRIP_HEX_KEY_ID_PREFIX=y
export SOFTHSM_LOGS_DIR=${SOFTHSM_LOGS_DIR:-$(pwd)/logs}
export DATE_FORMAT=${DATE_FORMAT:-%Y%m%d-%H%M%S}

maybe_dry_run=${maybe_dry_run:-}

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # There's got to be a better way.
  local -a possible_paths=(
    /usr{/local,}/lib{/x86_64-linux-gnu,64,}{/pkcs11,}/libsofthsm2.so
  )
  local path; for path in "${possible_paths[@]}"; do
    if [ -e "$path" ]; then
      PKCS11_MODULE=$path
      return 0
    fi
  done
  echo "Please install the SoftHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
  return 1
}
find_pkcs11_module
export PKCS11_MODULE

initialize_release_vendor() {
  # Must be overridden, but we have nothing to do.
  true
}
