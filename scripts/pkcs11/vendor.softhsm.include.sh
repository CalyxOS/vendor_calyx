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
  local -a possible_module_paths=(
    /usr/local/lib64/pkcs11/libsofthsm2.so
    /usr/local/lib64/libsofthsm2.so
    /usr/local/lib/pkcs11/libsofthsm2.so
    /usr/local/lib/libsofthsm2.so
    /usr/lib64/pkcs11/libsofthsm2.so
    /usr/lib64/libsofthsm2.so
    /usr/lib/pkcs11/libsofthsm2.so
    /usr/lib/libsofthsm2.so
  )
  local module_path; for module_path in "${possible_module_paths[@]}"; do
    if [ -e "$module_path" ]; then
      PKCS11_MODULE=$module_path
      return 0
    fi
  done
  echo "Please install the SoftHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
  return 1
}
find_pkcs11_module
export PKCS11_MODULE
