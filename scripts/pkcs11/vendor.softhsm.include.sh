export KEYMAPPER=id2b
export USE_APKSIGNER=y
export FIND_KEYS_BY_ID=y
export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
export STRIP_HEX_KEY_ID_PREFIX=y
export SOFTHSM_LOGS_DIR=${SOFTHSM_LOGS_DIR:-$(pwd)/logs}
export DATE_FORMAT=${DATE_FORMAT:-%Y%m%d-%H%M%S}

maybe_dry_run=${maybe_dry_run:-}

initialize_vendor() {
  # Must be overridden, but we have nothing to do.
  true
}

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

initialize_vendor_release() {
  # Must be overridden, but we have nothing to do.
  true
}

initialize_vendor_release_child() {
  local DEVICE=${1:-$DEVICE}
  local command=${2:-$0}
  if [ -n "${SOFTHSM_LOGS_DIR:-}" ]; then
    if [ ! -d "$SOFTHSM_LOGS_DIR" ]; then
      $maybe_dry_run mkdir "$SOFTHSM_LOGS_DIR" || {
        err=$?
        echo "SOFTHSM_LOGS_DIR ($SOFTHSM_LOGS_DIR) does not exist, and failed to create it" >&2
        return $err
      }
    fi
    timestamp=$(date -u +"${DATE_FORMAT:-%Y%m%d-%H%M%S}")
    DEVICE=$1
    default_prefix=$BUILD_NUMBER-$DEVICE-$timestamp-$(basename "$command" .sh)
    export AUDIT_LOG_PATH=$SOFTHSM_LOGS_DIR/${AUDIT_LOG_PATH:-$default_prefix-audit.log}
    export EXEC_LOG_PATH=$SOFTHSM_LOGS_DIR/${EXEC_LOG_PATH:-$default_prefix-exec.log}
  fi
}

populate_devices_with_loaded_keys_arrays() {
  # We assume all keys are loaded.
  devices_with_loaded_keys_arrays+=("$@")
}
