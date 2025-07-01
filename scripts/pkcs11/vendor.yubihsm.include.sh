export RSA_KEY_SIZE=2048  # temporary
export KEYMAPPER=yubihsm
export USE_APKSIGNER=y
export PKCS11_PIN=$(printf "%4s" "$YUBIHSM_AUTHKEY" | tr ' ' 0)$YUBIHSM_PASSWORD
export FIND_KEYS_BY_ID=y

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # TODO: There's got to be a better way.
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/pkcs11/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/pkcs11/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/yubihsm_pkcs11.so' | head -n 1)}
  if [ -z "$PKCS11_MODULE" ]; then
    echo "Please install the YubiHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
    return 1
  fi
}
find_pkcs11_module
export PKCS11_MODULE

_generate_yubihsm_pkcs11_library_config() {
  # https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html
  cat <<EOF
# This is a sample configuration file for the YubiHSM PKCS#11 module
# Uncomment the various options as needed

# URL of the connector to use. This can be a comma-separated list
connector = http://127.0.0.1:12345

# Enables general debug output in the module
#
# debug

# Enables function tracing (ingress/egress) debug output in the module
#
# dinout

# Enables libyubihsm debug output in the module
#
# libdebug

# Redirects the debug output to a specific file. The file is created
# if it does not exist. The content is appended
#
# debug-file = /tmp/yubihsm_pkcs11_debug

# CA certificate to use for HTTPS validation. Point this variable to
# a file containing one or more certificates to use when verifying
# a peer. Currently not supported on Windows
#
# cacert = /tmp/cacert.pem

# Proxy server to use for the connector
# Currently not supported on Windows
#
# proxy = http://proxyserver.local.com:8080

# Timeout in seconds to use for the initial connection to the connector
# timeout = 5
EOF
}

if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
  export YUBIHSM_PKCS11_CONF=$(mktemp "${TMPDIR:-/tmp}/yubihsm_pkcs11.XXXXXXXX.conf")
  _generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
fi

get_key_id() {
  # This is an unfortunate amount of extra parsing to come up with an ID.
  # TODO: Find a way to mitigate that.
  local label=$1
  case "$label" in
    shared/*)
      ;;
    device/*)
      ;;
  esac
  case "$label" in
    */avb/vbmeta)
      ;;
    */avb/*)
      ;;
  esac
}
