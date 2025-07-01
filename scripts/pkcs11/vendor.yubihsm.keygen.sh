#!/bin/bash
set -euo pipefail

ourpath=$(cd "$(dirname "$0")";pwd -P)
scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
source "$scriptpath/keygen.include.sh" || exit $?

trap cleanup EXIT

unset TEMP_DIR
unset KEY_ID

pkcs11-tool_for_yubihsm() {
  PKCS11_PIN=$PKCS11_PIN \
  YUBIHSM_PKCS11_CONF=<(_generate_yubihsm_pkcs11_library_config) \
    "$UNDERLYING_PKCS11_TOOL_BIN" "$@" || return $?
}

openssl_for_yubihsm() {
  PKCS11_PIN=$PKCS11_PIN \
  YUBIHSM_PKCS11_CONF=<(_generate_yubihsm_pkcs11_library_config) \
    "$UNDERLYING_OPENSSL_BIN" "$@" || return $?
}

initialize_pre_metadata() {
  TEMP_DIR=$(mktemp -d /dev/shm/keygen-XXXXXXXX) || return $?
  if [ -z "${YUBIHSM_CONNECTOR_HOST:-}" ]; then
    YUBIHSM_CONNECTOR_HOST=http://127.0.0.1:12345
    echo "YUBIHSM_CONNECTOR_HOST not specified. Using $YUBIHSM_CONNECTOR_HOST." >&2
  fi

  if [ -z "${YUBIHSM_AUTHKEY:-}" ]; then
    YUBIHSM_AUTHKEY=1
    echo "YUBIHSM_AUTHKEY not specified. Using $YUBIHSM_AUTHKEY." >&2
  fi
  if [ -z "${YUBIHSM_PASSWORD:-}" ]; then
    YUBIHSM_PASSWORD=password
    echo "YUBIHSM_PASSWORD not specified. Using $YUBIHSM_PASSWORD." >&2
  fi

  source "$ourpath/vendor.yubihsm.include.sh" || exit $?

  # Construct PKCS11_PIN from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD.
  # See: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html#logging-in
  if [ -n "${PKCS11_PIN:-}" ]; then
    echo "WARNING: Specified PKCS11_PIN is ignored! It is constructed from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD." >&2
  fi
  PKCS11_PIN=$(printf '%4s\n' "$YUBIHSM_AUTHKEY" | tr ' ' 0)$YUBIHSM_PASSWORD

  #PKCS11_OPENSSL_CONFIG_EXTRA="INIT_ARGS = connector=$YUBIHSM_CONNECTOR_HOST debug"
  initialize_pre_metadata_pkcs11 "$@" || return $?
  #LIST_REQUIRES_NO_PIN=y
  #MODIFICATION_USES_SO_PIN=y
  #KEY_LABEL_IS_HEX=y
  if [ -z "${YUBIHSM_KEY_CAPABILITIES:-}" ]; then
    YUBIHSM_KEY_CAPABILITIES="sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,exportable-under-wrap,sign-attestation-certificate"
    echo "YUBIHSM_KEY_CAPABILITIES not specified. Using $YUBIHSM_KEY_CAPABILITIES." >&2
  fi
  UNDERLYING_PKCS11_TOOL_BIN=$PKCS11_TOOL_BIN
  UNDERLYING_OPENSSL_BIN=$OPENSSL_BIN
  PKCS11_TOOL_BIN=pkcs11-tool_for_yubihsm
  OPENSSL_BIN=openssl_for_yubihsm
  local missing_something=
  if ! YUBIHSM_SHELL_BIN=${YUBIHSM_SHELL_BIN:-$(which yubihsm-shell)}; then
    echo "Please install yubihsm-shell, or set YUBIHSM_SHELL_BIN to its path." >&2
    missing_something=1
  fi
  if [ -n "$missing_something" ]; then
    exit 1
  fi
}

initialize_post_metadata() {
  initialize_post_metadata_pkcs11 "$@" || return $?
  # TODO: initialization
  #maybe_provision_or_unlock_hsm || return $?
  #maybe_add_operator || return $?
}

generate_keypair() {
  local key_id=$1
  local key_label=$2  # unused
  # Password shouldn't just be on the command line, ideally...
  # However, for production, this should all be run on an air-gapped machine in a temporary
  # environment, so it could be worse.
  # TODO: Provide a notice for / document the above.
  "$YUBIHSM_SHELL_BIN" --authkey="$YUBIHSM_AUTHKEY" --password="$YUBIHSM_PASSWORD" \
    -a generate-asymmetric-key --algorithm="rsa$RSA_KEY_SIZE" -i "0x$key_id" \
    --capabilities="$YUBIHSM_KEY_CAPABILITIES" || return $?
  # --label="$key_label"
}

generate_cert() {
  local key_id=$1
  local key_label=$2  # unused
  local key_type=$3
  local key_name=$4
  local dstdir=$public_key_out_dir
  "$YUBIHSM_SHELL_BIN" --authkey="$YUBIHSM_AUTHKEY" --password="$YUBIHSM_PASSWORD" \
    -a sign-attestation-certificate -i "0x$key_id" --attestation-id 0 \
    --out "$dstdir/$key_id.x509.pem" || return $?
  "$YUBIHSM_SHELL_BIN" --authkey="$YUBIHSM_AUTHKEY" --password="$YUBIHSM_PASSWORD" \
    -a put-opaque -i "0x$key_id" -A opaque-x509-certificate --informat=PEM \
    --in "$dstdir/$key_id.x509.pem" || return $?

  # Output the certificate and the public key.
  local name=$key_id
  case "$key_type" in
    avb|apex_payload|apex_container)
      if [ -e "$dstdir/$name.pem" ]; then
        echo "Public key file already exists: $dstdir/$name.pem" >&2
      else
        # Output public key and avbpubkey for APEX payload or AVB keys.
        # Also do this for core keys, since APEX might use them.
        "$OPENSSL_BIN" x509 -pubkey -noout -in "$dstdir/$key_id.x509.pem" -out "$dstdir/$name.pem" || return $?
      fi
      if [ -e "$dstdir/$name.avbpubkey" ]; then
        echo "avbpubkey file already exists: $dstdir/$name.avbpubkey" >&2
      else
        "$AVBTOOL_BIN" extract_public_key \
          --key "$dstdir/$name.pem" \
          --output "$dstdir/$name.avbpubkey" \
          || return $?
      fi
      ;;
  esac
}

ensure_key_not_exist() {
  # temp just say it does not exist
  #return 0
  ensure_key_not_exist_pkcs11 "$@" || return $?
}

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

cleanup() {
  if [ -n "${TEMP_DIR:-}" ]; then
    if [ "${CLEANUP_ON_EXIT:-y}" = "n" ]; then
      echo "Temp files retained at $TEMP_DIR." >&2
    else
      if [ -z "${CLEANUP_ON_EXIT:-}" ]; then
        echo >&2
        echo "Note: You can retain temp files and imported keys/certs for inspection by setting CLEANUP_ON_EXIT=n" >&2
        echo >&2
      fi
      rm -rf "$TEMP_DIR"
    fi
  fi
}

keygen_main "$@" || exit $?
