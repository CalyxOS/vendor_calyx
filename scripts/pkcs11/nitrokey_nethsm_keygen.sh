#!/bin/bash
set -euo pipefail

SCRIPTPATH=$(cd "$(dirname "$0")";pwd -P)
source "$SCRIPTPATH/keygen.include.sh" || exit $?

trap cleanup EXIT

unset TEMP_DIR
unset KEY_ID

pkcs11-tool_for_nethsm() {
  P11NETHSM_CONFIG_FILE=<(_generate_nethsm_pkcs11_library_config)
    "$UNDERLYING_PKCS11_TOOL_BIN" "$@" || return $?
}

initialize_pre_metadata() {
  initialize_pre_metadata_pkcs11 "$@" || return $?
  LIST_REQUIRES_NO_PIN=y
  MODIFICATION_USES_SO_PIN=y
  KEY_LABEL_IS_HEX=y
  FIND_KEYS_BY_ID=y
  UNDERLYING_PKCS11_TOOL_BIN=$PKCS11_TOOL_BIN
  PKCS11_TOOL_BIN=pkcs11-tool_for_nethsm
  [ -n "${NETHSM_HOST:-}" ] || { NETHSM_HOST=127.0.0.1:8443; echo "NETHSM_HOST not specified. Using $NETHSM_HOST." >&2; }
  [ -n "${NETHSM_ADMIN:-}" ] || { NETHSM_ADMIN=admin; echo "NETHSM_ADMIN not specified. Using $NETHSM_ADMIN." >&2; }
  [ -n "${NETHSM_OPERATOR:-}" ] || { NETHSM_OPERATOR=operator1; echo "NETHSM_OPERATOR not specified. Using $NETHSM_OPERATOR." >&2; }
  [ -n "${NETHSM_ADMIN_PASSWORD:-}" ] || { NETHSM_ADMIN_PASSWORD=adminadmin; echo "NETHSM_ADMIN_PASSWORD not specified. Using $NETHSM_ADMIN_PASSWORD." >&2; }
  [ -n "${NETHSM_OPERATOR_PASSWORD:-}" ] || { NETHSM_OPERATOR_PASSWORD=adminadmin; echo "NETHSM_OPERATOR_PASSWORD not specified. Using $NETHSM_OPERATOR_PASSWORD." >&2; }
  [ -n "${NETHSM_UNLOCK_PASSWORD:-}" ] || { NETHSM_UNLOCK_PASSWORD=unlockunlock; echo "NETHSM_UNLOCK_PASSWORD not specified. Using $NETHSM_UNLOCK_PASSWORD." >&2; }
  local missing_something=
  if ! NITROPY_BIN=${NITROPY_BIN:-$(which nitropy)}; then
    echo "Please install nitropy, or set NITROPY_BIN to its path." >&2
    missing_something=1
  fi
  if [ -n "$missing_something" ]; then
    exit 1
  fi
}

initialize_post_metadata() {
  initialize_post_metadata_pkcs11 "$@" || return $?
  maybe_provision_or_unlock_hsm || return $?
  maybe_add_operator || return $?
}

generate_keypair() {
  generate_keypair_pkcs11 "$@" || return $?
}

generate_cert() {
  generate_cert_pkcs11 "$@" || return $?
}

ensure_key_not_exist() {
  ensure_key_not_exist_pkcs11 "$@" || return $?
}

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # There's got to be a better way.
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/pkcs11/libnethsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/libnethsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/pkcs11/libnethsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/libnethsm_pkcs11.so' | head -n 1)}
  if [ -z "$PKCS11_MODULE" ]; then
    echo "Please install the Nitrokey NetHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
    return 1
  fi
}

maybe_provision_or_unlock_hsm() {
  local state
  state=$(_nethsm state) || return $?
  case "$state" in
    *" is Unprovisioned")
      echo "WARNING: Insecurely provisioning NetHSM for testing!" >&2
      echo "         Passwords in the clear on command line; unattended boot will be on!" >&2
      _nethsm provision \
        --unlock-passphrase "$NETHSM_UNLOCK_PASSWORD" \
        --admin-passphrase "$NETHSM_ADMIN_PASSWORD" \
        || return $?
      _nethsm set-unattended-boot on || return $?
      ;;
    *" is Locked")
      _nethsm unlock "$NETHSM_UNLOCK_PASSWORD" || return $?
      ;;
    *" is Operational")
      true
      ;;
  esac
}

maybe_add_operator() {
  if ! _nethsm list-users | tail -n+5 | awk '{print $1}' | grep -qFx -- "$NETHSM_OPERATOR"; then
    echo "Missing operator user '$NETHSM_OPERATOR'; adding..." >&2
    _nethsm add-user \
      --user-id "$NETHSM_OPERATOR" \
      --passphrase "$NETHSM_OPERATOR_PASSWORD" \
      --role Operator \
      --real-name "$NETHSM_OPERATOR"
  fi
}

generate_and_import_test_key_and_cert() {
  TEMP_DIR=$(mktemp -d /dev/shm/repro-XXXXXXXX) || return $?
  KEY_ID=$(basename "$TEMP_DIR")
  KEY_ID=${KEY_ID/-/}
  chmod go-rwx "$TEMP_DIR" || true
  (
    cd "$TEMP_DIR" || return $?
    "$OPENSSL" genrsa -out privkey.pem "$RSA_KEY_SIZE" || return $?
    "$OPENSSL" rsa -in privkey.pem -pubout -out pubkey.pem || return $?
    "$OPENSSL" req -subj "/CN=${KEY_ID}/emailAddress=address@example.com" -new -x509 -key privkey.pem -days 7300 -out pub.x509.pem || return $?
    "$OPENSSL" pkcs12 -export -inkey privkey.pem -in pub.x509.pem -out privkeypair.p12 -passout pass: || return $?
    "$OPENSSL" rsa -in privkey.pem -outform DER -out privkey.der || return $?
    "$OPENSSL" x509 -in pub.x509.pem -outform DER -out pub.x509.der || return $?
    _nethsm import-key --key-id "$KEY_ID" --mechanism RSA_Signature_PKCS1 privkey.pem || return $?
    _nethsm set-certificate --key-id "$KEY_ID" pub.x509.pem || return $?
    if [ -n "${PKCS11_SOFTHSM_LIBRARY_PATH:-}" ]; then
      PKCS11_PIN=$PKCS11_PIN \
        "$PKCS11_TOOL" --module "$PKCS11_SOFTHSM_LIBRARY_PATH" \
          --pin env:PKCS11_PIN \
          --write-object privkey.pem \
          --type privkey \
          --id "feedfeedfeedfeed1234" \
          --label "$KEY_ID" || return $?
      PKCS11_PIN=$PKCS11_PIN \
        "$PKCS11_TOOL" --module "$PKCS11_SOFTHSM_LIBRARY_PATH" \
          --pin env:PKCS11_PIN \
          --write-object pub.x509.pem \
          --type cert \
          --id "feedfeedfeedfeed1234" \
          --label "$KEY_ID" || return $?
    fi
  ) || return $?
}

_nethsm() {
  local args=(
    --host "$NETHSM_HOST"
    --username "$NETHSM_ADMIN"
    --password "$NETHSM_ADMIN_PASSWORD"
  )
  [ "${VERIFY_TLS:-}" = "y" ] || args+=(--no-verify-tls)
  "$NITROPY_BIN" nethsm "${args[@]}" "$@"
}

_generate_nethsm_pkcs11_library_config() {
  cat <<EOF
  slots:
    - label: Test HSM
      operator:
        username: "$NETHSM_OPERATOR"
        password: "$NETHSM_OPERATOR_PASSWORD"
      administrator:
        username: "$NETHSM_ADMIN"
        password: "$NETHSM_ADMIN_PASSWORD"
      instances:
        - url: "https://$NETHSM_HOST/api/v1"
          max_idle_connections: 10
          danger_insecure_cert: true
      retries:
        count: 3
        delay_seconds: 1
      tcp_keepalive:
        time_seconds: 600
        interval_seconds: 60
        retries: 3
      connections_max_idle_duration: 1800
      timeout_seconds: 30
EOF
}

_unused__start_new_podman_container() {
  local podman_run_args=(
    --name nethsm_testing
    #-v ./nethsm_data:/data:Z
    #-e DEBUG_LOG=1
    -ti
    -p 8443:8443
    --restart always
    -d
    docker.io/nitrokey/nethsm:testing
  )
  podman run "${podman_run_args[@]}" || return $?
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
      [ -z "${KEY_ID:-}" ] || _nethsm delete-key "$KEY_ID"
    fi
  fi
}

keygen_main "$@" || exit $?

echo >&2
echo "IMPORTANT: Nitrokey NetHSM has a unique concept of label vs ID and some other quirks." >&2
echo "           When signing with release.sh, set the following environment variables:" >&2
echo "           KEY_LABEL_IS_HEX=y FIND_KEYS_BY_ID=y LIST_REQUIRES_NO_PIN=y \\" >&2
echo "           SIGNING_USES_SO_PIN=y PREFER_OPENSSL=y" >&2
