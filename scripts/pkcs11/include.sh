#!/bin/bash
OPENSSL_BIN=${OPENSSL_BIN:-$(which openssl)}
PKCS11_TOOL_BIN=${PKCS11_TOOL_BIN:-$(which pkcs11-tool)}
if [ -n "${OPENSSL_BIN:-}" ] && [ -z "${PKCS11_OPENSSL_ENGINE_LIBRARY_PATH:-}" ]; then
  PKCS11_OPENSSL_ENGINE_LIBRARY_PATH=${PKCS11_OPENSSL_ENGINE_LIBRARY_PATH:-$(find /usr/local -path '/usr/local/lib*/engines-3/libpkcs11.so' | head -n 1)}
  PKCS11_OPENSSL_ENGINE_LIBRARY_PATH=${PKCS11_OPENSSL_ENGINE_LIBRARY_PATH:-$(find /usr -path '/usr/lib*/engines-3/libpkcs11.so' | head -n 1)}
  export PKCS11_OPENSSL_ENGINE_LIBRARY_PATH
fi

if ! XXD_BIN=${XXD_BIN:-$(which xxd)}; then
  echo "ERROR: Please install xxd, or set XXD_BIN to its path." >&2
  exit 1
fi

generate_openssl_config() {
  cat <<EOF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = ${PKCS11_OPENSSL_ENGINE_LIBRARY_PATH:-}
MODULE_PATH = ${PKCS11_MODULE:-}
init = 0
EOF

if [ -n "${PKCS11_PIN:-}" ]; then
  printf "PIN = %s\n" "$PKCS11_PIN"
fi

if [ -n "${PKCS11_OPENSSL_CONFIG_EXTRA:-}" ]; then
  printf "%s\n" "$PKCS11_OPENSSL_CONFIG_EXTRA"
fi
}

generate_sunpkcs11_config() {
  # TODO: Support slotListIndex != 0?
  cat <<EOF
name = PKCS11
description = SunPKCS11
library = ${PKCS11_MODULE:-}
slotListIndex = 0
EOF
  if [ -n "${PKCS11_SUN_CONFIG_EXTRA:-}" ]; then
    printf "%s\n" "$PKCS11_SUN_CONFIG_EXTRA"
  fi
}

find_id_for_key() {
  local key=$1
  if [ "${FIND_KEYS_BY_ID:-}" = "y" ]; then
    # This would be returning the key ID from the perspective of pkcs11-tool anyway.
    # Therefore, we should get the form of the key ID that we use with pkcs11-tool.
    key=$(get_key_id_for_pkcs11-tool "$key")
    printf "%s\n" "$key"
    return 0
  fi
  local -a args
  if [ "${LIST_REQUIRES_NO_PIN:-n}" = "y" ]; then
    args=("${pkcs11_tool_args_no_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi
  local result
  result=$(PKCS11_PIN=${PKCS11_PIN:-} PKCS11_SO_PIN=${PKCS11_SO_PIN:-} \
    "$PKCS11_TOOL_BIN" --list-objects --type cert \
    --label "$key" "${args[@]}") || return $?
  printf "%s\n" "$result" | sed -n -e 's/^  ID: \+//p' || true
}

key_id_exists() {
  local key_id=$1
  key_id=$(get_key_id_for_pkcs11-tool "$key_id")
  local -a args
  if [ "${LIST_REQUIRES_NO_PIN:-}" = "y" ]; then
    args=("${pkcs11_tool_args_no_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi
  local output
  output=$(PKCS11_PIN=${PKCS11_PIN:-} PKCS11_SO_PIN=${PKCS11_SO_PIN:-} \
    "$PKCS11_TOOL_BIN" --list-objects --type pubkey --id "$key_id" \
    "${args[@]}") || exit $?
  [ -n "$output" ]
}

get_rsa_key_size() {
  local key_id=$1
  key_id=$(get_key_id_for_pkcs11-tool "$key_id")
  local -a args
  if [ "${LIST_REQUIRES_NO_PIN:-n}" = "y" ]; then
    args=("${pkcs11_tool_args_no_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi
  local output
  output=$(PKCS11_PIN=${PKCS11_PIN:-} PKCS11_SO_PIN=${PKCS11_SO_PIN:-} \
    "$PKCS11_TOOL_BIN" --list-objects --type pubkey --id "$key_id" \
    "${args[@]}") || return $?
  local rsa_key_size
  rsa_key_size=$(printf "%s\n" "$output" |
    sed -n -e 's/^Public Key Object; RSA \(.*\) bits$/\1/p') || return $?
  printf "%s;%s\n" "$rsa_key_size" "$key_id"
}

get_id_and_rsa_key_size_for_key() {
  local key=$1
  local -a args
  if [ "${LIST_REQUIRES_NO_PIN:-n}" = "y" ]; then
    args=("${pkcs11_tool_args_no_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi
  if [ "${FIND_KEYS_BY_ID:-}" = "y" ]; then
    key=$(get_key_id_for_pkcs11-tool "$key")
    local output
    output=$(PKCS11_PIN=${PKCS11_PIN:-} PKCS11_SO_PIN=${PKCS11_SO_PIN:-} \
      "$PKCS11_TOOL_BIN" --list-objects --type pubkey --id "$key" \
      "${args[@]}") || return $?
    rsa_key_size=$(printf "%s\n" "$output" |
      sed -n -e 's/^Public Key Object; RSA \(.*\) bits$/\1/p') || return $?
    printf "%s;%s\n" "$key" "$rsa_key_size"
    return 0
  fi
  local output
  output=$(PKCS11_PIN=${PKCS11_PIN:-} PKCS11_SO_PIN=${PKCS11_SO_PIN:-} \
    "$PKCS11_TOOL_BIN" --list-objects --type pubkey --label "$key" \
    "${args[@]}") || return $?
  local key_id
  if [ "${FIND_KEYS_BY_ID:-n}" = "y" ]; then
    key_id=$key
  else
    key_id=$(printf "%s\n" "$output" | sed -n -e 's/^  ID: \+//p') || return $?
  fi
  local rsa_key_size
  rsa_key_size=$(printf "%s\n" "$output" |
    sed -n -e 's/^Public Key Object; RSA \(.*\) bits$/\1/p') || return $?
  printf "%s;%s\n" "$key_id" "$rsa_key_size"
}

_escape_for_uri() {
  local escapee=$1
  escapee=${escapee//\//%2f}
  escapee=${escapee//;/%3b}
  printf "%s\n" "$escapee"
}

_hex_id_for_uri() {
  local escapee=$1
  printf "%s\n" "$escapee" | sed -e 's/\(..\)/%\1/g'
}

get_key_name() {
  local key=$1
  if [ -n "${KEY_DIR:-}" ]; then
    key=${key#$KEY_DIR*}
    key=${key%.pem}
  fi
  printf "%s\n" "$key"
}

get_key_id_for_pkcs11-tool() {
  local key_id=$1
  if [ "${STRIP_HEX_KEY_ID_PREFIX:-}" = "y" ]; then
    key_id=${key_id#0x}
  fi
  printf "%s\n" "$key_id"
}

get_privkey_uri() {
  local key=$1
  if [ "${STRIP_HEX_KEY_ID_PREFIX:-}" = "y" ]; then
    key=${key#0x}
  fi
  if [ "${OPENSSL_PKCS11_URI_USES_HEX_KEY_ID:-}" = "y" ]; then
    uri="pkcs11:id=$(_hex_id_for_uri "$key")"
  else
    uri="pkcs11:object=$(_escape_for_uri "$key")"
  fi
  printf "%s;type=private\n" "$uri"
}

refresh_pkcs11_tool_args() {
  declare -g -a pkcs11_tool_args_no_pin=()
  [ -z "${PKCS11_MODULE:-}" ] || pkcs11_tool_args_no_pin+=(--module "$PKCS11_MODULE")
  [ -z "${PKCS11_TOKEN_LABEL:-}" ] || pkcs11_tool_args_no_pin+=(--token-label "$PKCS11_TOKEN_LABEL")
  [ -z "${PKCS11_SLOT:-}" ] || pkcs11_tool_args_no_pin+=(--slot "$PKCS11_SLOT")
  declare -g -a pkcs11_tool_args=("${pkcs11_tool_args_no_pin[@]}")
  [ -z "${PKCS11_PIN:-}" ] || pkcs11_tool_args+=(--pin env:PKCS11_PIN)
  declare -g -a pkcs11_tool_args_so_pin=("${pkcs11_tool_args_no_pin[@]}")
  [ -z "${PKCS11_SO_PIN:-}" ] || pkcs11_tool_args_so_pin+=(--login-type so --so-pin env:PKCS11_SO_PIN)
}

refresh_pkcs11_tool_args

ensure_key_is_available() {
  # Do nothing by default; keys are expected to be available.
  # This can be overridden by vendor includes, in which case it should make a key available
  # when it is not already available. If it cannot do so, it should return with a failure.
  true
}
