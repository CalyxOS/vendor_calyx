#!/bin/bash
set -euo pipefail

SCRIPTPATH=$(cd "$(dirname "$0")";pwd -P)
source "$SCRIPTPATH/include.sh" || exit $?

main() {
  # Handle arguments.
  args=()
  local input_file
  local output_file
  local key_file
  while [ $# -gt 0 ]; do
    case "$1" in
      "-in")
        input_file=$2
        shift 1
        ;;
      "-out")
        output_file=$2
        shift 1
        ;;
      "-inkey")
        key_file=$2
        shift 1
        ;;
    esac
    shift 1
  done

  local key=$(_get_key_name "$key_file")
  local uri=$(_get_privkey_uri "$key")

  OPENSSL_CONF=<(_generate_openssl_config) \
    "$OPENSSL_BIN" pkeyutl -sign -engine pkcs11 -keyform engine \
    -inkey "$uri" \
    -pkeyopt digest:sha256 \
    -in "$input_file" \
    -out "$output_file" \
    || return $?
}

main "$@" || exit $?
