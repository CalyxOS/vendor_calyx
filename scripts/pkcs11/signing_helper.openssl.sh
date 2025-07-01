#!/bin/bash
set -euo pipefail

SCRIPTPATH=$(cd "$(dirname "$0")";pwd -P)
source "$SCRIPTPATH/include.sh" || exit $?

main() {
  local algorithm=$1
  local key_file=$2
  shift 2

  if [ $# -gt 0 ]; then
    echo "Unexpected arguments: $*" >&2
    return 1
  fi

  # See external/avb/avbtool.py ALGORITHMS.
  local padding_size
  case "$algorithm" in
    SHA256_RSA2048) padding_size=$((3+202)) ;;
    SHA256_RSA4096) padding_size=$((3+458)) ;;
    SHA256_RSA8192) padding_size=$((3+970)) ;;
    SHA512_RSA2048) padding_size=$((3+170)) ;;
    SHA512_RSA4096) padding_size=$((3+426)) ;;
    SHA512_RSA8192) padding_size=$((3+938)) ;;
    *)
      echo "Unsupported/untested algorithm: $algorithm" >&2
      return 1
      ;;
  esac

  local uri=$(get_privkey_uri "${KEY_ID:-$(get_key_name "$key_file")}")

  tail -c+$((1+$padding_size)) | OPENSSL_CONF=<(generate_openssl_config) \
    "$OPENSSL_BIN" pkeyutl -engine pkcs11 -sign -keyform engine \
      -inkey "$uri" -pkeyopt rsa_padding_mode:pkcs1 || return $?
}

main "$@" || exit $?
