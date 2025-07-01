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

  local key=$(get_key_name "$key_file")

  # Workaround for the fact that pkcs11-tool ignores --label during a --sign operation.
  local id
  id=$(find_id_for_cert "$key") || return $?
  if [ -z "$id" ]; then
    echo "Could not found find key with label '$key'" >&2
    return 1
  fi

  local args
  if [ "${SIGNING_USES_SO_PIN:-n}" = "y" ]; then
    args=("${pkcs11_tool_args_so_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi

  # The data we are signing is already padded and hashed.
  # Remove the padding so that we can use RSA-PKCS. This mechanism adds the padding back itself
  # while being more widely-supported.
  tail -c+$((1+padding_size)) | "$PKCS11_TOOL_BIN" --sign "${args[@]}" -m RSA-PKCS --id "$id" \
    || return $?
}

main "$@" || exit $?
