#!/bin/bash
set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")/..";pwd -P)"

export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
num_tries=5
is_a_signing_command=

main() {
  declare -g args=()
  cmd=$SIGNING_COMMAND
  if [ "$cmd" = "avbtool" ]; then
    handle_avbtool "$@"
  elif [ "$cmd" = "java" ]; then
    handle_java "$@"
  else
    args=("$@")
  fi
  { printf "%q " "$cmd" "${args[@]}"; echo; } > last_command.txt

  # Note: We expect nothing from stdin, so we don't handle it.

  # Try multiple times, backing off for longer after each try.
  local err=
  for try in $(seq 1 $num_tries); do
    "$cmd" "${args[@]}" || { err=$?; sleep $((try*3 + 2)); continue; }
    err=0
    break
  done
  if [ "$is_a_signing_command" = "y" ]; then
    source "$SCRIPTPATH/vendor.yubihsm.include.sh" || return $?
    extract_logs || return $?
  fi
  return $err
}

handle_avbtool() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --algorithm)
        # FIXME, temporary
        if [ $# -gt 1 ] && [ -n "${RSA_KEY_SIZE:-}" ]; then
          case "$2" in
            SHA256_RSA*|SHA512_RSA*)
              if [ "${2:10}" -gt "$RSA_KEY_SIZE" ]; then
                args+=("$1" "${2:0:10}$RSA_KEY_SIZE")
                shift 2
                continue
              fi ;;
          esac
        fi
        ;;
      --signing*)
        is_a_signing_command=y
        ;;
    esac
    args+=("$1")
    shift 1
  done
}

handle_java() {
  local jar=
  while [ $# -gt 0 ]; do
    case "$1" in
      -jar)
        jar=$(basename "${2:-}")
        jar=${jar%.jar}
        ;;
      --ks-key-alias)
        # Actually, this is not needed anymore...
        continue
        # Back when it was needed, we did this:
        if [ $# -gt 1 ] && [ "$jar" = "apksigner" ]; then
          # Add 0x to the private key.
          args+=("$1" "0x$2")
          shift 2
          continue
        fi
        ;;
    esac
    args+=("$1")
    shift 1
  done
  if [ "$jar" = "signapk" ]; then
    # Add 0x to the private key.
    local private_key_index=$((${#args[@]}-3))
    args[$private_key_index]=0x${args[$private_key_index]}
    is_a_signing_command=y
  elif [ "$jar" = "apksigner" ]; then
    is_a_signing_command=y
  fi
}

main "$@" || exit $?
