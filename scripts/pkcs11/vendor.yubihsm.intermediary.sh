#!/bin/bash
set -euo pipefail

num_tries=5

main() {
  declare -g args=()
  cmd=$1
  shift 1
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
    esac
    args+=("$1")
    shift 1
  done
}

handle_java() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --ks-key-alias)
        if [ $# -gt 1 ]; then
          args+=("$1" "0x$2")
          shift 2
          continue
        fi
        ;;
    esac
    args+=("$1")
    shift 1
  done
}

main "$@"
