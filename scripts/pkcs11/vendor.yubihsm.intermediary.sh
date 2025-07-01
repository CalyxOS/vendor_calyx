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
  { printf "%q " "${args[@]}"; echo; } > last_command.txt

  # Note: We expect nothing from stdin, so we don't handle it.

  # Try multiple times, backing off for longer after each try.
  local err=0
  for try in $(seq 1 $num_tries); do
    "$cmd" "${args[@]}" || { err=$?; sleep $((try*3 + 2)); continue; }
    err=0
  done
  return $err
}

handle_avbtool() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --algorithm)
        # FIXME, temporary
        if [ -n "${RSA_KEY_SIZE:-}" ] && [ "$RSA_KEY_SIZE" != 4096 ] && [ "${2:-}" = "SHA256_RSA4096" ]; then
          args+=("$1" "SHA256_RSA$RSA_KEY_SIZE")
          shift 2
          continue
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
