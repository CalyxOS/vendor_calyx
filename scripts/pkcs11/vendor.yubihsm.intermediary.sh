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

  # TODO: Remove me! Only here for debugging.
  { printf "%q " "${args[@]}"; echo; } > last_command.txt

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
  # TODO: Something. Anything. If needed, anyway...
  args=("$@")
}

handle_java() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --ks-key-alias)
        # The key alias for Java starts with 0x, unlike the ID for pkcs11-tool.
        # So, prepend 0x to it.
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
