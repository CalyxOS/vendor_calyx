#!/bin/bash

dry_run() {
  printf "%q " "$@" >&2
  echo >&2
}
if [ "${DRY_RUN:-}" = "y" ]; then
  maybe_dry_run=dry_run
  maybe_dry_run_ignore=true  # runs the command "true" which does and outputs nothing
else
  maybe_dry_run=
  maybe_dry_run_ignore=
fi

load_keymapper() {
  local scriptpath
  scriptpath=$(cd "$(dirname "${BASH_SOURCE[0]}")" || exit $?;pwd -P) || return $?
  local keymapper_path
  if [ -n "${KEYMAPPER_FILE:-}" ]; then
    keymapper_path=$(cd "$scriptpath"; realpath -e "$KEYMAPPER_FILE") || return $?
  else
    local keymapper=${KEYMAPPER:-legacy}
    keymapper_path=$(cd "$scriptpath"; realpath -e "keymapper.$keymapper.include.sh" || true)
    if [ -z "$keymapper_path" ]; then
      echo "Could not find keymapper '$keymapper'." >&2
      return 1
    fi
  fi
  source "$keymapper_path" || {
    local err=$?
    echo "Loading keymapper script failed!" >&2
    return $?
  }
  initialize_keymapper || {
    local err=$?
    echo "Failed to initialize keymapper: $keymapper_path" >&2
    return $err
  }
}

initialize_keymapper() {
  # This method must be overridden by keymapper include.
  echo "Not a keymapper file or does not override initialize_keymapper" >&2
  return 1
}
