#!/bin/bash
scriptpath="$(cd "$(dirname "$BASH_SOURCE")";pwd -P)"

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
