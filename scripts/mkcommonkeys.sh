#!/bin/bash
set -euo pipefail
if [ -d "$1" ]; then
  echo "key directory already exists" >&2
  exit 1
fi
mkdir -p "$1"
scriptpath=$(cd "$(dirname "$0")" || exit $?;pwd -P)
exec "$scriptpath/updatecommonkeys.sh" "$@"
