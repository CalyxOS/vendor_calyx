#!/bin/bash
# WIP
set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")/..";pwd -P)"

KEYMAPPER=modern exec "$SCRIPTPATH/release.sh" "$@"
