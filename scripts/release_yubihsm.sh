#!/bin/bash
# WIP
set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

SIGN_COMMAND_INTERMEDIARY=$SCRIPTPATH/pkcs11/vendor.yubihsm.intermediary.sh PKCS11_VENDOR=yubihsm exec "$SCRIPTPATH/release.sh" "$@"
