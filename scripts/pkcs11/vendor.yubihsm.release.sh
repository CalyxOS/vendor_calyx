#!/bin/bash
# WIP
set -euo pipefail
ourpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"
export SIGNING_COMMAND_INTERMEDIARY=$scriptpath/pkcs11/vendor.yubihsm.intermediary.sh
export PKCS11_VENDOR=yubihsm

created_yubihsm_pkcs11_conf=
cleanup() {
  if [ "$created_yubihsm_pkcs11_conf" = "y" ]; then
    [ ! -e "$YUBIHSM_PKCS11_CONF" ] || rm -f "$YUBIHSM_PKCS11_CONF"
  fi
}
trap cleanup EXIT

source "$ourpath/vendor.yubihsm.include.sh" || exit $?

if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
  created_yubihsm_pkcs11_conf=y
  export YUBIHSM_PKCS11_CONF=$(mktemp "${TMPDIR:-/tmp}/yubihsm_pkcs11.XXXXXXXX.conf")
  _generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
fi

"$scriptpath/release.sh" "$@" || exit $?
