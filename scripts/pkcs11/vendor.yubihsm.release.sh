#!/bin/bash
# WIP
set -euo pipefail
ourpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"
export SIGNING_COMMAND_INTERMEDIARY=$ourpath/vendor.yubihsm.intermediary.sh
export PKCS11_VENDOR=yubihsm

command_to_execute="$scriptpath/release.sh"
case "$(basename "$0")" in
  *.release.sh)
    true ;; # default
  *.generate_delta.sh)
    command_to_execute="$scriptpath/generate_delta.sh" ;;
  *)
    echo "Warning: The script '$0' has been renamed. Will assume you are using it for release." >&2
    ;;
esac

created_yubihsm_pkcs11_conf=
cleanup() {
  if [ "$created_yubihsm_pkcs11_conf" = "y" ]; then
    [ ! -e "$YUBIHSM_PKCS11_CONF" ] || rm -f "$YUBIHSM_PKCS11_CONF"
  fi
}
trap cleanup EXIT

source "$ourpath/include.sh" || exit $?
source "$ourpath/vendor.yubihsm.include.sh" || exit $?

if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
  created_yubihsm_pkcs11_conf=y
  export YUBIHSM_PKCS11_CONF=$(mktemp "${TMPDIR:-/tmp}/yubihsm_pkcs11.XXXXXXXX.conf")
  _generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
fi

if [ -n "${YUBIHSM_LOGS_DIR:-}" ]; then
  if [ ! -d "$YUBIHSM_LOGS_DIR" ]; then
    $maybe_dry_run mkdir "$YUBIHSM_LOGS_DIR" || {
      err=$?
      echo "YUBIHSM_LOGS_DIR ($YUBIHSM_LOGS_DIR) does not exist, and failed to create it" >&2
      return $err
    }
  fi
  timestamp=$(date -u +"${DATE_FORMAT:-%Y%m%d-%H%M%S}")
  DEVICE=$1
  default_suffix="$(basename "$command_to_execute" .sh)"-$timestamp-$BUILD_NUMBER-$DEVICE
  export AUDIT_LOG_PATH=${AUDIT_LOG_PATH:-$YUBIHSM_LOGS_DIR/audit-$default_suffix.log}
  export BUILD_LOG_PATH=${BUILD_LOG_PATH:-$YUBIHSM_LOGS_DIR/build-$default_suffix.log}
fi

if [ "${DRY_RUN:-}" != "y" ] && [ -n "${BUILD_LOG_PATH:-}" ]; then
  "$command_to_execute" "$@" 2>&1 | tee -a "$BUILD_LOG_PATH" || exit $?
else
  "$command_to_execute" "$@" || exit $?
fi


