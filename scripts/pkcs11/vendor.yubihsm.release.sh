#!/bin/bash
# WIP
set -euo pipefail
pkcs11_scriptpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"
export SIGNING_COMMAND_INTERMEDIARY=$pkcs11_scriptpath/vendor.yubihsm.intermediary.sh
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

source "$pkcs11_scriptpath/include.sh" || exit $?
source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || exit $?

if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
  created_yubihsm_pkcs11_conf=y
  export YUBIHSM_PKCS11_CONF=$(mktemp "${TMPDIR:-/tmp}/yubihsm_pkcs11.XXXXXXXX.conf")
  generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
fi

if [ -n "${YUBIHSM_LOGS_DIR:-}" ]; then
  if [ ! -d "$YUBIHSM_LOGS_DIR" ]; then
    $maybe_dry_run mkdir "$YUBIHSM_LOGS_DIR" || {
      err=$?
      echo "YUBIHSM_LOGS_DIR ($YUBIHSM_LOGS_DIR) does not exist, and failed to create it" >&2
      return $err
    }
  fi
  DEVICE=$1
  default_prefix=$BUILD_NUMBER-$DEVICE-$(get_name_for_hsm_and_session)-$(basename "$command_to_execute" .sh)
  export AUDIT_LOG_PATH=${AUDIT_LOG_PATH:-$default_prefix-audit.log}
  export EXEC_LOG_PATH=${EXEC_LOG_PATH:-$default_prefix-exec.log}
fi

if [ "${DRY_RUN:-}" != "y" ] && [ -n "${EXEC_LOG_PATH:-}" ]; then
  "$command_to_execute" "$@" 2>&1 | tee -a "$EXEC_LOG_PATH" || exit $?
else
  "$command_to_execute" "$@" || exit $?
fi
