#!/bin/bash
# WIP
set -euo pipefail
pkcs11_scriptpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"
export PKCS11_VENDOR=softhsm

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

source "$pkcs11_scriptpath/include.sh" || exit $?
source "$pkcs11_scriptpath/vendor.softhsm.include.sh" || exit $?

if [ -n "${SOFTHSM_LOGS_DIR:-}" ]; then
  if [ ! -d "$SOFTHSM_LOGS_DIR" ]; then
    $maybe_dry_run mkdir "$SOFTHSM_LOGS_DIR" || {
      err=$?
      echo "SOFTHSM_LOGS_DIR ($SOFTHSM_LOGS_DIR) does not exist, and failed to create it" >&2
      return $err
    }
  fi
  timestamp=$(date -u +"${DATE_FORMAT:-%Y%m%d-%H%M%S}")
  DEVICE=$1
  default_prefix=$BUILD_NUMBER-$DEVICE-$timestamp-$(basename "$command_to_execute" .sh)
  export AUDIT_LOG_PATH=$SOFTHSM_LOGS_DIR/${AUDIT_LOG_PATH:-$default_prefix-audit.log}
  export EXEC_LOG_PATH=$SOFTHSM_LOGS_DIR/${EXEC_LOG_PATH:-$default_prefix-exec.log}
fi

if [ "${DRY_RUN:-}" != "y" ] && [ -n "${EXEC_LOG_PATH:-}" ]; then
  "$command_to_execute" "$@" 2>&1 | tee -a "$EXEC_LOG_PATH" || exit $?
else
  "$command_to_execute" "$@" || exit $?
fi
