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

source "$pkcs11_scriptpath/include.sh" || exit $?
source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || exit $?

ourtmpdir=
cleanup() {
  $maybe_dry_run maybe_stop_apksigner_batch || true
  $maybe_dry_run maybe_stop_yubihsm_connector || true
  if [ -n "$ourtmpdir" ] && [ -d "$ourtmpdir" ]; then
    rm -rf "$ourtmpdir"
  fi
}

if [ "${DRY_RUN:-}" != "y" ]; then
  trap cleanup EXIT

  ourtmpdir=$(mktemp -d "${TMPDIR:-/tmp}/yhrelease.XXXXXXXX")
  chmod 0700 "$ourtmpdir"

  if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
    export YUBIHSM_PKCS11_CONF=$ourtmpdir/yubihsm_pkcs11.conf
    generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
  fi

  maybe_start_yubihsm_connector "$ourtmpdir/yubihsm_connector.pid"
  maybe_start_apksigner_batch "$ourtmpdir"
fi

if [ -z "${YUBIHSM_LOGS_DIR+x}" ]; then
  export YUBIHSM_LOGS_DIR=$(pwd)/logs
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
  export AUDIT_LOG_PATH=$YUBIHSM_LOGS_DIR/${AUDIT_LOG_PATH:-$default_prefix-audit.log}
  export EXEC_LOG_PATH=$YUBIHSM_LOGS_DIR/${EXEC_LOG_PATH:-$default_prefix-exec.log}
fi

if [ "${DRY_RUN:-}" != "y" ] && [ -n "${EXEC_LOG_PATH:-}" ]; then
  "$command_to_execute" "$@" 2>&1 | tee -a "$EXEC_LOG_PATH" || exit $?
  cleanup
  trap "" EXIT
else
  "$command_to_execute" "$@" || exit $?
fi
