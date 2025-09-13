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
  if [ -n "${fifo_keepalive_pid:-}" ] \
     && ps -p "$fifo_keepalive_pid" >/dev/null
  then
    kill "$fifo_keepalive_pid" || true
  fi
  if [ -n "${APKSIGNER_BATCH_PID:-}" ] && ps -p "$APKSIGNER_BATCH_PID" >/dev/null; then
    kill "$APKSIGNER_BATCH_PID" || true
  fi
  if [ -n "$ourtmpdir" ] && [ -d "$ourtmpdir" ]; then
    rm -rf "$ourtmpdir"
  fi
}

if [ "${DRY_RUN:-}" != "y" ]; then
  trap cleanup EXIT
  ourtmpdir=$(mktemp -d "${TMPDIR:-/tmp}/yhrelease.XXXXXXXX")
  chmod 0700 "$ourtmpdir"

  # Start apksigner in batch mode for improved performance, to be used by the signing intermediary.
  # Pass its stdin and stdout FIFOs in environment variables.
  export APKSIGNER_BATCH_STDIN_FIFO=$ourtmpdir/apksigner_stdin_fifo
  export APKSIGNER_BATCH_STDOUT_FIFO=$ourtmpdir/apksigner_stdout_fifo
  export APKSIGNER_BATCH_STDERR_FIFO=$ourtmpdir/apksigner_stderr_fifo
  mkfifo "$APKSIGNER_BATCH_STDIN_FIFO"
  mkfifo "$APKSIGNER_BATCH_STDOUT_FIFO"
  mkfifo "$APKSIGNER_BATCH_STDERR_FIFO"
  fifo_keepalive_pid=

  if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
    export YUBIHSM_PKCS11_CONF=$ourtmpdir/yubihsm_pkcs11.conf
    generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
  fi

  java_cmd=(java -Xmx4096m \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
    -Djava.library.path=$(pwd)/lib64 \
    -jar $(pwd)/framework/apksigner.jar
  )

  (
    err=0
    "${java_cmd[@]}" batch \
      < "$APKSIGNER_BATCH_STDIN_FIFO" \
      2> "$APKSIGNER_BATCH_STDERR_FIFO" \
      > "$APKSIGNER_BATCH_STDOUT_FIFO" \
      || err=$?
  ) &
  export APKSIGNER_BATCH_PID=$!
  sleep infinity >"$APKSIGNER_BATCH_STDIN_FIFO" &
  fifo_keepalive_pid=$!
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
