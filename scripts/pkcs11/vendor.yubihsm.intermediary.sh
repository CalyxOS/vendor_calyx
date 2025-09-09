#!/bin/bash
set -euo pipefail
pkcs11_scriptpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"

num_tries=2
sleep_time=30
is_a_signing_command=

declare -g -a args=()
declare -g -a tool_args=()
jar=

# Source: https://stackoverflow.com/questions/11027679/capture-stdout-and-stderr-into-different-variables
# Solution 7, fetched 2025-09-10.
# Modified to maintain existing stdout and stderr while also capturing.
# SYNTAX:
#   transparent_catch STDOUT_VARIABLE STDERR_VARIABLE COMMAND [ARG1[ ARG2[ ...[ ARGN]]]]
transparent_catch() {
  {
    IFS=$'\n' read -r -d '' "${1}";
    IFS=$'\n' read -r -d '' "${2}";
    (IFS=$'\n' read -r -d '' _ERRNO_; return ${_ERRNO_});
  } 5>&1 6>&2 < <((printf '\0%s\0%d\0' "$(((({ shift 2; "${@}" > >(tee >(cat - >&5)) 2> >(tee >(cat - >&6) >&2); echo "${?}" 1>&3-; } | tr -d '\0' 1>&4-) 4>&2- 2>&1- | tr -d '\0' 1>&4-) 3>&1- | exit "$(cat)") 4>&1-)" "${?}" 1>&2) 2>&1)
}

read_all_fifo() {
  local fifo=$1
  local fifo_name=$2
  local captured i
  for i in $(seq 1 9); do
    read -t 7 -r -d $'\0' captured <>"$fifo" || return $?
    case "$captured" in
      RETURN:*)
        return_value=${captured#RETURN:}
        return $return_value ;;
      *)
        printf "%s" "$captured" ;;
    esac
  done
}

main() {
  local err=
  cmd=$SIGNING_COMMAND
  if [ "$cmd" = "avbtool" ]; then
    handle_avbtool "$@"
  elif [ "$cmd" = "java" ]; then
    handle_java "$@"
  else
    args=("$@")
  fi

  {
    if [ -n "${YUBIHSM_LOCKFILE:-}" ]; then
      # Ensure only one YubiHSM operation, including subsequent log extraction,
      # can happen at a time.
      flock -x 3
    fi
    run_command_maybe_batch "$@" || return $?
  } 3>>"${YUBIHSM_LOCKFILE:-/dev/null}"
}

run_command_maybe_batch() {
  local use_apksigner_batch=
  local try=1
  if [ "$jar" = "apksigner" ] \
     && [ "${APKSIGNER_BATCH_STDIN_FIFO:-/dev/null}" != "/dev/null" ] \
     && ps -p "$APKSIGNER_BATCH_PID" >/dev/null
  then
    use_apksigner_batch=y
  fi

  if [ "$use_apksigner_batch" = "y" ]; then
    true ${APKSIGNER_BATCH_STDOUT_FIFO?Need APKSIGNER_BATCH_STDOUT_FIFO to know when it is done}

    # Send the signing command to the apksigner batch FIFO.
    printf "%s\0" "${#tool_args[@]}" "${tool_args[@]}" >>"$APKSIGNER_BATCH_STDIN_FIFO" \
      || return $?

    local out_reader_pid err_reader_pid
    read_all_fifo "$APKSIGNER_BATCH_STDOUT_FIFO" stdout & out_reader_pid=$!
    read_all_fifo "$APKSIGNER_BATCH_STDERR_FIFO" stderr >&2 & err_reader_pid=$!
    wait $out_reader_pid || err=$?
    wait $err_reader_pid

    if [ -n "$err" ]; then
      echo "apksigner batch command exited with error $err, so we will try non-batch." >&2
    fi
  fi
  if [ -n "$err" ] || [ "$use_apksigner_batch" != "y" ]; then
    # Note: We expect nothing from stdin, so we don't handle it.

    # Try multiple times, backing off for longer after each try.
    # This is a workaround for an issue in which the YubiHSM 2 is not able to allocate additional
    # sessions after multiple signing commands in a row, with errors such as:
    #   "Failed to create session: All sessions are allocated" from yubihsm-shell
    #   "CKR_SESSION_COUNT" from PKCS#11 tools
    for try in $(seq 1 $num_tries); do
      local stdout stderr
      transparent_catch stdout stderr "$cmd" "${args[@]}" || {
        err=$?
        if [ -n "${YUBIHSM_CONNECTOR_PIDFILE:-}" ]; then
          case "$stderr" in
            *"Connector operation failed"*)
              # Try one more time after restarting the YubiHSM connector.
              maybe_start_or_restart_yubihsm_connector || return $?
              err=0
              transparent_catch stdout stderr "$cmd" "${args[@]}" || err=$?
              ;;
          esac
        fi
        case "$stdout $stderr" in
          *"All sessions are allocated"*|*SESSION_COUNT*)
            true ;;  # We retry for this...
          *)
            break ;; # But nothing else.
        esac
        echo "Warning: $cmd failed on try $try (error $err)." >&2
        sleep "$sleep_time"
        continue
      }
      err=0
      break
    done
  fi
  local log_err=
  local prepend_line=
  if [ "$is_a_signing_command" = "y" ]; then
    source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || return $?

    # Also try multiple times to get this logged...
    local log_try
    for log_try in $(seq 1 $num_tries); do
      prepend_line="Command:$(printf ' %q' "$SIGNING_COMMAND" "${args[@]}")"$'\n'"Result: $err"

      # Make sure the number of tries required is part of the log.
      if [ "$try" -gt 1 ]; then
        prepend_line="$prepend_line"$'\n'"Try: $try"
      fi

      # ...including the number of tries to get logs!
      if [ "$log_try" -gt 1 ]; then
        prepend_line="$prepend_line"$'\n'"Try (log): $log_try"
      fi

      extract_logs "" "$prepend_line" \
        || \
        {
          log_err=$?
          echo "Warning: extract_logs failed on try $log_try (error $log_err)." >&2
          sleep "$sleep_time"
          continue
        }

      log_err=0
      break
    done
  fi
  if [ "${err:-0}" = "0" ]; then
    err=$log_err
  fi
  return $err
}

handle_avbtool() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --algorithm)
        # Allow forcibly overriding the RSA key size provided to avbtool.
        # This shouldn't be necessary in most cases. On its own, this has no security impact.
        # Rather, it will allow signing to succeed and device to boot when a lower RSA key size
        # than is expected for a device is used for avb partitions.
        # Nevertheless, we only allow it with FORCE_AVB_RSA_KEY_SIZE=y.
        if [ $# -gt 1 ] && [ -n "${RSA_KEY_SIZE:-}" ] && [ "${FORCE_AVB_RSA_KEY_SIZE:-}" = "y" ];
        then
          case "$2" in
            SHA256_RSA*|SHA512_RSA*)
              if [ "${2:10}" -gt "$RSA_KEY_SIZE" ]; then
                args+=("$1" "${2:0:10}$RSA_KEY_SIZE")
                shift 2
                continue
              fi ;;
          esac
        fi
        ;;
      --signing*)
        is_a_signing_command=y
        ;;
    esac
    args+=("$1")
    shift 1
  done
}

handle_java() {
  while [ $# -gt 0 ]; do
    if [ -z "$jar" ] && [ "$1" = "-jar" ] && [ $# -gt 1 ]; then
      jar=$(basename "$2")
      jar=${jar%.jar}
      args+=("$1" "$2")
      shift 2
      continue
    elif [ -n "$jar" ]; then
      if [ "$1" = "--min-sdk-version" ]; then
        # Enforce that non-essential APK signature schemes be skipped to save time.
        # This is a workaround of unexpected behavior from apksigner in which it incorporates
        # signature schemes that should be unnecessary signatures for a given minimum SDK level.
        if [ $# -gt 1 ]; then
          local min_sdk_version=$2
          local to_add=()
          to_add+=("$1" "$2")
          if [ "$min_sdk_version" -ge 24 ]; then
            to_add+=(--v1-signing-enabled=false)
          fi
          if [ "$min_sdk_version" -ge 28 ]; then
            to_add+=(--v2-signing-enabled=false)
          fi
          args+=("${to_add[@]}")
          tool_args+=("${to_add[@]}")
          shift 2
          continue
        fi
      else
        tool_args+=("$1")
      fi
    fi
    args+=("$1")
    shift 1
  done
  if [ "$jar" = "signapk" ]; then
    is_a_signing_command=y
  elif [ "$jar" = "apksigner" ]; then
    is_a_signing_command=y
  fi
}

main "$@" || exit $?
