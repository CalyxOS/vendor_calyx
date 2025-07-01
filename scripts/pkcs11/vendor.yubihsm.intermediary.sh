#!/bin/bash
set -euo pipefail
ourpath="$(cd "$(dirname "$0")";pwd -P)"
scriptpath="$(cd "$(dirname "$0")/..";pwd -P)"

export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
export STRIP_HEX_KEY_ID_PREFIX=y
num_tries=4
is_a_signing_command=

main() {
  declare -g args=()
  cmd=$SIGNING_COMMAND
  if [ "$cmd" = "avbtool" ]; then
    handle_avbtool "$@"
  elif [ "$cmd" = "java" ]; then
    handle_java "$@"
  else
    args=("$@")
  fi

  # Note: We expect nothing from stdin, so we don't handle it.

  # Try multiple times, backing off for longer after each try.
  # This is a workaround for an issue in which the YubiHSM 2 is not able to allocate additional
  # sessions after multiple signing commands in a row, with errors such as:
  #   "Failed to create session: All sessions are allocated" from yubihsm-shell
  #   "CKR_SESSION_COUNT" from PKCS#11 tools
  local err=
  local try
  for try in $(seq 1 $num_tries); do
    "$cmd" "${args[@]}" || {
      err=$?
      echo "Warning: $cmd failed on try $try (error $err)." >&2
      sleep $((try*5))
      continue
    }
    err=0
    break
  done
  local log_err=
  if [ "$is_a_signing_command" = "y" ]; then
    source "$ourpath/vendor.yubihsm.include.sh" || return $?

    # Also try multiple times to get this logged...
    local log_try
    for log_try in $(seq 1 $num_tries); do
      PREPEND_LINE="Command:$(printf ' %q' "$SIGNING_COMMAND" "${args[@]}")"$'\n'"Result: $err"

      # Make sure the number of tries required is part of the log.
      if [ "$try" -gt 1 ]; then
        PREPEND_LINE="$PREPEND_LINE"$'\n'"Try: $try"
      fi

      # ...including the number of tries to get logs!
      if [ "$log_try" -gt 1 ]; then
        PREPEND_LINE="$PREPEND_LINE"$'\n'"Try (log): $log_try"
      fi

      PREPEND_LINE=$PREPEND_LINE \
      APPEND_LINE="---" \
        extract_logs || {
          log_err=$?
          echo "Warning: extract_logs failed on try $log_try (error $log_err)." >&2
          sleep $((try*5))
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
  local jar=
  while [ $# -gt 0 ]; do
    case "$1" in
      -jar)
        jar=$(basename "${2:-}")
        jar=${jar%.jar}
        ;;
      --min-sdk-version)
        # Enforce that non-essential APK signature schemes be skipped to save time.
        # This is a workaround of unexpected behavior from apksigner in which it incorporates
        # signature schemes that should be unnecessary signatures for a given minimum SDK level.
        if [ $# -gt 1 ]; then
          local min_sdk_version=$2
          args+=("$1" "$2")
          if [ "$min_sdk_version" -ge 24 ]; then
            args+=(--v1-signing-enabled=false)
          fi
          if [ "$min_sdk_version" -ge 28 ]; then
            args+=(--v2-signing-enabled=false)
          fi
          shift 2
          continue
        fi
        ;;
    esac
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
