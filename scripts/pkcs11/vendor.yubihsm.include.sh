export KEYMAPPER=id2b
export USE_APKSIGNER=y
# Construct PKCS11_PIN from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD.
# See: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html#logging-in
export PKCS11_PIN=$(printf "%4s" "${YUBIHSM_AUTHKEY#0x}" | tr ' ' 0)$YUBIHSM_PASSWORD
export FIND_KEYS_BY_ID=y
export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
export STRIP_HEX_KEY_ID_PREFIX=y

# alternately, http://127.0.0.1:12345 and run yubihsm-connector
export YUBIHSM_CONNECTOR=${YUBIHSM_CONNECTOR:-yhusb://}

export YUBIHSM_LOGS_DIR=${YUBIHSM_LOGS_DIR:-$(pwd)/logs}
export YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND=${YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND:-y}
export YUBIHSM_KEY_CAPABILITIES=${YUBIHSM_KEY_CAPABILITIES:-sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep}
export YUBIHSM_OPAQUE_CAPABILITIES=${YUBIHSM_OPAQUE_CAPABILITIES:-}
export YUBIHSM_ONDEMAND_DOMAIN=${YUBIHSM_ONDEMAND_DOMAIN:-2}
export YUBIHSM_EXPORTABLE_DOMAIN=${YUBIHSM_EXPORTABLE_DOMAIN:-3}
export YUBIHSM_UNEXPORTABLE_DOMAIN=${YUBIHSM_UNEXPORTABLE_DOMAIN:-4}
export YUBIHSM_MAX_ONDEMAND_KEYS=${YUBIHSM_MAX_ONDEMAND_KEYS:-20}
export DATE_FORMAT=${DATE_FORMAT:-%Y%m%d-%H%M%S}


YUBIHSM_SIGNING_AUTHKEY_ID=${YUBIHSM_SIGNING_AUTHKEY_ID:-0x0001}
YUBIHSM_SIGNING_AUTHKEY_DOMAINS=${YUBIHSM_SIGNING_AUTHKEY_DOMAINS:-all}
# Authkey capabilities are based on yubihsm-setup, with some changes for our use cases.
YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,import-wrapped,export-wrapped,exportable-under-wrap,get-option,sign-attestation-certificate,get-log-entries,change-authentication-key,decrypt-pkcs,decrypt-oaep,put-opaque,get-opaque}
YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,exportable-under-wrap,get-option,decrypt-pkcs,decrypt-oaep}
YUBIHSM_AUDIT_AUTHKEY_ID=${YUBIHSM_AUDIT_AUTHKEY_ID:-0x0002}
YUBIHSM_AUDIT_AUTHKEY_DOMAINS=${YUBIHSM_AUDIT_AUTHKEY_DOMAINS:-all}
YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES:-get-log-entries,exportable-under-wrap,get-option,get-opaque}
YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES:-none}
YUBIHSM_WRAP_KEY_ID=${YUBIHSM_WRAP_KEY_ID:-0x0010}

# Fake... We don't truly get to control these wrap key details; yubihsm-setup controls it all,
# and there is no customization...
YUBIHSM_WRAP_KEY_DOMAINS=${YUBIHSM_WRAP_KEY_DOMAINS:-all}
YUBIHSM_WRAP_KEY_CAPABILITIES=${YUBIHSM_WRAP_KEY_CAPABILITIES:-export-wrapped,import-wrapped}
YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES=${YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES:-decrypt-oaep,decrypt-pkcs,derive-ecdh,export-wrapped,exportable-under-wrap,generate-asymmetric-key,get-log-entries,get-option,import-wrapped,sign-ecdsa,sign-eddsa,sign-pkcs,sign-pss,sign-attestation-certificate,change-authentication-key}

maybe_dry_run=${maybe_dry_run:-}

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # There's got to be a better way.
  local -a possible_paths=(
    /usr{/local,}/lib{/x86_64-linux-gnu,64,}{/pkcs11,}/yubihsm_pkcs11.so
  )
  local path; for path in "${possible_paths[@]}"; do
    if [ -e "$path" ]; then
      PKCS11_MODULE=$path
      return 0
    fi
  done
  echo "Please install the YubiHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
  return 1
}
find_pkcs11_module
export PKCS11_MODULE

find_yubihsm_shell() {
  [ -z "${YUBIHSM_SHELL_BIN:-}" ] || return 0
  if ! YUBIHSM_SHELL_BIN=${YUBIHSM_SHELL_BIN:-$(which yubihsm-shell)}; then
    echo "Please install yubihsm-shell, or set YUBIHSM_SHELL_BIN to its path." >&2
    return 1
  fi
}
find_yubihsm_shell
export YUBIHSM_SHELL_BIN

generate_yubihsm_pkcs11_library_config() {
  # https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html
  cat <<EOF
# This is a sample configuration file for the YubiHSM PKCS#11 module
# Uncomment the various options as needed

# URL of the connector to use. This can be a comma-separated list
connector = $YUBIHSM_CONNECTOR

# Enables general debug output in the module
#
# debug

# Enables function tracing (ingress/egress) debug output in the module
#
# dinout

# Enables libyubihsm debug output in the module
#
# libdebug

# Redirects the debug output to a specific file. The file is created
# if it does not exist. The content is appended
#
# debug-file = /tmp/yubihsm_pkcs11_debug

# CA certificate to use for HTTPS validation. Point this variable to
# a file containing one or more certificates to use when verifying
# a peer. Currently not supported on Windows
#
# cacert = /tmp/cacert.pem

# Proxy server to use for the connector
# Currently not supported on Windows
#
# proxy = http://proxyserver.local.com:8080

# Timeout in seconds to use for the initial connection to the connector
# timeout = 5
EOF
}

yubihsm() {
  if [ -z "${YUBIHSM_CONNECTOR:-}" ]; then
    echo "ERROR: Must set YUBIHSM_CONNECTOR." >&2
    return 1
  fi
  if [ -z "${YUBIHSM_AUTHKEY:-}" ]; then
    echo "ERROR: Must set YUBIHSM_AUTHKEY." >&2
    return 1
  fi
  if [ -z "${YUBIHSM_PASSWORD:-}" ]; then
    echo "ERROR: Must set YUBIHSM_PASSWORD." >&2
    return 1
  fi

  # The stderr from yubihsm-shell is annoyingly chatty, so we filter out the offenders.
  local err=
  $maybe_dry_run "$YUBIHSM_SHELL_BIN" \
    --connector "$YUBIHSM_CONNECTOR" \
    --authkey "$YUBIHSM_AUTHKEY" \
    --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
    "$@" \
    2> >(grep -v '^Session keepalive set up to run every 15 seconds$\|^Created session' >&2) \
    || err=$?

  # Redact arguments for log.
  local log_args=
  local arg
  local redact_next=
  for arg in "$@"; do
    if [ -n "$redact_next" ]; then
      arg="REDACTED"
      redact_next=
    fi
    case "$arg" in
      --password=*)
        arg="--password=REDACTED" ;;
      --new-password=*)
        arg="--new-password=REDACTED" ;;
      --password|--new-password|-p)
        redact_next=y
        ;;
    esac
    log_args="$log_args$(printf " %q" "$arg")"
  done

  if [ "${DRY_RUN:-}" != "y" ] && [ "$YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND" = "y" ]; then
    # Let's not pollute a dry run with this, but we want to extract logs after every command,
    # except commands to extract logs, since then we'd be stuck in a loop! extract_logs uses
    # yubihsm_nolog for that reason.
    NO_WARN=y \
    extract_logs "" "Command: yubihsm-shell$log_args"$'\n'"Result: ${err:-0}" \
      || \
      {
        err=${err:-$?}
        echo "Failed to extract logs" >&2
        return $err
      }
  fi
  return ${err:-0}
}

yubihsm_nolog() {
  YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND=n yubihsm "$@" || return $?
}

maybe_set_audit_log_path() {
  local timestamp=$1
  if [ -n "${AUDIT_LOG_PATH+x}" ]; then
    return 0
  fi
  local file_timestamp=
  local text_file
  file_timestamp=$(date -u --date="@$timestamp" +"$DATE_FORMAT") || return $?
  text_file=audit-$file_timestamp.log
  AUDIT_LOG_PATH=$text_file
}

# Extract an audit log to the supplied path or to $AUDIT_LOG_PATH, both in text (ASCII)
# and hex formats.  Use YUBIHSM_LOGS_DIR as the directory if given only a filename.
# Create the directory if it does not exist. Always append to logs.
# Use PREPEND_LINE and APPEND_LINE if given.
extract_logs() {
  # Get the logs from the device, both in ASCII and hex formats.
  local logs
  local hex
  local err=
  logs=$(yubihsm_nolog -a get-logs) \
    || {
      err=$?
      echo "ERROR: Failed to get logs" >&2
      logs="Failed to get logs (code $err)"
      # Don't exit yet. We want to log the failure.
    }

  hex=$(yubihsm_nolog -a get-logs --outformat hex) \
    || {
      err=$?
      echo "ERROR: Failed to get hex logs" >&2
      logs="Failed to get logs (code $err)"
    }

  # Build up text to write to the text file.
  {
    if [ -z "$err" ]; then
      printf "Hex: %s\n" "$hex"
      printf "%s\n" "$logs"
    else
      printf "%s\n" "$logs"
    fi
  } | add_input_to_log "$@" || return ${err:-$?}

  # We had errors earlier, so we should not mark the logs as extracted.
  if [ -n "$err" ]; then
    return $err
  fi

  # Get the last index found in the logs, if any.
  local last_index
  last_index=$(
    printf "%s\n" "$logs" \
      | tail -n1 \
      | sed -n -e 's/^item: \+\([0-9]\+\) --.*$/\1/p'
  ) \
  || return $?

  # Evaluate whether we're in a dry run, whether there are no logs to extract, or whether
  # an error occurred, before marking logs as extracted.
  if [ "${DRY_RUN:-}" != "y" ] && { [ -z "$last_index" ] || ! [ "$last_index" -ge 0 ]; }; then
    # We're not in a dry run, but we can't find the last index to mark the logs as fetched.
    if printf "%s\n" "$logs" | grep -qFx 'No logs to extract'; then
      # There was nothing to extract, so we don't need to mark anything as fetched.
      # We are done.
      [ "${NO_WARN:-}" = "y" ] || echo "WARNING: No logs to extract!" >&2
      return 0
    fi
    # An actual failure happened.
    echo "Failed to get index of last log entry" >&2
    return 1
  fi

  # Mark all the logs we saw as extracted.
  yubihsm_nolog -a set-log-index --log-index "$last_index" || {
    err=$?
    echo "Failed to set log index to $last_index" >&2
    return $err
  }
}

add_input_to_log() {
  local timestamp
  timestamp=$(date -u +%s.%3N) || return $?
  local text_file=${1:-}
  local prepend_line=${2:-}
  local append_line=---
  if [ -n "${3+x}" ]; then
    append_line=$3
  fi

  {
    if [ -n "${prepend_line:-}" ]; then printf "%s\n" "$prepend_line"; fi
    echo "Timestamp: $timestamp"
    cat
    if [ -n "${append_line:-}" ]; then printf "%s\n" "$append_line"; fi
  } | add_input_to_log_raw "$text_file" \
  || \
  { # Error writing to the text file.
    err=$?
    echo "Failed to save logs" >&2
    return $err
  }
}

add_input_to_log_raw() {
  local text_file=${1:-}

  if [ -z "$text_file" ]; then
    maybe_set_audit_log_path "$timestamp" || return $?
    text_file=${AUDIT_LOG_PATH:-}
    if [ -z "$text_file" ]; then
      # Nowhere to save logs, so don't.
      return 0
    fi
  fi

  if [ "${DRY_RUN:-}" = "y" ]; then
    # yubihsm commands will do nothing in dry run other than output the command they'd have
    # run to stderr, so we don't need to change those, but we do need to ensure that we
    # don't write anywhere.
    text_file=/dev/null
  fi

  if [ "$text_file" = "$(basename "$text_file")" ]; then
    # It's just a filename, no path. Put it in the logs dir if available, else current directory.
    $maybe_dry_run mkdir -p "${YUBIHSM_LOGS_DIR:-.}" || return $?
    text_file=${YUBIHSM_LOGS_DIR:-.}/$text_file
  fi

  cat >> "$text_file" || return $?
}

limit_ondemand_objects() {
  local -a ondemand_keys
  ondemand_keys=($(yubihsm -a list-objects \
    --object-type asymmetric-key \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN" \
    | sed -n -e 's/^id: \(0x[^,]\+\),.*$/\1/p'))
  if [ "${#ondemand_keys[@]}" -gt "$YUBIHSM_MAX_ONDEMAND_KEYS" ]; then
    local to_remove=$((${#ondemand_keys[@]}-$YUBIHSM_MAX_ONDEMAND_KEYS))
    local key
    for key in "${ondemand_keys[@]}"; do
      yubihsm -a delete-object --object-id "$key" --object-type asymmetric-key || return $?
      yubihsm -a delete-object --object-id "$key" --object-type opaque || return $?
      to_remove=$((to_remove-1))
      if [ "$to_remove" -le 0 ]; then
        break
      fi
    done
  fi
}

ensure_key_is_available_internal() {
  local key_id=$1
  local is_key_id_ondemand
  is_key_id_ondemand=$(get_key_id_is_ondemand_yn "$key_id") || return $?
  if [ "$is_key_id_ondemand" != "y" ]; then
    # Do not bother with any of this, if the key is not ondemand anyway.
    return 0
  fi

  # Check if needed key is available already.
  local needed_key
  needed_key=$(yubihsm -a list-objects \
    --object-id "$key_id" \
    --object-type asymmetric-key \
    | sed -n -e 's/^id: \(0x[^,]\+\),.*$/\1/p') || return $?
  if [ -n "$needed_key" ]; then
    return 0
  fi

  if [ ! -e "${KEY_DIR}${key_id}-asymmetric-key.yhk" ]; then
    echo "Need to load key $key_id but could not find a wrapped copy on disk" >&2
    return 1
  fi

  # Select a key to delete to make room.
  local ondemand_key
  ondemand_key=$(yubihsm -a list-objects \
    --object-type asymmetric-key \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN" \
    | sed -n -e 's/^id: \(0x[^,]\+\),.*$/\1/p' \
    | head -n1) || return $?
  if [ -z "$ondemand_key" ]; then
    echo "Could not find any on-demand key to delete to make room for $key_id" >&2
    return 1
  fi
  if [ ! -e "${KEY_DIR}${ondemand_key}-asymmetric-key.yhk" ]; then
    echo "Would delete $ondemand_key but could not find a wrapped copy on disk" >&2
    return 1
  fi

  # Make room to import wrapped key.
  yubihsm -a delete-object --object-id "$ondemand_key" --object-type asymmetric-key || return $?
  yubihsm -a delete-object --object-id "$ondemand_key" --object-type opaque || return $?

  # Import wrapped key.
  yubihsm -a put-wrapped \
    --wrap-id "$YUBIHSM_WRAP_KEY_ID" \
    --object-id "$key_id" \
    --object-type asymmetric-key \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN,$YUBIHSM_EXPORTABLE_DOMAIN" \
    --capabilities "$YUBIHSM_KEY_CAPABILITIES" \
    --in "${KEY_DIR}${key_id}-asymmetric-key.yhk" \
    || return $?

  # The cert itself is not sensitive so does not really need to be wrapped and unwrapped,
  # but yubihsm-setup already does it.
  #yubihsm -a put-wrapped --wrap-id "$YUBIHSM_WRAP_KEY_ID" --object-id "$key_id" \
  #  --object-type opaque \
  #  --domain "$YUBIHSM_EXPORTABLE_DOMAIN" \
  #  --capabilities "$YUBIHSM_OPAQUE_CAPABILITIES" \
  #  --in "${KEY_DIR}0x${key_id}-opaque.yhk" \
  #  || return $?
  # Still, we'll use the unwrapped variant.
  yubihsm -a put-opaque \
    --object-id "$key_id" \
    --object-type opaque \
    --algorithm opaque-x509-certificate \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN,$YUBIHSM_EXPORTABLE_DOMAIN" \
    --capabilities "$YUBIHSM_OPAQUE_CAPABILITIES" \
    --informat PEM \
    --in "${KEY_DIR}${key_id}.x509.pem" \
    || return $?
}

ensure_key_is_available() {
  local err=0
  ensure_key_is_available_internal "$@" || err=$?

  # Extract logs.

  local prepend_line="Function: ensure_key_is_available
Result: $err"
  extract_logs "" "$prepend_line" || return $?
  return $err
}

initialize_release_vendor() {
  read_yubihsm_deviceinfo || return $?
  local key_id
  key_id=$(get_key_id avb vbmeta) || return $?

  NO_WARN=y extract_logs "" "BUILD_NUMBER=$BUILD_NUMBER DEVICE=$DEVICE $0 ${*@Q}" \
    || return $?

  $maybe_dry_run ensure_key_is_available "$key_id" || return $?
}

read_yubihsm_deviceinfo() {
  declare -g yubihsm_deviceinfo
  declare -g yubihsm_serial
  declare -g yubihsm_partnumber
  yubihsm_deviceinfo=$(yubihsm_nolog -a get-device-info)
  [ -n "$yubihsm_deviceinfo" ] || return 1
  yubihsm_serial=$(printf "%s\n" "$yubihsm_deviceinfo" | sed -ne 's/^Serial number:\s\+//p')
  [ -n "$yubihsm_serial" ] || return 1
  yubihsm_partnumber=$(printf "%s\n" "$yubihsm_deviceinfo" | sed -ne 's/^Part number:\s\+//p')
  [ -n "$yubihsm_partnumber" ] || return 1
  declare -g yubihsm_id=$yubihsm_partnumber-$yubihsm_serial
}
