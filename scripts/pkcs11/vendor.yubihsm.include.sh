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

# YUBIHSM_LOGS_DIR must be set somewhere else.
export YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND=${YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND:-y}
export YUBIHSM_KEY_CAPABILITIES=${YUBIHSM_KEY_CAPABILITIES:-sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-ecdsa,sign-eddsa}
export YUBIHSM_OPAQUE_CAPABILITIES=${YUBIHSM_OPAQUE_CAPABILITIES:-}
export YUBIHSM_ONDEMAND_DOMAIN=${YUBIHSM_ONDEMAND_DOMAIN:-2}
export YUBIHSM_EXPORTABLE_DOMAIN=${YUBIHSM_EXPORTABLE_DOMAIN:-3}
export YUBIHSM_UNEXPORTABLE_DOMAIN=${YUBIHSM_UNEXPORTABLE_DOMAIN:-4}
export DATE_FORMAT=${DATE_FORMAT:-%Y%m%d-%H%M%S}

# Examples: RSA:4096, EC:secp256r1
# Unfortunately, secp512r1 consistently fails to verify in apksigner.
PREFERRED_KEY_ALGORITHM=EC:secp384r1

YUBIHSM_SIGNING_AUTHKEY_ID=${YUBIHSM_SIGNING_AUTHKEY_ID:-0x0001}
YUBIHSM_SIGNING_AUTHKEY_DOMAINS=${YUBIHSM_SIGNING_AUTHKEY_DOMAINS:-all}
# Authkey capabilities are based on yubihsm-setup, with some changes for our use cases.
YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,import-wrapped,export-wrapped,exportable-under-wrap,get-option,sign-attestation-certificate,get-log-entries,change-authentication-key,decrypt-pkcs,decrypt-oaep,put-opaque,get-opaque,delete-opaque,delete-asymmetric-key}
YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,exportable-under-wrap,get-option,decrypt-pkcs,decrypt-oaep}

YUBIHSM_AUDIT_AUTHKEY_ID=${YUBIHSM_AUDIT_AUTHKEY_ID:-0x0002}
YUBIHSM_AUDIT_AUTHKEY_DOMAINS=${YUBIHSM_AUDIT_AUTHKEY_DOMAINS:-all}
YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES:-get-log-entries,exportable-under-wrap,get-option,get-opaque}
YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES:-none}

additional_delegated_capabilities_for_admin_key=,put-asymmetric-key,delete-symmetric-key,generate-symmetric-key,put-symmetric-key,delete-hmac-key,generate-hmac-key,put-mac-key,sign-hmac,verify-hmac,delete-template,get-template,put-template,sign-ssh-certificate,decrypt-cbc,encrypt-cbc,decrypt-ecb,encrypt-ecb,delete-otp-aead-key,generate-otp-aead-key,put-otp-aead-key,create-otp-aead,randomize-otp-aead,rewrap-from-otp-aead-key,rewrap-to-otp-aead-key,delete-opaque
additional_capabilities_for_admin_key=$additional_delegated_capabilities_for_admin_key,delete-authentication-key,put-authentication-key,set-option,reset-device
# Key ID 0x0001 is not available when admin authkey is created, so please do not use 0x0001.
YUBIHSM_ADMIN_AUTHKEY_ID=${YUBIHSM_ADMIN_AUTHKEY_ID:-0x00ad}
YUBIHSM_ADMIN_AUTHKEY_DOMAINS=${YUBIHSM_ADMIN_AUTHKEY_DOMAINS:-all}
# Admin authkey defaults to having the same capabilities as signing, plus some more.
YUBIHSM_ADMIN_AUTHKEY_CAPABILITIES=${YUBIHSM_ADMIN_AUTHKEY_CAPABILITIES:-$YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES$additional_capabilities_for_admin_key}
# Admin authkey defaults to having the same delegated capabilities as the signing authkey's
# main capabilities, plus more. It needs to be able to re-create the signing authkey, after all.
YUBIHSM_ADMIN_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_ADMIN_AUTHKEY_DELEGATED_CAPABILITIES:-$YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES$additional_delegated_capabilities_for_admin_key}
YUBIHSM_WRAP_KEY_ID=${YUBIHSM_WRAP_KEY_ID:-0x0010}

YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE=${YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE:-0100030004000500060007000900080040004100420243004402450246024702550256024800490057004a024b024c024d0067004e004f0250005102520253025400580259005a025b025c005d005e025f006000610062026302640265026602680269026a026b006c020a006d026e026f0070007100720073027402750276027702}

# We don't truly get to control these wrap key details; yubihsm-setup controls it all,
# and there is no customization...
#YUBIHSM_WRAP_KEY_DOMAINS=${YUBIHSM_WRAP_KEY_DOMAINS:-all}
#YUBIHSM_WRAP_KEY_CAPABILITIES=${YUBIHSM_WRAP_KEY_CAPABILITIES:-export-wrapped,import-wrapped}
#YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES=${YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES:-decrypt-oaep,decrypt-pkcs,derive-ecdh,export-wrapped,exportable-under-wrap,generate-asymmetric-key,get-log-entries,get-option,import-wrapped,sign-ecdsa,sign-eddsa,sign-pkcs,sign-pss,sign-attestation-certificate,change-authentication-key}

_already_processed_log_path=

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

yubihsm_spam_filter() {
  grep -v '^Session keepalive set up to run every 15 seconds$\|^Created session'
}

yubihsm() {
  if [ "${DRY_RUN:-}" = "y" ]; then
    $maybe_dry_run yubihsm "$@" || return $?
    return 0
  fi
  if [ "$YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND" != "y" ]; then
    yubihsm_nolog "$@" || return $?
    return 0
  fi
  local log_path
  log_path=$(get_log_path) || return $?

  # The stderr from yubihsm-shell is annoyingly chatty, so we filter out the offenders.
  local err=
  local stdout=
  local stderr=
  transparent_catch stdout stderr \
  $maybe_dry_run \
    yubihsm_nolog "$@" || err=$?

  # Build and redact arguments for log.
  local log_args=
  local arg
  local redact_next=
  if [ "$YUBIHSM_AUTHKEY" != "1" ] && [ "$YUBIHSM_AUTHKEY" != "0x0001" ]; then
    log_args+=(--authkey "$YUBIHSM_AUTHKEY")
  fi
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

  # Build log entry text, and extract logs.
  local prepend="Command: yubihsm-shell$log_args"$'\n'"Result: ${err:-0}"
  if [ -n "$stdout" ]; then
    prepend="$prepend"$'\n'"-stdout-"$'\n'"$stdout"$'\n'"-"
  fi
  if [ -n "$stderr" ]; then
    prepend="$prepend"$'\n'"-stderr-"$'\n'"$stderr"$'\n'"-"
  fi
  NO_WARN=y _already_processed_log_path=y \
  extract_logs "$log_path" "$prepend" \
    || \
    {
      err=${err:-$?}
      echo "Failed to extract logs" >&2
      if [ "${NO_LOG_FAIL:-}" = "y" ]; then
        return 0
      else
        return $err
      fi
    }
  return ${err:-0}
}

yubihsm_nolog() {
  "$YUBIHSM_SHELL_BIN" \
    --connector "$YUBIHSM_CONNECTOR" \
    --authkey "$YUBIHSM_AUTHKEY" \
    --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
    "$@" \
    2> >(yubihsm_spam_filter >&2) || return $?
}

maybe_set_audit_log_path() {
  local timestamp=$1
  if [ -n "${AUDIT_LOG_PATH+x}" ]; then
    return 0
  fi
  local file_timestamp=
  local log_path
  file_timestamp=$(date -u --date="@$timestamp" +"$DATE_FORMAT") || return $?
  log_path=audit-$file_timestamp.log
  AUDIT_LOG_PATH=$log_path
}

# Extract an audit log to the supplied path or to $AUDIT_LOG_PATH, both in text (ASCII)
# and hex formats. Use YUBIHSM_LOGS_DIR as the directory if given only a filename.
# If YUBIHSM_LOGS_DIR is not set in this case, this function will fail.
# Otherwise, create the directory if it does not exist. Always append to logs.
# Usage: extract_logs [path] [prepend_line] [append_line] if given.
extract_logs() {
  # Get the logs from the device, both in ASCII and hex formats.
  if [ "${DRY_RUN:-}" = "y" ]; then
    return 0
  fi
  local err=
  local log_path
  log_path=$(get_log_path "${1:-}") \
    || \
    {
      local err=$?
      echo "Cannot extract logs when there is nowhere appropriate to extract them to." >&2
      return $err
    }
  shift 1
  local logs
  local hex
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
  } | _already_processed_log_path=y add_input_to_log "$log_path" "$@" || return ${err:-$?}

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
  local log_path
  log_path=$(get_log_path "${1:-}" "$timestamp") || return $?
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
  } | _already_processed_log_path=y add_input_to_log_raw "$log_path" \
  || \
  { # Error writing to the text file.
    err=$?
    echo "Failed to save logs" >&2
    return $err
  }
}

add_input_to_log_raw() {
  local log_path
  log_path=$(get_log_path "$1") || return $?
  cat >> "$log_path" || return $?
}

get_log_path() {
  if [ "${_already_processed_log_path:-}" = "y" ]; then
    printf "%s\n" "$1"
    return 0
  fi
  local log_path=${1:-${AUDIT_LOG_PATH:-}}
  if [ -z "$log_path" ]; then
    local timestamp=${2:-$(date -u +%s.%3N)}
    maybe_set_audit_log_path "$timestamp" || return $?
    log_path=${AUDIT_LOG_PATH:-}
    if [ -z "$log_path" ]; then
      # Nowhere to save logs, so don't.
      return 0
    fi
  fi
  if [ -z "$log_path" ]; then
    # Nowhere to save logs, so don't.
    return 0
  fi
  if [ "$log_path" = "$(basename "$log_path")" ]; then
    if [ -z "${YUBIHSM_LOGS_DIR:-}" ]; then
      echo "YUBIHSM_LOGS_DIR not set. Cannot write logs." >&2
      echo "If you do not want logs, try settings YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_COMMAND=n." >&2
      return 1
    fi
    # It's just a filename, no path. Put it in the logs dir if available, else current directory.
    $maybe_dry_run mkdir -p "$YUBIHSM_LOGS_DIR" || return $?
    log_path=$YUBIHSM_LOGS_DIR/$log_path
  fi
  if [ ! -e "$log_path" ]; then
    # Test if the path can be written to. If not, fail. If so, remove file if we created it to test.
    if ! printf "%s" "" >> "$log_path"; then
      echo "Log path could not be written to: $log_path" >&2
    elif [ "$(stat -c%s "$log_path")" = "0" ]; then
      rm -f "$log_path"
    fi
  elif [ ! -w "$log_path" ]; then
    echo "Log path is not writable: $log_path" >&2
    return 1
  fi
  printf "%s\n" "$log_path"
}

_fill_object_arrays_delegate_filtered_for_restorable_types() {
  case "$type" in
    asymmetric-key)
      true ;; # fine
    opaque)
      if [ -z "$algo" ] || [ "$algo" = "opaque-x509-certificate" ]; then
        true
      else
        return 0
      fi ;;
    *)
      return 0 ;;
  esac
  object_ids+=("$id")
  object_types+=("$type")
}

should_make_space_on_hsm_yn() {
  local storage_info
  # yubihsm_nolog's spamfilter is important here, because the information we need is part of
  # stderr, and it is combined with other useless messages.
  storage_info=$(yubihsm_nolog -a get-storage-info 2>&1) || return $?
  local oldIFS=$IFS
  IFS=,; set -- $storage_info; IFS=$oldIFS
  local free_records=
  local free_pages=
  while [ $# -gt 0 ]; do
    local value=${1# }
    case "$value" in
      "free records: "*)
        free_records=${value#free records: }
        free_records=${free_records%/*} ;;
      "free pages: "*)
        free_pages=${value#free pages: }
        free_pages=${free_pages%/*} ;;
    esac
    shift 1
  done
  if [ "$free_records" -lt 16 ]; then
    echo y
    return 0
  fi
  if [ "$free_pages" -lt 32 ]; then
    echo y
    return 0
  fi
  echo n
}

limit_ondemand_objects() {
  local -a object_ids=()
  local -a object_types=()
  call_for_each_object _fill_object_arrays_delegate_filtered_for_restorable_types \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN" \
    || return $?
  local i
  local last_id=
  for i in $(seq 0 $((${#object_ids[@]}-1))); do
    local id=${object_ids[$i]}
    local type=${object_types[$i]}
    if ! is_object_available_on_disk "$id" "$type"; then
      continue
    fi

    # Keep going as long as there are other types with the same id.
    local should_make_space
    should_make_space=$(should_make_space_on_hsm_yn) || return $?
    if [ "$should_make_space" = "n" ] && [ "$last_id" != "$id" ]; then
      return 0
    fi

    yubihsm -a delete-object --object-id "$id" --object-type "$type" \
      || return $?
    last_id=$id
  done
  if [ "$(should_make_space_on_hsm_yn)" != "n" ]; then
    echo "Failed to make enough space on the HSM in limit_ondemand_objects." >&2
    return 1
  fi
}

is_object_available_on_disk() {
  local id=$1
  local type=$2
  local algo=${3:-}
  case "$type" in
    asymmetric-key)
      [ -e "$KEY_DIR$id-asymmetric-key.yhw" ] || return $? ;;
    opaque)
      if [ -n "$algo" ] && [ "$algo" = "opaque-x509-certificate" ]; then
        echo "Unsupported opaque algorithm '$algo'" >&2
        return 1
      fi
      [ -e "$KEY_DIR$id.x509.pem" ] || return $? ;;
    *)
      echo "Unsupported type '$type'" >&2
      return 1 ;;
  esac
}

ensure_key_is_available_no_extract_logs_at_end() {
  local KEY_DIR=${KEY_DIR:-.}
  KEY_DIR=${KEY_DIR%/}/
  local key_id=$1
  local restore_mode=${2:-}
  local is_key_id_ondemand
  is_key_id_ondemand=$(get_key_id_is_ondemand_yn "$key_id") || return $?
  is_key_id_exportable=$(get_key_id_is_exportable_yn "$key_id") || return $?
  if [ "$is_key_id_ondemand" != "y" ]; then
    # Do not bother with any of this, if the key is not ondemand anyway.
    return 0
  fi

  # Check if needed key is available already.
  local -a object_ids=()
  local -a object_types=()
  local lookup_domain=$YUBIHSM_ONDEMAND_DOMAIN

  if [ "$restore_mode" = "y" ]; then
    lookup_domain=$YUBIHSM_EXPORTABLE_DOMAIN,$lookup_domain
  fi

  call_for_each_object _fill_object_arrays_delegate_filtered_for_restorable_types \
    --domain "$lookup_domain" \
    || return $?
  local found_key=
  local found_cert=
  local deletion_candidate_key_id=
  local deletion_candidate_cert_id=

  local should_make_space
  should_make_space=$(should_make_space_on_hsm_yn) || return $?

  # Sort through everything in the ondemand domain, looking for our needed key and noting
  # candidates for deletion if needed.
  for i in $(seq 0 $((${#object_ids[@]}-1))); do
    local id=${object_ids[$i]}
    local type=${object_types[$i]}
    if [ "$id" = "$key_id" ]; then
      if [ "$type" = "asymmetric-key" ]; then
        found_key=y
      elif [ "$type" = "opaque" ]; then
        found_cert=y
      fi
      continue
    fi

    if [ "$should_make_space" = "n" ]; then
      if [ "$found_key" = "y" ] && [ "$found_cert" = "y" ]; then
        break
      fi
      continue
    fi

    # Ensure any candidate to remove is actually ondemand, especially because we don't want
    # to delete anything else.
    if [ -z "$deletion_candidate_key_id" ] || [ -z "$deletion_candidate_cert_id" ]; then
      if is_object_available_on_disk "$id" "$type"; then
        local is_this_key_ondemand
        is_this_key_ondemand=$(get_key_id_is_ondemand_yn "$id") || return $?
        if [ "$is_this_key_ondemand" = "y" ]; then
          if [ "$type" = "asymmetric-key" ] && [ -z "$deletion_candidate_key_id" ]; then
            deletion_candidate_key_id=$id
          elif [ "$type" = "opaque" ] && [ -z "$deletion_candidate_cert_id" ]; then
            deletion_candidate_cert_id=$id
          fi
        fi
      fi
    fi
  done

  if [ "$found_key" = "y" ] && [ "$found_cert" = "y" ]; then
    # Key and cert are on the HSM already. Nothing to do.
    return 0
  fi

  if [ "$found_key" != "y" ]; then
    # Key is not on the HSM and needs to be loaded.
    # Make sure we have everything we need.
    if ! is_object_available_on_disk "$key_id" asymmetric-key; then
      echo "Wanted to load key $key_id but could not find a wrapped copy on disk" >&2
      if [ "$restore_mode" != "y" ]; then
        return 1
      fi
      found_key=y # So it will be skipped.
    fi
    if [ "$should_make_space" = "y" ] && [ -z "$deletion_candidate_key_id" ]; then
      echo "Could not find any on-demand key to delete to make room for $key_id" >&2
      return 1
    fi
  fi

  if [ "$found_cert" != "y" ]; then
    # Cert is not on the HSM and needs to be loaded.
    # Make sure we have everything we need.
    if ! is_object_available_on_disk "$key_id" opaque; then
      echo "Wanted to load cert $key_id but could not find it on disk" >&2
      if [ "$restore_mode" != "y" ]; then
        return 1
      fi
      found_cert=y # So it will be skipped.
    fi
    if [ "$should_make_space" = "y" ] && [ -z "$deletion_candidate_cert_id" ]; then
      echo "Could not find any on-demand cert to delete to make room for $key_id" >&2
      return 1
    fi
  fi

  if [ "$restore_mode" = "y" ] && [ "$found_key" = "y" ] && [ "$found_cert" = "y" ]; then
    echo "Failed to find any on-disk keys or certs for $key_id" >&2
    return 1
  fi

  local domain
  local key_capabilities
  local opaque_capabilities

  domain=$(get_domains_for_key_id "$key_id") \
    || return $?
  key_capabilities=$(get_capabilities_for_key_id "$key_id" "$YUBIHSM_KEY_CAPABILITIES") \
    || return $?
  opaque_capabilities=$(get_capabilities_for_key_id "$key_id" "$YUBIHSM_OPAQUE_CAPABILITIES") \
    || return $?

  if [ "$found_key" != "y" ]; then
    if [ -n "$deletion_candidate_key_id" ]; then
      # Delete a key to make room.
      yubihsm -a delete-object --object-id "$deletion_candidate_key_id" \
        --object-type asymmetric-key \
        || return $?
    fi
    # Import wrapped key.
    yubihsm -a put-wrapped \
      --wrap-id "$YUBIHSM_WRAP_KEY_ID" \
      --object-id "$key_id" \
      --object-type asymmetric-key \
      --domain "$domain" \
      --capabilities "$key_capabilities" \
      --in "$KEY_DIR$key_id-asymmetric-key.yhw" \
      || return $?
  fi

  if [ "$found_cert" != "y" ]; then
    if [ -n "$deletion_candidate_cert_id" ]; then
      # Delete a cert to make room.
      yubihsm -a delete-object --object-id "$deletion_candidate_cert_id" \
        --object-type opaque \
        || return $?
    fi
    # Import cert. It is not sensitive so really does not need to be wrapped and unwrapped.
    yubihsm -a put-opaque \
      --object-id "$key_id" \
      --object-type opaque \
      --algorithm opaque-x509-certificate \
      --domain "$domain" \
      --capabilities "$opaque_capabilities" \
      --informat PEM \
      --in "$KEY_DIR$key_id.x509.pem" \
      || return $?
  fi
}

restore_all_keys_and_certs() {
  local KEY_DIR=${KEY_DIR:-.}
  KEY_DIR=${KEY_DIR%/}/
  local -A found=()
  local file
  for file in "$KEY_DIR"*.x509.pem "$KEY_DIR"*-asymmetric-key.yhw; do
    [ -e "$file" ] || continue
    local key_id=$(basename "$file")
    key_id=${key_id%-asymmetric-key.yhw}
    key_id=${key_id%.x509.pem}
    if [ -n "${found[$key_id]:-}" ]; then
      continue
    fi
    found[$key_id]=1
    ensure_key_is_available_no_extract_logs_at_end "$key_id" y || return $?
  done
}

get_domains_for_key_id() {
  local key_id=$1
  local is_key_id_exportable
  local is_key_id_ondemand
  is_key_id_exportable=$(get_key_id_is_exportable_yn "$key_id") || return $?
  if [ "$is_key_id_exportable" = "y" ]; then
    is_key_id_ondemand=$(get_key_id_is_ondemand_yn "$key_id") || return $?
    if [ "$is_key_id_ondemand" = "y" ]; then
      printf "%s\n" "$YUBIHSM_EXPORTABLE_DOMAIN,$YUBIHSM_ONDEMAND_DOMAIN"
    else
      printf "%s\n" "$YUBIHSM_EXPORTABLE_DOMAIN"
    fi
  else
    printf "%s\n" "$YUBIHSM_UNEXPORTABLE_DOMAIN"
  fi
}

get_capabilities_for_key_id() {
  local key_id=$1
  local capabilities=$2
  local is_key_id_exportable
  is_key_id_exportable=$(get_key_id_is_exportable_yn "$key_id") || return $?
  if [ "$is_key_id_exportable" = "y" ]; then
    printf "%s,%s\n" "$2" "exportable-under-wrap"
  else
    printf "%s\n" "$2"
  fi
}

ensure_key_is_available() {
  local log_path
  log_path=$(get_log_path) || return $?
  local err=0
  ensure_key_is_available_no_extract_logs_at_end "$@" || err=$?

  # Extract logs.
  local prepend_line="Function: ensure_key_is_available
Result: $err"
  _already_processed_log_path=y \
  extract_logs "$log_path" "$prepend_line" \
    || err=$?
  return $err
}

initialize_release_vendor() {
  read_yubihsm_deviceinfo || return $?
  local key_id
  key_id=$(get_key_id avb vbmeta) || return $?
  local log_path
  log_path=$(get_log_path) || return $?

  NO_WARN=y _already_processed_log_path=y \
  extract_logs "$log_path" "BUILD_NUMBER=$BUILD_NUMBER DEVICE=$DEVICE $0 ${*@Q}" \
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

call_for_each_object() {
  local function_to_call=$1
  shift 1
  local -a object_lines=()
  mapfile -t object_lines < <(yubihsm_nolog -a list-objects "$@") \
    || return $?
  if [ "${#object_lines[@]}" -eq 0 ]; then
    return 1
  fi
  local object_line
  for object_line in "${object_lines[@]}"; do
    case "$object_line" in
      "Found "*)
        continue ;;
    esac
    local oldIFS=$IFS
    IFS=,; set -- $object_line; IFS=$oldIFS
    local id=
    local type=
    local algo=
    local sequence=
    local label=
    while [ $# -gt 0 ] && { [ -z "$id" ] || [ -z "$type" ]; }; do
      local value=${1# }
      case "$value" in
        "id: "*)
          id=${value#id: } ;;
        "type: "*)
          type=${value#type: } ;;
        "algo: "*)
          algo=${value#algo: } ;;
        "sequence: "*)
          sequence=${value#sequence: } ;;
        "label: "*)
          label=${value#label: } ;;
        *)
          if [ -n "$label" ]; then
            # Label may have had a comma in it.
            label="$label,$1"
          fi
          ;;
      esac
      shift 1
    done
    if [ -n "$id" ] && [ -n "$type" ]; then
      id="$id" type="$type" algo="$algo" sequence="$sequence" label="$label" \
        "$function_to_call" || return $?
    fi
  done
}

_dump_object_info_delegate() {
  yubihsm_nolog -a get-object-info --object-id "$id" --object-type "$type" \
    || return $?
}

dump_object_info() {
  call_for_each_object _dump_object_info_delegate || return $?
}

check_command_audit_value() {
  local command_audit_value
  command_audit_value=$(
    yubihsm_nolog -a get-option --opt-name command-audit | sed -e 's/^Option value is: //'
  ) || return $?
  [ "$command_audit_value" = "$YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE" ] || return $?
}

provision_auditing() {
  if check_command_audit_value; then
    echo "Command audit value is already as expected."
    return 0
  fi
  yubihsm -a put-option --opt-name command-audit --opt-value "$YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE" || return $?
  yubihsm -a put-option --opt-name force-audit --opt-value 02 || return $? # prevent operations when audit log is full
  if ! check_command_audit_value; then
    # TODO: Maybe allow this enforcement to be skipped? But maybe not.
    echo "Command audit value is not as expected after provisioning!" >&2
    return 1
  fi
  echo "Successfully provisioned auditing options."
}

show_yubihsm_info() {
  if [ -z "${yubihsm_deviceinfo:-}" ]; then
    read_yubihsm_deviceinfo || return $?
  fi
  local objects
  objects=$(dump_object_info) || return $?
  local command_audit_value
  command_audit_value=$(
    yubihsm_nolog -a get-option --opt-name command-audit | sed -e 's/^Option value is: //'
  ) || return $?
  local storage_info
  storage_info=$(
    yubihsm_nolog -a get-storage-info 2>&1
  ) || return $?
  printf "%s\n" "-Device info-"
  printf "%s\n" "$yubihsm_deviceinfo"
  printf "%s\n" "-Objects-"
  printf "%s\n" "$objects"
  printf "%s\n" "-Command audit value-"
  printf "%s\n" "$command_audit_value"
  printf "%s\n" "-Storage info-"
  printf "%s\n" "$storage_info"
}

get_name_for_hsm_and_session() {
  local prefix=${1:-}
  if [ -n "$prefix" ]; then
    prefix="${prefix}-"
  fi
  declare -g session_date=${session_date:-$(date -u +$DATE_FORMAT)}
  printf "%s%s\n" "$prefix" "${yubihsm_id:-unknown-hsm}-$session_date"
}

get_key_algorithm() {
  local key_type=${1:-}
  local key_name=${2:-}
  case "$key_type" in
    avb|apex_payload)
      get_default_key_algorithm "$@" || return $? ;;
    *)
      local key_id
      key_id=$(get_key_id "$key_type" "$key_name") || return $?
      algorithm=$(get_key_id_algorithm "$key_id") || return $?
      if [ -z "$algorithm" ]; then
        get_default_key_algorithm "$@" || return $?
      else
        printf "%s\n" "$algorithm"
      fi ;;
  esac
}

get_key_id_algorithm() {
  local key_id=$1
  local pairs
  pairs=$(get_key_type_and_name_pairs_for_id "$1") || return $?
  local oldIFS=$IFS
  IFS=$'\t'; set -- $pairs; IFS=$oldIFS
  local alg
  for pair in "$@"; do
    local key_type=${pair%%:*}
    local key_name=${pair#*:}
    local key_algorithm
    case "$key_type" in
      avb|apex_payload)
        key_algorithm=$(get_default_key_algorithm "$@") || return $? ;;
      *)
        key_algorithm=$PREFERRED_KEY_ALGORITHM ;;
    esac
    case "$key_algorithm" in
      rsa*)
        printf "%s\n" "$key_algorithm"
        return 0 ;;
      *)
        alg=$key_algorithm ;;
    esac
  done
  printf "%s\n" "${alg:-$PREFERRED_KEY_ALGORITHM}"
}

declare -g -A pkcs11_algorithm_to_yubico_algorithm=(
  [RSA:2048]=rsa2048
  [RSA:3072]=rsa3072
  [RSA:4096]=rsa4096
  [EC:secp256k1]=eck256
  [EC:secp256r1]=ecp256
  [EC:secp384r1]=ecp384
  [EC:secp521r1]=ecp521
  [EC:brainpoolP256r1]=ecbp256
  [EC:brainpoolP384r1]=ecbp384
  [EC:brainpoolP512r1]=ecbp512
)

get_yubico_key_algorithm_name() {
  local algorithm=$1
  local yubico_algorithm=${pkcs11_algorithm_to_yubico_algorithm[$algorithm]:-}
  if [ -z "$yubico_algorithm" ]; then
    echo "Unknown algorithm '$algorithm'; cannot convert to yubico" >&2
    return 1
  fi
  printf "%s\n" "$yubico_algorithm"
}
