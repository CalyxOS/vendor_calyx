export KEYMAPPER=id2b
export USE_APKSIGNER=y
export FIND_KEYS_BY_ID=y
export OPENSSL_PKCS11_URI_USES_HEX_KEY_ID=y
export STRIP_HEX_KEY_ID_PREFIX=y

# alternately, yhusb://
export YUBIHSM_CONNECTOR=${YUBIHSM_CONNECTOR:-http://127.0.0.1:12345}

# YUBIHSM_LOGS_DIR must be set somewhere else.
export YUBIHSM_KEY_CAPABILITIES=${YUBIHSM_KEY_CAPABILITIES:-sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-ecdsa,sign-eddsa}
export YUBIHSM_OPAQUE_CAPABILITIES=${YUBIHSM_OPAQUE_CAPABILITIES:-}
export YUBIHSM_ONDEMAND_DOMAIN=${YUBIHSM_ONDEMAND_DOMAIN:-2}
export YUBIHSM_EXPORTABLE_DOMAIN=${YUBIHSM_EXPORTABLE_DOMAIN:-3}
export YUBIHSM_UNEXPORTABLE_DOMAIN=${YUBIHSM_UNEXPORTABLE_DOMAIN:-4}
export DATE_FORMAT=${DATE_FORMAT:-%Y%m%d-%H%M%S}

# Examples: RSA:4096, EC:secp256r1, EC:secp384r1
# Unfortunately, secp512r1 consistently fails to verify in apksigner.
PREFERRED_KEY_ALGORITHM=RSA:4096

YUBIHSM_SIGNING_AUTHKEY_ID=${YUBIHSM_SIGNING_AUTHKEY_ID:-0x0001}
YUBIHSM_AUDIT_AUTHKEY_ID=${YUBIHSM_AUDIT_AUTHKEY_ID:-0x0002}
# Key ID 0x0001 is not available when admin authkey is created, so please do not use 0x0001.
YUBIHSM_ADMIN_AUTHKEY_ID=${YUBIHSM_ADMIN_AUTHKEY_ID:-0x00ad}
YUBIHSM_WRAP_KEY_ID=${YUBIHSM_WRAP_KEY_ID:-0x0010}

YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE=${YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE:-0100030004000500060007000900080040004100420243004402450246024702550256024800490057004a024b024c024d0067004e004f0250005102520253025400580259005a025b025c005d005e025f006000610062026302640265026602680269026a026b006c020a006d026e026f0070007100720073027402750276027702}

_we_started_apksigner=
_we_started_yubihsm_connector=
_we_created_yubihsm_tmpdir=
_our_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" || exit;pwd -P)
for_restore=
verify_key_ids=
declare -g -A fully_loaded_keys_map=()

maybe_dry_run=${maybe_dry_run:-}

initialize_vendor_interactive() {
  if [ "${NEVER_START_YUBIHSM_CONNECTOR:-}" != "y" ]; then
    find_yubihsm_connector || return $?
    if is_yubihsm_connector_running; then
      echo
      echo "yubihsm-connector is already running."
      echo "This means we will not be able to restart it if it messes up."
      echo "Before running this script, please stop the existing connector by stopping its service,"
      echo "if any, or by running killall yubihsm-connector"
      confirm "Continue anyway?" || return $?
    fi
  fi

  ask_variable YUBIHSM_AUTHKEY "0x0001" n y || return $?
  ask_variable YUBIHSM_PASSWORD "" y y || return $?
  export YUBIHSM_AUTHKEY YUBIHSM_PASSWORD
}

initialize_vendor() {
  # Construct PKCS11_PIN from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD.
  # See: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html#logging-in
  export PKCS11_PIN=$(printf "%4s" "${YUBIHSM_AUTHKEY#0x}" | tr ' ' 0)$YUBIHSM_PASSWORD

  local pkcs11_scriptpath="$(cd "$(dirname "$BASH_SOURCE")";pwd -P)"
  export SIGNING_COMMAND_INTERCEPTOR=$pkcs11_scriptpath/vendor.yubihsm.interceptor.sh
  export PKCS11_VENDOR=yubihsm

  if [ "${DRY_RUN:-}" != "y" ]; then
    if [ -z "${YUBIHSM_TMPDIR:-}" ]; then
      export YUBIHSM_TMPDIR=$(mktemp -d "${TMPDIR:-/dev/shm}/yubihsm.XXXXXXXX") || return $?
      chmod 0700 "$YUBIHSM_TMPDIR"
      _we_created_yubihsm_tmpdir=y
    fi

    if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
      export YUBIHSM_PKCS11_CONF=$YUBIHSM_TMPDIR/yubihsm_pkcs11.conf
      generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
    fi

    maybe_start_yubihsm_connector "$YUBIHSM_TMPDIR/yubihsm_connector.pid"
    maybe_start_apksigner_batch "$YUBIHSM_TMPDIR"

    export YUBIHSM_LOCKFILE=${YUBIHSM_LOCKFILE:-$YUBIHSM_TMPDIR/yubihsm.lock}
    YUBIHSM_LOGS_DIR="$(pwd)/logs"
    if [ ! -s "$YUBIHSM_LOGS_DIR/upload.py"  ]; then
      printf "\n" >&2
      echo "YUBIHSM_LOGS_DIR ($YUBIHSM_LOGS_DIR) is not the expected git repository." >&2
      echo "Are you sure you are calling this script from the right place?" >&2
      echo "Did you clone the audit log git repository already?" >&2
      return 1
    fi
    export YUBIHSM_LOGS_DIR
  else
    export YUBIHSM_TMPDIR=
    export YUBIHSM_LOCKFILE=
  fi
}

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

find_yubihsm_connector() {
  [ -z "${YUBIHSM_CONNECTOR_BIN:-}" ] || return 0
  if ! YUBIHSM_CONNECTOR_BIN=${YUBIHSM_CONNECTOR_BIN:-$(which yubihsm-connector)}; then
    echo "Please install yubihsm-connector, or set YUBIHSM_CONNECTOR_BIN to its path." >&2
    echo "Alternatively, set NEVER_START_YUBIHSM_CONNECTOR=y." >&2
    return 1
  fi
  export YUBIHSM_CONNECTOR_BIN
}

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

  # The stderr from yubihsm-shell is annoyingly chatty, so we filter out the offenders.
  local err=
  local stdout=
  local stderr=
  transparent_catch stdout stderr \
  $maybe_dry_run_ignore \
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
  local prepend="Command: yubihsm-shell$log_args Result: ${err:-0}"
  if [ -n "$stdout" ]; then
    prepend="$prepend -stdout- $stdout -"
  fi
  if [ -n "$stderr" ]; then
    prepend="$prepend -stderr- $stderr -"
  fi
  extract_logs "$prepend" \
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
  local stdout
  local stderr
  local err=
  transparent_catch stdout stderr \
  "$YUBIHSM_SHELL_BIN" \
    --connector "$YUBIHSM_CONNECTOR" \
    --authkey "$YUBIHSM_AUTHKEY" \
    --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
    "$@" \
    2> >(yubihsm_spam_filter >&2) || err=$?

  if [ -n "$err" ] && [ -n "${YUBIHSM_CONNECTOR_PIDFILE:-}" ]; then
    case "$stderr" in
      *"Connector operation failed"*)
        sleep 2
        maybe_start_or_restart_yubihsm_connector || return $?
        err=0
        "$YUBIHSM_SHELL_BIN" \
          --connector "$YUBIHSM_CONNECTOR" \
          --authkey "$YUBIHSM_AUTHKEY" \
          --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
          "$@" \
          2> >(yubihsm_spam_filter >&2) || return $err
        ;;
      *"Unable to find a suitable connector"*)
        # Try one more time after restarting the YubiHSM connector.
        maybe_start_or_restart_yubihsm_connector || return $?
        err=0
        "$YUBIHSM_SHELL_BIN" \
          --connector "$YUBIHSM_CONNECTOR" \
          --authkey "$YUBIHSM_AUTHKEY" \
          --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
          "$@" \
          2> >(yubihsm_spam_filter >&2) || return $err
        ;;
    esac
    return $err
  fi
  return ${err:-}
}

# Extract an audit log to the supplied path.
# Usage: extract_logs [comment]
extract_logs() {
  if [ "${DRY_RUN:-}" = "y" ]; then
    return 0
  fi

  local log_path=$AUDIT_LOG_PATH || \
    {
      echo "Cannot extract logs when there is nowhere appropriate to extract them to." >&2
      return 1
    }
  local comment=${1:-}
  # shellcheck disable=SC2030
  (
    export YUBIHSM_CONNECTOR=$YUBIHSM_CONNECTOR
    export YUBIHSM_AUTHKEY=$YUBIHSM_AUTHKEY
    export YUBIHSM_PASSWORD=$YUBIHSM_PASSWORD
    "$_our_path/vendor.yubihsm.audit.logs.py" --log-file "$log_path" --comment "$comment" || return $?
  ) || return $?
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
  mapfile -t lines <<< "$storage_info"
  local free_records=
  local free_pages=
  local line
  for line in "${lines[@]}"; do
    local -a values
    mapfile -t -d ',' values <<< "$line"
    local value
    for value in "${values[@]}"; do
      value=${value# }
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
  done
  if [ "$free_records" -lt 5 ]; then
    echo y
    return 0
  fi
  if [ "$free_pages" -lt 25 ]; then
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

ensure_key_is_available_nolog() {
  local KEY_DIR=${KEY_DIR:-.}
  KEY_DIR=${KEY_DIR%/}/
  local -a key_ids=()
  local restore_mode=${for_restore:-}
  local key_id

  if [ "${verify_key_ids:-y}" = "y" ]; then
    for key_id in "$@"; do
      local is_key_id_ondemand
      is_key_id_ondemand=$(get_key_id_is_ondemand_yn "$key_id") || return $?
      is_key_id_exportable=$(get_key_id_is_exportable_yn "$key_id") || return $?
      if [ "$is_key_id_ondemand" = "y" ] || \
          { [ "$restore_mode" = "y" ] && [ "$is_key_id_exportable" = "y" ]; }; then
        key_ids+=("$key_id")
      else
        # Do not bother with this one. It's either not on-demand, or we're not in restore
        # more and it's not exportable, so don't import it.
        continue
      fi
    done
  else
    key_ids=("$@")
  fi

  local -a object_ids=()
  local -a object_types=()
  local -A deletion_ineligible_keys_map=()
  local -A deletion_ineligible_certs_map=()
  for key_id in "${key_ids[@]}"; do
    deletion_ineligible_keys_map[$key_id]=1
    deletion_ineligible_certs_map[$key_id]=1
  done
  local lookup_domain=$YUBIHSM_ONDEMAND_DOMAIN

  if [ "$restore_mode" = "y" ]; then
    lookup_domain=$YUBIHSM_EXPORTABLE_DOMAIN,$lookup_domain
  fi
  call_for_each_object _fill_object_arrays_delegate_filtered_for_restorable_types \
    --domain "$lookup_domain" \
    || return $?

  # Sort through everything in the ondemand domain, looking for our needed key and noting
  # candidates for deletion if needed.
  for key_id in "${key_ids[@]}"; do
    local should_make_space
    should_make_space=$(should_make_space_on_hsm_yn) || return $?
    local deletion_candidate_key_id=
    local deletion_candidate_cert_id=
    local key_index=
    local cert_index=
    local i
    for i in $(seq 0 $((${#object_ids[@]}-1))); do
      local id=${object_ids[$i]}
      local type=${object_types[$i]}
      if [ "$id" = "$key_id" ]; then
        if [ "$type" = "asymmetric-key" ]; then
          key_index=$i
        elif [ "$type" = "opaque" ]; then
          cert_index=$i
        fi
        continue
      fi

      if [ "$should_make_space" = "n" ]; then
        if [ -n "$key_index" ] && [ -n "$cert_index" ]; then
          break
        fi
        continue
      fi

      # If we are being asked to ensure a key is available, and that key's ID is closer to
      # the beginning of the range, then we should make room at the end. If it's closer to
      # the end, we should make room at the beginning. This assumes that parallel signing
      # will involve device-specific keys that enter and leave the HSM as needed, and that
      # devices with IDs near each other will be signed around the same time.
      # To handle this, we just compare it to the decimal value of the middle object ID.
      local middle=$((${#object_ids[@]} / 2))
      middle=${object_ids[$middle]}
      local delete_from_beginning
      if [ "$((key_id))" -lt "$((middle))" ]; then
        delete_from_beginning=n  # find deletion candidates at higher IDs
      else
        delete_from_beginning=y  # find deletion candidates at lower IDs
      fi

      if [ -z "$deletion_candidate_key_id" ] || [ -z "$deletion_candidate_cert_id" ]; then
        if is_object_available_on_disk "$id" "$type"; then
          # Ensure any candidate to remove is actually ondemand, especially because we don't want
          # to delete anything else.
          local is_this_key_ondemand
          is_this_key_ondemand=$(get_key_id_is_ondemand_yn "$id") || return $?
          if [ "$is_this_key_ondemand" = "y" ]; then
            if [ "$type" = "asymmetric-key" ] && \
               [ -z "${deletion_ineligible_keys_map[$id]:-}" ]; then
              if [ "$delete_from_beginning" = "y" ]; then
                [ -n "$deletion_candidate_key_id" ] || deletion_candidate_key_id=$id
              else
                deletion_candidate_key_id=$id
              fi
            elif [ "$type" = "opaque" ] && \
                 [ -z "${deletion_ineligible_certs_map[$id]:-}" ]; then
              if [ "$delete_from_beginning" = "y" ]; then
                [ -n "$deletion_candidate_cert_id" ] || deletion_candidate_cert_id=$id
              else
                deletion_candidate_cert_id=$id
              fi
            fi
          fi
        fi
      fi
    done

    if [ -n "$key_index" ] && [ -n "$cert_index" ]; then
      # Key and cert are on the HSM already. Nothing to do.
      continue
    fi

    if [ -z "$key_index" ]; then
      # Key is not on the HSM and needs to be loaded.
      # Make sure we have everything we need.
      if ! is_object_available_on_disk "$key_id" asymmetric-key; then
        echo "Wanted to load key $key_id but could not find a wrapped copy on disk" >&2
        if [ "$restore_mode" != "y" ]; then
          return 1
        fi
        key_index=-1 # Set it to something, so that it will be skipped.
      fi
      if [ "$should_make_space" = "y" ] && [ -z "$deletion_candidate_key_id" ]; then
        echo "Could not find any on-demand key to delete to make room for $key_id" >&2
        return 1
      fi
    fi

    if [ -z "$cert_index" ]; then
      # Cert is not on the HSM and needs to be loaded.
      # Make sure we have everything we need.
      if ! is_object_available_on_disk "$key_id" opaque; then
        echo "Wanted to load cert $key_id but could not find it on disk" >&2
        if [ "$restore_mode" != "y" ]; then
          return 1
        fi
        cert_index=-1 # Set it to something, so that it will be skipped.
      fi
      if [ "$should_make_space" = "y" ] && [ -z "$deletion_candidate_cert_id" ]; then
        echo "Could not find any on-demand cert to delete to make room for $key_id" >&2
        return 1
      fi
    fi

    if [ "$restore_mode" = "y" ] && [ -n "$key_index" ] && [ -n "$cert_index" ]; then
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

    if [ -z "$key_index" ]; then
      if [ -n "$deletion_candidate_key_id" ]; then
        # Delete a key to make room.
        yubihsm_nolog -a delete-object --object-id "$deletion_candidate_key_id" \
          --object-type asymmetric-key \
          || return $?
        deletion_ineligible_keys_map[$deletion_candidate_key_id]=1
      fi
      # Import wrapped key.
      yubihsm_nolog -a put-wrapped \
        --wrap-id "$YUBIHSM_WRAP_KEY_ID" \
        --object-id "$key_id" \
        --object-type asymmetric-key \
        --domain "$domain" \
        --capabilities "$key_capabilities" \
        --in "$KEY_DIR$key_id-asymmetric-key.yhw" \
        || return $?
    fi

    if [ -z "$cert_index" ]; then
      if [ -n "$deletion_candidate_cert_id" ]; then
        # Delete a cert to make room.
        yubihsm_nolog -a delete-object --object-id "$deletion_candidate_cert_id" \
          --object-type opaque \
          || return $?
        deletion_ineligible_certs_map[$deletion_candidate_cert_id]=1
      fi
      # Import cert. It is not sensitive so really does not need to be wrapped and unwrapped.
      yubihsm_nolog -a put-opaque \
        --object-id "$key_id" \
        --object-type opaque \
        --algorithm opaque-x509-certificate \
        --domain "$domain" \
        --capabilities "$opaque_capabilities" \
        --informat PEM \
        --in "$KEY_DIR$key_id.x509.pem" \
        || return $?
    fi
  done
}

_populate_loaded_keys_delegate() {
  case "$type" in
    asymmetric-key)
      loaded_keys_map[$id]=1
      if [ -n "${loaded_certs_map[$id]:-}" ]; then
        fully_loaded_keys_map[$id]=1
      fi
      true ;; # fine
    opaque)
      if [ -z "$algo" ] || [ "$algo" = "opaque-x509-certificate" ]; then
        loaded_certs_map[$id]=1
        if [ -n "${loaded_keys_map[$id]:-}" ]; then
          fully_loaded_keys_map[$id]=1
        fi
      fi ;;
  esac
}

populate_loaded_keys() {
  fully_loaded_keys_map=()
  local -a loaded_keys_map=()
  local -a loaded_certs_map=()
  local lookup_domain=$YUBIHSM_ONDEMAND_DOMAIN
  call_for_each_object _populate_loaded_keys_delegate \
    || return $?
}

_ensure_device_specific_key_ids_map_is_present() {
  local has_map=n
  if declare -F has_device_specific_key_ids_map >/dev/null; then
    if has_device_specific_key_ids_map; then
      has_map=y
    fi
  fi
  if [ "$has_map" = "n" ]; then
    {
      echo "Could not find device_specific_key_ids_map, or it is empty."
      echo "Does your keymapper (${KEYMAPPER:-${KEYMAPPER_FILE:-unknown}}) support it?"
    } >&2
    return 1
  fi
}

populate_devices_with_loaded_keys_arrays() {
  _ensure_device_specific_key_ids_map_is_present || return $?

  populate_loaded_keys || return $?

  local device
  for device in "$@"; do
    local oldIFS=$IFS
    IFS=$'\t'
    local key_id
    local is_device_fully_loaded=y
    for key_id in ${device_specific_key_ids_map[$device]}; do
      [ -n "$key_id" ] || continue
      if [ -z "${fully_loaded_keys_map[$key_id]:-}" ]; then
        is_device_fully_loaded=n
        break
      fi
    done
    IFS=$oldIFS
    if [ "$is_device_fully_loaded" = "y" ]; then
      devices_with_loaded_keys+=("$device")
    else
      devices_without_loaded_keys+=("$device")
    fi
  done
}

ensure_all_keys_available_for_devices() {
  _ensure_device_specific_key_ids_map_is_present || return $?

  local -A needed_keys=()
  local device
  for device in "$@"; do
    for key_id in ${device_specific_key_ids_map[$device]}; do
      [ -n "$key_id" ] || continue
      needed_keys[$key_id]=1
    done
  done
  # using the _nolog version here, because this is called from sign.sh where we extract logs ourselves for the batch
  verify_key_ids=n ensure_key_is_available_nolog "${!needed_keys[@]}" || return $?
}

restore_all_keys_and_certs() {
  local err=0

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
    # We do not do _nolog because we may run out of audit log space on the HSM
    # during this process.
    for_restore=y ensure_key_is_available "$key_id" || {
      err=$?
      break
    }
  done

  # Extract logs.
  local prepend_line="Function: restore_all_keys_and_certs Result: $err"
  extract_logs "$prepend_line" \
    || err=$?
  return $err
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
  local err=0
  ensure_key_is_available_nolog "$@" || err=$?

  # Extract logs.
  local prepend_line="Function: ensure_key_is_available Result: $err"
  extract_logs "$prepend_line" \
    || err=$?
  return $err
}

maybe_start_yubihsm_connector() {
  maybe_start_or_restart_yubihsm_connector "${1:-}" y
}

is_yubihsm_connector_running() {
  local -a procs
  mapfile -t procs < <(pgrep -a -f yubihsm-connector)
  local proc
  for proc in "${procs[@]}"; do
    proc=${proc#* }
    case "$proc" in
      "$YUBIHSM_CONNECTOR_BIN"|yubihsm-connector\
      |"$YUBIHSM_CONNECTOR_BIN "*|"yubihsm-connector "*)
        # This does not account for spaces in the process path or newlines in command lines,
        # but that is fine. It is truly good enough for determining if this process is running.
        return 0 ;;
    esac
  done
  return 1
}

maybe_start_or_restart_yubihsm_connector() {
  if [ "${NEVER_START_YUBIHSM_CONNECTOR:-}" = "y" ]; then
    return 0
  fi
  local pidfile=${1:-}
  local start_only=${2:-}
  find_yubihsm_connector || return $?
  case "${YUBIHSM_CONNECTOR:-}" in
    yhusb://*)
      # We don't handle that.
      return 0 ;;
  esac
  if [ "$start_only" = "y" ] && is_yubihsm_connector_running; then
    return 0  # Already running.
  fi
  pidfile=${YUBIHSM_CONNECTOR_PIDFILE:-${1:-}}
  if [ -z "${pidfile:-}" ]; then
    echo "Cannot start/restart YubiHSM connector without YUBIHSM_CONNECTOR_PIDFILE specified." >&2
    return 1
  fi
  export YUBIHSM_CONNECTOR_PIDFILE=$pidfile
  maybe_stop_yubihsm_connector y || return $?
  # Stopping the connector unsets the environment variable, so let's just set it again.
  export YUBIHSM_CONNECTOR_PIDFILE=$pidfile
  local pid
  nohup "$YUBIHSM_CONNECTOR_BIN" >/dev/null 2>&1 &pid=$!
  printf "%s\n" "$pid" > "$YUBIHSM_CONNECTOR_PIDFILE" || return $?
  if [ ! -e "$YUBIHSM_CONNECTOR_PIDFILE" ]; then
    echo "yubihsm-connector pidfile '$YUBIHSM_CONNECTOR_PIDFILE' does not exist somehow" >&2
  fi
  _we_started_yubihsm_connector=y
}

maybe_start_apksigner_batch() {
  maybe_start_or_restart_apksigner_batch "${1:-}" y || return $?
}

maybe_start_or_restart_apksigner_batch() {
  if [ "${NEVER_START_APKSIGNER_BATCH:-}" = "y" ]; then
    return 0
  fi
  if [ "${DRY_RUN:-}" = "y" ]; then
    return 0
  fi

  export APKSIGNER_BATCH_RUNTIME_DIR=${APKSIGNER_BATCH_RUNTIME_DIR:-${1:-}}
  local start_only=${2:-}

  if [ -z "$APKSIGNER_BATCH_RUNTIME_DIR" ]; then
    echo "Must set APKSIGNER_BATCH_RUNTIME_DIR to start apksigner" >&2
    return 1
  fi
  if [ -z "${APKSIGNER_BATCH_PIDFILE:-}" ]; then
    APKSIGNER_BATCH_PIDFILE=$APKSIGNER_BATCH_RUNTIME_DIR/apksigner.pid
  fi
  export APKSIGNER_BATCH_PIDFILE

  local was_running_once=
  local apksigner_batch_pid=
  local apksigner_batch_fifo_keepalive_pid=
  if [ -e "$APKSIGNER_BATCH_PIDFILE" ]; then
    was_running_once=y
    apksigner_batch_pid=$(cat "$APKSIGNER_BATCH_PIDFILE") || return $?
    apksigner_batch_fifo_keepalive_pid=$(
      cat "$APKSIGNER_BATCH_RUNTIME_DIR/apksigner_keepalive.pid"
    ) || return $?
  fi

  export APKSIGNER_BATCH_STDIN_FIFO=$APKSIGNER_BATCH_RUNTIME_DIR/apksigner_stdin_fifo
  export APKSIGNER_BATCH_STDOUT_FIFO=$APKSIGNER_BATCH_RUNTIME_DIR/apksigner_stdout_fifo
  export APKSIGNER_BATCH_STDERR_FIFO=$APKSIGNER_BATCH_RUNTIME_DIR/apksigner_stderr_fifo

  if [ "$start_only" = "y" ] && [ -n "$apksigner_batch_pid" ] && \
      ps -p "$apksigner_batch_pid" >/dev/null; then
    # Already running.
    export APKSIGNER_BATCH_PID=$apksigner_batch_pid
    return 0
  fi

  # Force stop it ('y' argument on end), to remove the FIFOs and other files, since by this point,
  # we know it is not currently running, or we are otherwise committed to restarting it.
  maybe_stop_apksigner_batch "$APKSIGNER_BATCH_RUNTIME_DIR" \
    "$apksigner_batch_pid" "$apksigner_batch_fifo_keepalive_pid" y || return $?

  # Start apksigner in batch mode for improved performance, to be used by the signing interceptor.
  # Pass its stdin and stdout FIFOs in environment variables.
  mkfifo "$APKSIGNER_BATCH_STDIN_FIFO" || return $?
  mkfifo "$APKSIGNER_BATCH_STDOUT_FIFO" || return $?
  mkfifo "$APKSIGNER_BATCH_STDERR_FIFO" || return $?

  java_cmd=(java -Xmx4096m \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
    "-Djava.library.path=$(pwd)/lib64" \
    -jar "$(pwd)/framework/apksigner.jar"
  )
  local pid
  nohup "${java_cmd[@]}" batch \
    < "$APKSIGNER_BATCH_STDIN_FIFO" \
    2> "$APKSIGNER_BATCH_STDERR_FIFO" \
    > "$APKSIGNER_BATCH_STDOUT_FIFO" \
    &pid=$!
  printf "%s\n" "$pid" > "$APKSIGNER_BATCH_PIDFILE" || return $?

  export APKSIGNER_BATCH_PID=$!
  printf "%s\n" "$APKSIGNER_BATCH_PID" > "$APKSIGNER_BATCH_RUNTIME_DIR/apksigner.pid"
  nohup sleep infinity >"$APKSIGNER_BATCH_STDIN_FIFO" 2>&1 &
  local keepalive_pid=$!
  printf "%s\n" "$keepalive_pid" > "$APKSIGNER_BATCH_RUNTIME_DIR/apksigner_keepalive.pid"
  if [ "$was_running_once" != "y" ]; then
    _we_started_apksigner=y
  fi
  sleep 1
  if ! ps -p "$APKSIGNER_BATCH_PID" >/dev/null; then
    echo "Apksigner not running!" >&2
    exit 1
  fi
  if ! ps -p "$keepalive_pid" >/dev/null; then
    echo "Keepalive not running!" >&2
    exit 1
  fi
}

maybe_stop_yubihsm_connector() {
  if [ "${NEVER_START_YUBIHSM_CONNECTOR:-}" = "y" ]; then
    return 0
  fi
  local for_restart=${1:-}
  if [ "$for_restart" != "y" ] && [ "$_we_started_yubihsm_connector" != "y" ]; then
    return 0
  fi
  if [ -z "$YUBIHSM_CONNECTOR_PIDFILE" ]; then
    # Already stopped.
    return 0
  fi
  local pid
  if [ ! -e "$YUBIHSM_CONNECTOR_PIDFILE" ]; then
    echo "yubihsm-connector pidfile '$YUBIHSM_CONNECTOR_PIDFILE' does not exist somehow" >&2
  fi
  if [ -e "$YUBIHSM_CONNECTOR_PIDFILE" ]; then
    pid=$(cat "$YUBIHSM_CONNECTOR_PIDFILE")
    if ps -p "$pid" >/dev/null; then
      kill "$pid" || return $?
    fi
    if ps -p "$pid" >/dev/null; then
      echo "Could not kill existing yubihsm-connector." >&2
      return 1
    fi
    rm -f "$YUBIHSM_CONNECTOR_PIDFILE"
  fi
  YUBIHSM_CONNECTOR_PIDFILE=
}

maybe_stop_apksigner_batch() {
  if [ "${NEVER_START_APKSIGNER_BATCH:-}" = "y" ]; then
    return 0
  fi
  local should_stop=${4:-$_we_started_apksigner}
  if [ "${DRY_RUN:-}" = "y" ]; then
    return 0
  fi
  if [ "$should_stop" != "y" ]; then
    return 0
  fi
  local runtime_dir=${1:-$APKSIGNER_BATCH_RUNTIME_DIR}
  if [ ! -d "$runtime_dir" ]; then
    echo "apksigner runtime dir does not exist: $runtime_dir" >&2
    return 0
  fi
  local apksigner_batch_pid=${2:-}
  local apksigner_batch_fifo_keepalive_pid=${3:-}
  if { [ -z "$apksigner_batch_pid" ] || [ -z "$apksigner_batch_fifo_keepalive_pid" ]; } \
      && [ -e "$runtime_dir/apksigner.pid" ]; then
    apksigner_batch_pid=$(cat "$runtime_dir/apksigner.pid")
    apksigner_batch_fifo_keepalive_pid=$(cat "$runtime_dir/apksigner_keepalive.pid") || true
  fi
  # Send a signal that we are done.
  printf "\0\0" | timeout 1 tee -a "$runtime_dir/apksigner_stdin_fifo" >/dev/null || true
  timeout 1 cat "$runtime_dir/apksigner_stdout_fifo" >/dev/null 2>&1 || true
  timeout 1 cat "$runtime_dir/apksigner_stderr_fifo" >/dev/null 2>&1 || true
  if [ -n "$apksigner_batch_fifo_keepalive_pid" ]; then
    if ps -p "$apksigner_batch_fifo_keepalive_pid" >/dev/null; then
      kill "$apksigner_batch_fifo_keepalive_pid" || true
    fi
    if ps -p "$apksigner_batch_fifo_keepalive_pid" >/dev/null; then
      kill -9 "$apksigner_batch_fifo_keepalive_pid" || true
      sleep 1
    fi
    if ps -p "$apksigner_batch_fifo_keepalive_pid" >/dev/null; then
      echo "Could not kill apksigner keepalive process" >&2
      return 1
    fi
  fi
  rm -f "$runtime_dir/apksigner.pid"
  rm -f "$runtime_dir/apksigner_keepalive.pid"
  rm -f "$runtime_dir/apksigner_stdin_fifo"
  rm -f "$runtime_dir/apksigner_stdout_fifo"
  rm -f "$runtime_dir/apksigner_stderr_fifo"
  if [ -n "$apksigner_batch_pid" ]; then
    if ps -p "$apksigner_batch_pid" >/dev/null; then
      kill "$apksigner_batch_pid" || return $?
    fi
    if ps -p "$apksigner_batch_pid" >/dev/null; then
      kill -9 "$apksigner_batch_pid" || return $?
      sleep 1
    fi
    if ps -p "$apksigner_batch_pid" >/dev/null; then
      echo "Could not kill apksigner, pid $apksigner_batch_pid" >&2
      return 1
    fi
  fi
}

# Returns true if the key ID provided is within a range eligible to be exported.
get_key_id_is_exportable_yn() {
  # At the moment, everything should be exportable until there is further testing and
  # validation that key rotation works, and a known-working process. It seems that
  # rotating core keys can lead to problems if done as a simple replacement, such as
  # platform apps not working. There are ways around this, as mentioned on the LineageOS
  # wiki for example, but it's not a sure- and secure-enough thing to go for right now.
  # Once we figure it out, we can always rotate the relevant keys and make non-exportable.
  # TODO: The above.
  echo y
}

unused_get_key_id_is_exportable_yn_new() {
  # Core keys are not exportable for transparency reasons.
  # Core keys can be rotated, so they do not need to be exported. This provides an assurance
  # that the same HSM has been used to sign everything that uses these important core keys,
  # as the attestation will show that the key was generated on device and not exportable.
  # This makes it possible to determine if the secondary HSM - or any other device - is used
  # for signing these components, which could provide a clue in case somehow the keys are
  # used without proper authorization.
  local key_id=$1
  local ota_key_id
  local key_lookup=${key_id_to_type_and_name_pairs[$key_id]:-}
  local pair
  if [ -z "$key_lookup" ]; then
    echo "ERROR: get_key_id_is_exportable_yn: Could not find key information for key ID $key_id." >&2
    return 1
  fi
  local exportable=y
  local oldIFS=$IFS
  IFS=$'\t'; set -- $key_lookup; IFS=$oldIFS
  for pair in "$@"; do
    case "$pair" in
      avb:*|other:ota)
        # AVB cannot be rotated, and OTA needs the prior key to be rotated,
        # so these keys are essential and we cannot do without a backup.
        exportable=y
        break ;;
      core:*)
        # A key ID that solely represents a core key is not exportable because
        # these keys can be rotated without requiring the old keys.
        # TODO: How exactly? In recent testing, it is broken thanks to SELinux, with
        #       platform apps like Settings crashing. In earlier testing, it was fine...
        exportable=n ;;
      *)
        # It's exportable if it represents anything else.
        exportable=y
        break ;;
    esac
  done
  echo $exportable
}

# Returns true if the key ID provided is within the range designated for on-demand keys,
# meaning the key has been exported under wrap and can be removed and re-imported to the
# HSM any time in order to make room for other keys as needed.
get_key_id_is_ondemand_yn() {
  get_key_id_is_per_device_yn "$@" || return $?
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
    echo "ERROR: No objects found on YubiHSM." >&2
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

dump_object_info() {
  yubihsm_nolog -a list-objects || return $?
}

check_command_audit_value() {
  local command_audit_value
  command_audit_value=$(
    yubihsm_nolog -a get-option --opt-name command-audit | sed -e 's/^Option value is: //'
  ) || return $?
  [ "$command_audit_value" = "$YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE" ] || return $?
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

get_formatted_date() {
  printf "%s" "$(date --utc +"%Y-%m-%d_%H-%M-%S-%3N")"
}

get_name_for_hsm() {
  printf "%s" "${yubihsm_id:-unknown-hsm}"
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

initialize_vendor_release() {
  if [ "${DRY_RUN:-}" = "y" ]; then
    return 0
  fi
  local DEVICE=${1:-$DEVICE}
  local BUILD_NUMBER=${2:-$BUILD_NUMBER}
  local command=${3:-$0}

  {
    if [ -n "${YUBIHSM_LOCKFILE:-}" ]; then
      # Ensure only one YubiHSM operation, including subsequent log extraction,
      # can happen at a time.
      flock -x 3
    fi

    # Need to *not* redirect to the lockfile here in case we launch a new long-running process,
    # i.e. if we re-launch yubihsm-connector, because if we do, then the new process will keep
    # the lock open until it ends, which may never happen, and new executions would be deadlocked.
    # (This has been observed happening already.)
    {
      read_yubihsm_deviceinfo || return $?
      local name
      name=$(get_name_for_hsm) || return $?
      default_prefix=$BUILD_NUMBER-$DEVICE-$(basename "$command" .sh)
      AUDIT_LOG_PATH=$YUBIHSM_LOGS_DIR/$name/$(get_formatted_date)-$default_prefix.log
      export AUDIT_LOG_PATH
      EXEC_LOG_PATH=$YUBIHSM_LOGS_DIR/$name/exec/$(get_formatted_date)-$default_prefix.log
      mkdir -p "$YUBIHSM_LOGS_DIR/$name/exec"
      export EXEC_LOG_PATH
      local key_id
      key_id=$(get_key_id avb vbmeta) || return $?

      extract_logs "BUILD_NUMBER=$BUILD_NUMBER DEVICE=$DEVICE $0 ${*@Q}" \
        || return $?

      if [ "${ENSURE_KEY_IS_AVAILABLE:-y}" = "y" ]; then
        $maybe_dry_run ensure_key_is_available "$key_id" || return $?
      fi
    } 3>/dev/null

  } 3>>"${YUBIHSM_LOCKFILE:-/dev/null}"
}

finalize_vendor_release() {
  local err=0

  # Extract logs.
  if [ -n "${AUDIT_LOG_PATH:-}" ]; then
    extract_logs "Finished BUILD_NUMBER=$BUILD_NUMBER DEVICE=$DEVICE $0 ${*@Q}" \
      || true
  fi

  maybe_stop_apksigner_batch || true
  maybe_stop_yubihsm_connector || true

  if [ -n "${YUBIHSM_TMPDIR:-}" ] && [ -d "$YUBIHSM_TMPDIR" ] && \
      [ "$_we_created_yubihsm_tmpdir" = "y" ]; then
    rm -rf "$YUBIHSM_TMPDIR" || true
  fi
  common_cleanup || true
}
