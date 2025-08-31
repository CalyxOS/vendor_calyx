export KEYMAPPER=id2b
export USE_APKSIGNER=y
export PKCS11_PIN=$(printf "%4s" "$YUBIHSM_AUTHKEY" | tr ' ' 0)$YUBIHSM_PASSWORD
export FIND_KEYS_BY_ID=y
export YUBIHSM_CONNECTOR=${YUBIHSM_CONNECTOR:-yhusb://}
export YUBIHSM_LOGS_DIR=${YUBIHSM_LOGS_DIR:-$(pwd)/logs}
export YUBIHSM_KEY_CAPABILITIES=${YUBIHSM_KEY_CAPABILITIES:-sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep}
export YUBIHSM_OPAQUE_CAPABILITIES=${YUBIHSM_OPAQUE_CAPABILITIES:-}
export YUBIHSM_ONDEMAND_DOMAIN=${YUBIHSM_ONDEMAND_DOMAIN:-2}
export YUBIHSM_EXPORTABLE_DOMAIN=${YUBIHSM_EXPORTABLE_DOMAIN:-3}
export YUBIHSM_UNEXPORTABLE_DOMAIN=${YUBIHSM_UNEXPORTABLE_DOMAIN:-4}
export YUBIHSM_WRAP_KEY=${YUBIHSM_WRAP_KEY:-0x0010}
export YUBIHSM_MAX_ONDEMAND_KEYS=${YUBIHSM_MAX_ONDEMAND_KEYS:-20}
# alternately, http://127.0.0.1:12345

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # TODO: There's got to be a better way.
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/pkcs11/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr/local -path '/usr/local/lib*/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/pkcs11/yubihsm_pkcs11.so' | head -n 1)}
  PKCS11_MODULE=${PKCS11_MODULE:-$(find /usr -path '/usr/lib*/yubihsm_pkcs11.so' | head -n 1)}
  if [ -z "$PKCS11_MODULE" ]; then
    echo "Please install the YubiHSM PKCS#11 module, or set PKCS11_MODULE to its path." >&2
    return 1
  fi
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

_generate_yubihsm_pkcs11_library_config() {
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
  if [ -z "${YUBIHSM_AUTHKEY:-}" ]; then
    echo "ERROR: Must set YUBIHSM_AUTHKEY." >&2
    return 1
  fi
  if [ -z "${YUBIHSM_PASSWORD:-}" ]; then
    echo "ERROR: Must set YUBIHSM_PASSWORD." >&2
    return 1
  fi
  "$YUBIHSM_SHELL_BIN" \
    --connector "$YUBIHSM_CONNECTOR" \
    --authkey "$YUBIHSM_AUTHKEY" \
    --password file:<(printf "%s\n" "$YUBIHSM_PASSWORD") \
    "$@"
}

# Extract a text log to the path provided in argument 1, and a hex log to the path
# provided in argument 2. If neither argument is present, generate a path for both
# and extract both. If one is missing, skip extracting that one.
extract_logs() {
  local text_file=${1:-}
  local hex_file=${2:-}
  local file
  if [ -z "$text_file" ] || [ "$text_file" = "$(basename "$text_file")" ]; then
    if [ -n "${YUBIHSM_LOGS_DIR:-}" ] && [ ! -d "$YUBIHSM_LOGS_DIR" ]; then
      mkdir "$YUBIHSM_LOGS_DIR" || {
        err=$?
        echo "YUBIHSM_LOGS_DIR ($YUBIHSM_LOGS_DIR) does not exist, and failed to create it" >&2
        return $err
      }
    fi
  fi
  if [ -z "$text_file" ]; then
    text_file=audit-$(date +%Y-%m-%d-%H-%M-%S) || return $?
    [ -n "$hex_file" ] || hex_file=$text_file.hex
    text_file=$text_file.log
  fi
  if [ "$text_file" = "$(basename "$text_file")" ]; then
    text_file=${YUBIHSM_LOGS_DIR:-.}/$text_file
  fi
  if [ -n "$hex_file" ] && [ "$hex_file" = "$(basename "$hex_file")" ]; then
    hex_file=${YUBIHSM_LOGS_DIR:-.}/$hex_file
  fi
  local last_index
  local logs
  logs=$(yubihsm -a get-logs) || {
    err=$?
    echo "Failed to get logs" >&2
    return $err
  }
  if [ -n "$text_file" ]; then
    [ -z "$PREPEND_LINE" ] || printf "%s\n" "$PREPEND_LINE" >> "$text_file"
    printf "%s\n" "$logs" >> "$text_file" || {
      echo "Failed to save logs" >&2
      return $?
    }
  fi
  last_index=$(
    printf "%s\n" "$logs" \
      | tail -n1 \
      | sed -n -e 's/^item: \+\([0-9]\+\) --.*$/\1/p' \
    ) \
    || return $?
  if [ -n "$hex_file" ]; then
    yubihsm -a get-logs --outformat hex >> "$hex_file" || {
      err=$?
      echo "Failed to get and save logs in hex format" >&2
      return $err
    }
  fi
  if [ -z "$last_index" ] || ! [ "$last_index" -ge 0 ]; then
    if printf "%s\n" "$logs" | grep -Fx 'No logs to extract'; then
      echo "WARNING: No logs to extract!" >&2
      return 0
    fi
    echo "Failed to get index of last log entry" >&2
    return 1
  fi
  yubihsm -a set-log-index --log-index "$last_index" || {
    err=$?
    echo "Failed to set log index to $last_index" >&2
    return $err
  }
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

ensure_key_is_available() {
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
    --wrap-id "$YUBIHSM_WRAP_KEY" \
    --object-id "$key_id" \
    --object-type asymmetric-key \
    --domain "$YUBIHSM_ONDEMAND_DOMAIN,$YUBIHSM_EXPORTABLE_DOMAIN" \
    --capabilities "$YUBIHSM_KEY_CAPABILITIES" \
    --in "${KEY_DIR}${key_id}-asymmetric-key.yhk" \
    || return $?

  # The cert itself is not sensitive so does not really need to be wrapped and unwrapped,
  # but yubihsm-setup already does it.
  #yubihsm -a put-wrapped --wrap-id "$YUBIHSM_WRAP_KEY" --object-id "$key_id" \
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
    --in "${KEY_DIR}${key_id}.x509.pem"

  # Extract logs.
  # Actually, we'll save that for a later operation.
  # extract_logs || return $?
}

initialize_release_vendor() {
  local key_id
  key_id=$(get_key_id avb vbmeta) || return $?
  $maybe_dry_run ensure_key_is_available "$key_id" || return $?
}
