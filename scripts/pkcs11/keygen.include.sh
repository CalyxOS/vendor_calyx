#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$BASH_SOURCE")";pwd -P)
scriptpath=$(cd "$(dirname "$BASH_SOURCE")/..";pwd -P)
source "$scriptpath/common.include.sh" || exit $?
source "$pkcs11_scriptpath/include.sh" || exit $?

_default_pkcs11_token_label=androsign
_default_signing_subject_template="/C=US/ST=New York/L=Rochester/O=Android/OU=Android/CN=_KEY_LABEL_/emailAddress=android@example.com/"

unset no_check_exist

initialize_pre_metadata() {
  initialize "$@" || return $?
}

initialize() {
  echo "ERROR: initialize_pre_metadata not implemented." >&2
  echo "       Consider implementing either as a call to initialize_pre_metadata_pkcs11 if supported." >&2
  echo "       Or, if initialization is not necessary, implement it as 'true'." >&2
  exit 1
}

initialize_post_metadata() {
  echo "ERROR: initialize_post_metadata not implemented." >&2
  echo "       Consider implementing either as a call to initialize_post_metadata_pkcs11 if supported." >&2
  echo "       Or, if initialization is not necessary, implement it as 'true'." >&2
  exit 1
}

maybe_initialize_token() {
  echo "ERROR: maybe_initialize_token not implemented." >&2
  echo "       Consider implementing it as a call to maybe_intialize_token_pkcs11 if supported." >&2
  echo "       Or, if token initialization is not necessary, implement it as 'true'." >&2
  exit 1
}

does_key_exist_yn() {
  echo "ERROR: does_key_exist_yn not implemented." >&2
  echo "       Consider implementing it as a call to does_key_exist_yn_pkcs11 if supported." >&2
  exit 1
}

does_cert_exist_yn() {
  echo "ERROR: does_cert_exist_yn not implemented." >&2
  echo "       Consider implementing it as a call to does_cert_exist_yn_pkcs11 if supported." >&2
  exit 1
}

generate_keypair() {
  echo "ERROR: generate_keypair not implemented." >&2
  echo "       Consider implementing it as a call to generate_keypair_pkcs11 if supported." >&2
  exit 1
}

generate_cert() {
  echo "ERROR: generate_cert not implemented." >&2
  echo "       Consider implementing it as a call to generate_cert_pkcs11 if supported." >&2
  exit 1
}

get_key_id() {
  echo "ERROR: get_key_id not implemented." >&2
  echo "       This method should take a key_type and key_name and output a PKCS#11 ID." >&2
  echo "       It is usually implemented in the keymapper." >&2
  exit 1
}

find_pkcs11_module() {
  echo "ERROR: find_pkcs11_module not implemented." >&2
  echo "       Or, if finding the module is not necessary, consider implementing it as 'true'." >&2
  exit 1
}

keygen_usage() {
  echo "usage: $(basename "$0") [public_key_output_dir]"
  echo
  echo "Generate keys using SoftHSM2 or a similarly compatible PKCS#11 module specified by the"
  echo "PKCS11_MODULE environment variable."
  echo
  echo "Most functionality is controlled by environment variables. Check out the initialize"
  echo "functions in this script or its includes."
}

keygen_main() {
  declare -g key_out_dir=
  while true; do
    case "${1:-}" in
      -?|-h|--help|"")
        keygen_usage
        return 0
        ;;
      *)
        if [ -n "$key_out_dir" ]; then
          echo "Expected just one argument, the key output directory." >&2
          return 1
        else
          key_out_dir=$1
        fi
        ;;
    esac
    shift 1
    [ $# -gt 0 ] || break
  done

  mkdir -p -m0700 "$key_out_dir" || return $?

  initialize_pre_metadata || return $?
  load_metadata || return $?
  load_keymapper || return $?
  initialize_post_metadata_common || return $?
  initialize_post_metadata || return $?
  generate_keys || return $?
  echo "Key generation finished successfully."
}

generate_keys() {
  if [ -z "${devices+x}" ] || [ "${#devices[@]}" -lt 1 ]; then
    echo "ERROR: No defined devices for which to generate keys." >&2
    echo "       Ensure the devices array is populated in \$DEVICES_FILE ($DEVICES_FILE)." >&2
    return 1
  fi
  declare -A already_generated
  local key_type
  for key_type in "${key_types[@]?Key types should be listed in metadata}"; do
    echo "###################################"
    echo "### GENERATING KEYS: $key_type"
    echo "###################################"
    local array_name
    case "$key_type" in
      avb)
        array_name=keys_avb ;;
      apex_container|apex_payload)
        array_name=keys_apex ;;
      *)
        array_name=keys_${key_type} ;;
    esac
    local indirect_array
    indirect_array="${array_name}[@]" || return $?
    local key_name
    for key_name in "${!indirect_array}"; do
      echo "# KEY: $key_name"

      # Skip getting key value for each device if it's not a per-device key.
      local -a devices_array
      local per_device
      per_device=$(get_key_is_per_device_yn "$key_type" "$key_name") || return $?
      if [ "$per_device" = "n" ]; then
        devices_array=("")
      else
        devices_array=("${devices[@]}")
      fi

      local device
      local mapped_value
      for device in "${devices_array[@]}"; do
        mapped_value=$(KEY_DIR= DEVICE=$device get_key "$key_type" "$key_name") || return $?
        if [ -z "$mapped_value" ]; then
          continue
        fi
        local msg="# VALUE: $mapped_value${device:+ (DEVICE: $device)}"
        if [ -n "${already_generated[$mapped_value]:-}" ]; then
          printf "%s\n" "$msg: skipping, generated ${already_generated[$mapped_value]}" >&2
          continue
        fi
        local key_exists
        key_exists=$(DEVICE=$device does_key_exist_yn "$mapped_value") || return $?
        local cert_exists
        cert_exists=$(DEVICE=$device does_cert_exist_yn "$mapped_value") || return $?
        local key_id
        local key_algorithm=
        if [ "${FIND_KEYS_BY_ID:-}" = "y" ]; then
          key_id=$mapped_value
        else
          key_id=$(get_key_id "$key_type" "$mapped_value") || return $?
        fi
        if [ "$key_exists" = "n" ]; then
          [ -n "$key_algorithm" ] \
            || key_algorithm=$(get_key_algorithm "$key_type" "$key_name") || return $?
          printf "%s\n" "$msg"
          DEVICE=$device \
          generate_keypair "$key_id" "$mapped_value" "$key_type" "$key_name" "$key_algorithm" \
            || return $?
        else
          printf "%s\n" "$msg: key already exists"
          already_generated[$mapped_value]="before this run"
        fi
        if [ "$cert_exists" = "n" ]; then
          if [ "$key_exists" = "y" ]; then
            printf "%s\n" "$msg: generating missing cert"
          fi
          [ -n "$key_algorithm" ] \
            || key_algorithm=$(get_key_algorithm "$key_type" "$key_name") || return $?
          DEVICE=$device \
          generate_cert "$key_id" "$mapped_value" "$key_type" "$key_name" "$key_algorithm" \
            || return $?
        fi
        if [ "$key_exists" = "n" ] || [ "$cert_exists" = "n" ]; then
          anything_generated=1
          already_generated[$mapped_value]="just now"
        fi
      done
    done || return $?
  done
}

maybe_initialize_token_pkcs11() {
  if is_any_token_initialized_pkcs11; then
    return 0
  fi
  if [ -z "${PKCS11_SO_PIN:-}" ]; then
    echo "Cannot initialize PKCS#11 token: you must set PKCS11_SO_PIN." >&2
    return 1
  fi
  if [ "${PKCS11_TESTING:-n}" = "n" ] && [ -z "${PKCS11_TOKEN_LABEL:-}" ]; then
    echo "Neither PKCS11_TOKEN_LABEL nor PKCS11_TESTING=y specified!" >&2
    echo "If you are just testing, please supply PKCS11_TESTING=y to use the default label." >&2
    echo "Otherwise, please set a label via PKCS11_TOKEN_LABEL,"\
         "e.g. $_default_pkcs11_token_label." >&2
    return 1
  fi
  if [ -z "${PKCS11_TOKEN_LABEL}" ]; then
    # TODO: Is this supposed to be supplied as --label rather than --token-label for this?
    # That is how it was before... Test it with SoftHSM.
    export PKCS11_TOKEN_LABEL=$_default_pkcs11_token_label
    refresh_pkcs11_tool_args || return $?
  fi
  PKCS11_SO_PIN=$PKCS11_SO_PIN \
    "$PKCS11_TOOL_BIN" \
      "${pkcs11_tool_args_no_pin[@]}" \
      --init-token \
      --so-pin env:PKCS11_SO_PIN || return $?
  if ! is_any_token_initialized_pkcs11; then
    echo "ERROR: Initialized token, but our check doesn't confirm that it is intialized." >&2
    return 1
  fi
  PKCS11_PIN=$PKCS11_PIN PKCS11_SO_PIN=$PKCS11_SO_PIN \
    "$PKCS11_TOOL_BIN" \
      "${pkcs11_tool_args_so_pin[@]}" \
      --pin env:PKCS11_PIN || return $?
}

is_any_token_initialized_pkcs11() {
  # Any token with a URI is considered to be initialized.
  "$PKCS11_TOOL_BIN" --module "$PKCS11_MODULE"  --list-token-slots | grep -q '^ *uri *:' \
    || return $?
}

load_metadata() {
  local missing_something=
  if [ -z "${METADATA_FILE:-}" ]; then
    METADATA_FILE=$scriptpath/metadata
  fi
  if [ -e "$METADATA_FILE" ]; then
    # FIXME: Current metadata files may have issues with unbound variables.
    set +u  # Turn off checking for unbound variable use.
    PKCS11_MODULE=$PKCS11_MODULE source "$METADATA_FILE" || return $?
    set -u  # Turn the checking back on.
  else
    echo "ERROR: Please set METADATA_FILE to the path of a file that includes key mappings." >&2
    echo "       Note that this file will be sourced as a script, so it should be trusted!" >&2
    missing_something=1
  fi
  if [ -z "${DEVICES_FILE:-}" ]; then
    DEVICES_FILE=$(realpath -e -q "$scriptpath/../../../calyx/scripts/vars/devices")
  fi
  if [ -e "$DEVICES_FILE" ]; then
    source "$DEVICES_FILE" || return $?
  else
    echo "ERROR: Please set DEVICES_FILE to the path of a file that includes a list of" >&2
    echo "       devices in the 'devices' array. Note that this file will be sourced as" >&2
    echo "       a script, so it should be trusted!" >&2
    missing_something=1
  fi
  if [ -n "$missing_something" ]; then
    return 1
  fi
}

initialize_post_metadata_common() {
  local missing_something=
  if ! OPENSSL_BIN=${OPENSSL_BIN:-$(which openssl)}; then
    echo "Please install openssl, or set OPENSSL_BIN to its path." >&2
    missing_something=1
  fi
  if ! AVBTOOL_BIN=${AVBTOOL_BIN:-$(which avbtool)}; then
    AVBTOOL_BIN=$(pwd)/bin/avbtool
    if [ ! -x "$AVBTOOL_BIN" ] || [ ! -f "$AVBTOOL_BIN" ]; then
      echo "Could not find avbtool. Please set AVBTOOL_BIN to its location, or run this from" \
        "otatools-keys-package's extracted folder." >&2
      missing_something=1
    fi
  fi
  if [ -n "$missing_something" ]; then
    return 1
  fi
  if [ -z "${RSA_KEY_SIZE:-}" ]; then
    RSA_KEY_SIZE=4096
    echo "RSA_KEY_SIZE not specified. Using $RSA_KEY_SIZE." >&2
  fi
  if [ -z "${CERT_EXPIRY_DAYS:-}" ]; then
    CERT_EXPIRY_DAYS=7200
    echo "CERT_EXPIRY_DAYS not specified. Using $CERT_EXPIRY_DAYS." >&2
  fi
  if [ -z "${SIGNING_SUBJECT_TEMPLATE:-}" ]; then
    # Performs replacement _KEY_LABEL_. Cannot be escaped.
    SIGNING_SUBJECT_TEMPLATE=${SIGNING_SUBJECT_TEMPLATE:-$_default_signing_subject_template}
    echo "SIGNING_SUBJECT_TEMPLATE not specified. Using $SIGNING_SUBJECT_TEMPLATE." >&2
  fi
  if [ -z "${EXTRACTION_ARGS:-}" ]; then
    EXTRACTION_ARGS="--sensitive --extractable"
    echo "EXTRACTION_ARGS not specified. Using $EXTRACTION_ARGS." >&2
  fi
}

initialize_pre_metadata_pkcs11() {
  local missing_something=
  if [ -n "${PKCS11_MODULE+x}" ] && [ -z "${PKCS11_MODULE:-}" ]; then
    echo "WARNING: PKCS11_MODULE set to an empty string! Expecting it to be in the metadata file." >&2
    echo "         Unset PKCS11_MODULE entirely if you want this script to find it." >&2
  elif ! find_pkcs11_module || [ -z "${PKCS11_MODULE:-}" ]; then
    echo "Could not find PKCS#11 module. Please set PKCS11_MODULE to its location." >&2
    missing_something=1
  fi
  if ! PKCS11_TOOL_BIN=${PKCS11_TOOL_BIN:-$(which pkcs11-tool)}; then
    echo "Please install pkcs11-tool, or set PKCS11_TOOL_BIN to its path." >&2
    missing_something=1
  fi
  if [ -z "${PKCS11_OPENSSL_ENGINE_LIBRARY_PATH:-}" ]; then
    echo "Please install openssl pkcs11 engine library, or set PKCS11_OPENSSL_ENGINE_LIBRARY_PATH to its path." >&2
    missing_something=1
  fi
  if [ -n "$missing_something" ]; then
    return 1
  fi
  if [ -z "${PKCS11_SO_PIN:-}" ] && \
     { [ "${MODIFICATION_USES_SO_PIN:-}" = "y" ] || [ "${PKCS11_TESTING:-}" = "y" ]; }; then
    if [ "${PKCS11_TESTING:-n}" = "n" ]; then
      echo "PKCS11_SO_PIN environment variable must be supplied for production!" >&2
      echo "If you are just testing, please supply PKCS11_TESTING=y." >&2
      return 1
    fi
    PKCS11_SO_PIN=12345678
    echo "PKCS11_SO_PIN not specified. Using $PKCS11_SO_PIN." >&2
  fi
  if [ -z "${PKCS11_PIN:-}" ]; then
    if [ "${PKCS11_TESTING:-n}" = "n" ]; then
      echo "PKCS11_PIN environment variable must be supplied for production!" >&2
      echo "If you are just testing, please supply PKCS11_TESTING=y." >&2
      return 1
    fi
    PKCS11_PIN=123456
    echo "PKCS11_PIN not specified. Using $PKCS11_PIN." >&2
  fi
  refresh_pkcs11_tool_args || return $?
}

initialize_post_metadata_pkcs11() {
  refresh_pkcs11_tool_args || return $?
}

generate_keypair_pkcs11() {
  local key_id=$1
  key_id=$(get_key_id_for_pkcs11-tool "$key_id")
  local key_label=$2
  local key_type=$3
  local key_name=$4
  local key_algorithm=$5
  local -a args=()
  if [ "${MODIFICATION_USES_SO_PIN:-}" = "y" ]; then
    args=("${pkcs11_tool_args_so_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi
  args+=(
    --keypairgen
    --key-type "$key_algorithm"
    $EXTRACTION_ARGS
  )
  PKCS11_PIN=$PKCS11_PIN \
    "$PKCS11_TOOL_BIN" "${args[@]}" --id "$key_id" --label "$key_label" || return $?
  # Note: The public key will be pulled out of the certificate later.
}

generate_cert_pkcs11() {
  local key_id=$1
  key_id=$(get_key_id_for_pkcs11-tool "$key_id")
  local key_label=$2
  local key_type=$3
  local key_name=$4
  local key_algorithm=$5
  local escaped_key_label_for_signing_subject=${key_label//\//\\/}
  local tmpfile
  tmpfile=$(mktemp "${TMPDIR:-/tmp}/cert.XXXXXX") || return $?

  local sha_arg=
  case "$key_algorithm" in
    *224*)
      sha_arg=-sha224 ;;
    *256*)
      sha_arg=-sha256 ;;
    *384*)
      sha_arg=-sha384 ;;
    *512*|*521*)
      sha_arg=-sha512 ;;
    *)
      sha_arg=-sha256 ;;
  esac

  local err=0
  # Generate a self-signed certificate as usual, but using the HSM.
  # Capture the public key into the cert variable.
  # TODO: Should -sha256 be overridable?
  OPENSSL_CONF=<(generate_openssl_config) \
    "$OPENSSL_BIN" req -new -x509 -engine pkcs11 \
      -subj "${SIGNING_SUBJECT_TEMPLATE//_KEY_LABEL_/$escaped_key_label_for_signing_subject}" \
      $sha_arg \
      -keyform engine \
      -key "$(get_privkey_uri "$key_label")" \
      -days "$CERT_EXPIRY_DAYS" \
      -out "$tmpfile" || { err=$?; rm -f "$tmpfile"; return $err; }
  if [ "${MODIFICATION_USES_SO_PIN:-}" = "y" ]; then
    args=("${pkcs11_tool_args_so_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi

  # Import the self-signed certificate.
  PKCS11_PIN=$PKCS11_PIN \
    "$PKCS11_TOOL_BIN" \
      "${args[@]}" \
      --write-object "$tmpfile" \
      --type cert \
      --id "$key_id" \
      --label "$key_label" || err=$?

  if [ $err -eq 0 ] && [ -n "${key_out_dir:-}" ]; then
    # Output the certificate and the public key.
    local parent_key_dir=$(dirname "$key_label")
    local dstdir="$key_out_dir/$parent_key_dir"
    local name=$(basename "$key_label")
    mkdir -p "$dstdir" || return $?
    cp "$tmpfile" "$dstdir/$name.x509.pem" || return $?
    case "$key_type" in
      avb|apex_payload|apex_container)
        if [ -e "$dstdir/$name.pem" ]; then
          echo "Public key file already exists: $dstdir/$name.pem" >&2
        else
          # Output public key and avbpubkey for APEX payload or AVB keys.
          # Also do this for core keys, since APEX might use them.
          "$OPENSSL_BIN" x509 -pubkey -noout -in "$tmpfile" -out "$dstdir/$name.pem" || return $?
        fi
        if [ "$key_type" = "avb" ] || [ "$key_type" = "apex_payload" ]; then
          if [ -e "$dstdir/$name.avbpubkey" ]; then
            echo "avbpubkey file already exists: $dstdir/$name.avbpubkey" >&2
          else
            "$AVBTOOL_BIN" extract_public_key \
              --key "$dstdir/$name.pem" \
              --output "$dstdir/$name.avbpubkey" \
              || return $?
          fi
        fi
        ;;
    esac
  fi
  rm -f "$tmpfile"
  return $err
}

_does_key_or_cert_exist_yn_pkcs11() {
  local result
  if [ "${FIND_KEYS_BY_ID:-}" = "y" ]; then
    does_id_exist_for_type_yn_pkcs11 "$1" "$2"
    return $?
  fi
  local key_label=$1
  result=$(FIND_KEYS_BY_ID=n find_id_for_cert "$key_label") || return $?
  if [ -n "$result" ]; then
    # Skip key that already exists.
    echo y
  else
    echo n
  fi
}

does_key_exist_yn_pkcs11() {
  _does_key_or_cert_exist_yn_pkcs11 "$@" pubkey || return $?
}

does_cert_exist_yn_pkcs11() {
  _does_key_or_cert_exist_yn_pkcs11 "$@" cert || return $?
}
