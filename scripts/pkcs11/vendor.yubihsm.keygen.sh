#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$0")";pwd -P)
scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
source "$pkcs11_scriptpath/keygen.include.sh" || exit $?
# $scriptpath/vendor.yubihsm.include.sh is included later, in initialize_pre_metadata()

trap cleanup EXIT

unset TEMP_DIR
unset KEY_ID

pkcs11-tool_for_yubihsm() {
  PKCS11_PIN=$PKCS11_PIN \
  YUBIHSM_PKCS11_CONF=<(generate_yubihsm_pkcs11_library_config) \
    "$UNDERLYING_PKCS11_TOOL_BIN" "$@" || return $?
}

openssl_for_yubihsm() {
  PKCS11_PIN=$PKCS11_PIN \
  YUBIHSM_PKCS11_CONF=<(generate_yubihsm_pkcs11_library_config) \
    "$UNDERLYING_OPENSSL_BIN" "$@" || return $?
}

initialize_pre_metadata() {
  TEMP_DIR=$(mktemp -d /dev/shm/keygen-XXXXXXXX) || return $?

  if [ -z "${YUBIHSM_AUTHKEY:-}" ]; then
    YUBIHSM_AUTHKEY=1
    echo "YUBIHSM_AUTHKEY not specified. Using $YUBIHSM_AUTHKEY." >&2
  fi
  if [ -z "${YUBIHSM_PASSWORD:-}" ]; then
    YUBIHSM_PASSWORD=password
    echo "YUBIHSM_PASSWORD not specified. Using $YUBIHSM_PASSWORD." >&2
  fi

  if [ -n "${PKCS11_PIN:-}" ]; then
    echo "WARNING: Specified PKCS11_PIN is ignored! It is constructed from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD." >&2
  fi

  source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || exit $?

  #PKCS11_OPENSSL_CONFIG_EXTRA="INIT_ARGS = connector=$YUBIHSM_CONNECTOR debug"
  initialize_pre_metadata_pkcs11 "$@" || return $?
  YUBIHSM_KEY_CAPABILITIES=${YUBIHSM_KEY_CAPABILITIES:-}
  YUBIHSM_OPAQUE_CAPABILITIES=${YUBIHSM_OPAQUE_CAPABILITIES:-}
  echo "Using additional YUBIHSM_KEY_CAPABILITIES: ${YUBIHSM_KEY_CAPABILITIES:-(none)}." >&2
  echo "Using additional YUBIHSM_OPAQUE_CAPABILITIES: ${YUBIHSM_OPAQUE_CAPABILITIES:-(none)}." >&2
  UNDERLYING_PKCS11_TOOL_BIN=$PKCS11_TOOL_BIN
  UNDERLYING_OPENSSL_BIN=$OPENSSL_BIN
  PKCS11_TOOL_BIN=pkcs11-tool_for_yubihsm
  OPENSSL_BIN=openssl_for_yubihsm
  local missing_something=
  if ! YUBIHSM_SHELL_BIN=${YUBIHSM_SHELL_BIN:-$(which yubihsm-shell)}; then
    echo "Please install yubihsm-shell, or set YUBIHSM_SHELL_BIN to its path." >&2
    missing_something=1
  fi
  if [ -n "$missing_something" ]; then
    exit 1
  fi

  read_yubihsm_deviceinfo || return $?
  unique_key_out_dir=$key_out_dir/by-id-$yubihsm_id-$(date +$DATE_FORMAT)
  declare -g hsm_key_out_dir=$key_out_dir/by-id-$yubihsm_id
}

initialize_post_metadata() {
  initialize_post_metadata_pkcs11 "$@" || return $?
  extract_attestation_key || exit $?
  save_yubihsm_deviceinfo || exit $?
}

_get_domains_for_key_id() {
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

_get_capabilities_for_key_id() {
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

generate_keypair() {
  local key_id=$1
  local key_label=$2  # unused
  local domain
  local capabilities
  domain=$(_get_domains_for_key_id "$key_id") || return $?
  capabilities=$(_get_capabilities_for_key_id "$key_id" "$YUBIHSM_KEY_CAPABILITIES") || return $?

  yubihsm -a generate-asymmetric-key \
    --object-id "$key_id" \
    --algorithm "rsa$RSA_KEY_SIZE" \
    --domain "$domain" \
    --capabilities "$capabilities" \
    || return $?
  # --label="$key_label"

  local is_key_id_exportable
  is_key_id_exportable=$(get_key_id_is_exportable_yn "$key_id") || return $?
  if [ "$is_key_id_exportable" = "y" ]; then
    local name=$key_id-asymmetric-key.yhk
    local out=$unique_key_out_dir/$name
    mkdir -p "$unique_key_out_dir" || return $?
    yubihsm -a get-wrapped \
      --wrap-id "$YUBIHSM_WRAP_KEY_ID" \
      --object-id "$key_id" \
      --object-type asymmetric-key \
      --out "$out" \
      || return $?
    copy_exported_file_to_other_dirs "$out" || return $?
  fi
}

generate_cert() {
  local key_id=$1
  local key_label=$2  # unused
  local key_type=$3
  local key_name=$4
  local domain
  local capabilities
  domain=$(_get_domains_for_key_id "$key_id") || return $?
  capabilities=$(_get_capabilities_for_key_id "$key_id" "$YUBIHSM_OPAQUE_CAPABILITIES") || return $?

  # Save an attestation certificate proving the key was generated on device.
  # We must do this now, and keep it forever, because it is possible that the
  # key might be exported and imported under wrap later, if it is exportable.
  local attestation_cert=$unique_key_out_dir/$key_id.attestation.pem
  mkdir -p "$unique_key_out_dir" || return $?
  yubihsm -a sign-attestation-certificate \
    --object-id "$key_id" \
    --attestation-id 0 \
    --out "$attestation_cert" \
    || return $?
  copy_exported_file_to_other_dirs "$attestation_cert" || return $?

  # Currently, we use the key attestation certificate as the key cert directly.
  local key_cert=$unique_key_out_dir/$key_id.x509.pem
  cp -p "$attestation_cert" "$key_cert" || return $?
  copy_exported_file_to_other_dirs "$key_cert" || return $?

  # Import the cert.
  yubihsm -a put-opaque \
    --object-id "$key_id" \
    -A opaque-x509-certificate \
    --informat=PEM \
    --domain "$domain" \
    --capabilities "$capabilities" \
    --in "$key_cert" \
    || return $?

  # Extract the public key. (Purely for convenience. Can happen any time with
  # the x509 cert we already saved; no private key access required.)
  case "$key_type" in
    avb|apex_payload|apex_container)
      local public_key=$unique_key_out_dir/$key_id.pem
      if [ -e "$public_key" ]; then
        echo "Public key file already exists: $public_key" >&2
      else
        # Output public key and avbpubkey for APEX payload or AVB keys.
        # Also do this for core keys, since APEX might use them.
        "$OPENSSL_BIN" x509 -pubkey -noout -in "$key_cert" \
          -out "$public_key" \
          || return $?
        copy_exported_file_to_other_dirs "$public_key" || return $?
      fi

      # TODO: The AVB public key can be extracted any time. It does not require
      #       private key access, so we don't really need it in this keygen,
      #       as long as it happens later / dynamically. Think about it, as
      #       it could allow removal of the avbtool dependency for provisioning.
      local avb_public_key=$unique_key_out_dir/$key_id.avbpubkey
      if [ -e "$avb_public_key" ]; then
        echo "avbpubkey file already exists: $avb_public_key" >&2
      else
        "$AVBTOOL_BIN" extract_public_key \
          --key "$public_key" \
          --output "$avb_public_key" \
          || return $?
        copy_exported_file_to_other_dirs "$avb_public_key" || return $?
      fi
      ;;
  esac

  # Generating the cert happens after the keypair, so this is our chance to limit the
  # on-demand key object.
  limit_ondemand_objects || return $?

  # And we can go ahead and extract logs, too.
  # Or actually, no need, since now we do that as part of yubihsm.
  #extract_logs "" "KEYGEN" || return $?
}

ensure_key_not_exist() {
  ensure_key_not_exist_pkcs11 "$@" || return $?

  # Ensure it does not exist wrapped on disk, in which case we don't want to regenerate it.
  local key_id=$1
  local key_file=$key_out_dir/$key_id-asymmetric-key.yhk
  if [ -e "$key_file" ]; then
    return 1
  fi
}

extract_attestation_key() {
  local out=$unique_key_out_dir/YubiHSM_attestation.pem
  mkdir -p "$unique_key_out_dir" || return $?
  yubihsm -a get-opaque --object-id 0x0000 --outformat PEM \
    --out "$out" || return $?
  copy_exported_file_to_other_dirs "$out" || return $?
}

copy_exported_file_to_other_dirs() {
  # Copy the exported file to the HSM-unique keys directory, and also to the main keys
  # directory, provided the file doesn't already exist there. The goal of this whole
  # structure is to prevent loss of keys while also ensuring that keys for a particular
  # device or created during a particular session are consistently available, never lost
  # or clobbered.
  local source=$1
  local rel_source
  rel_source=$(realpath --relative-to="$unique_key_out_dir" "$source") || return $?
  mkdir -p "$(dirname "$hsm_key_out_dir/$rel_source")" || return $?
  mkdir -p "$(dirname "$key_out_dir/$rel_source")" || return $?
  cp "$source" "$hsm_key_out_dir/$rel_source" || return $?
  cp --no-clobber "$source" "$key_out_dir/$rel_source" || return $?
}

save_yubihsm_deviceinfo() {
  # Save the deviceinfo for the HSM so that its association with the folders' keys is clear.
  local out=$unique_key_out_dir/hsm_info.txt
  printf "%s\n" "$yubihsm_deviceinfo" > "$out" || return $?
  copy_exported_file_to_other_dirs "$out" || return $?
}

cleanup() {
  if [ -n "${TEMP_DIR:-}" ]; then
    if [ "${CLEANUP_ON_EXIT:-y}" = "n" ]; then
      echo "Temp files retained at $TEMP_DIR." >&2
    else
      if [ -z "${CLEANUP_ON_EXIT:-}" ]; then
        echo >&2
        echo "Note: You can retain temp files and imported keys/certs for inspection by setting CLEANUP_ON_EXIT=n" >&2
        echo >&2
      fi
      rm -rf "$TEMP_DIR"
    fi
  fi
}

keygen_main "$@" || exit $?
