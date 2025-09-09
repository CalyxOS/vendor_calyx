#!/bin/bash
set -euo pipefail
ourpath=$(cd "$(dirname "$0")";pwd -P)
PROVISIONING_PATH=${PROVISIONING_PATH:-/dev/shm/hsmp}
KEEP_PATH=${KEEP_PATH:-$PROVISIONING_PATH/keep}
our_desired_path=$PROVISIONING_PATH/$(basename "$0")
YUBIHSM_CONNECTOR=${YUBIHSM_CONNECTOR:-http://127.0.0.1:12345}
YUBIHSM_AUTHKEY=${YUBIHSM_AUTHKEY:-1}
YUBIHSM_PASSWORD=${YUBIHSM_PASSWORD:-password}
YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE=${YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE:-0100030004000500060007000900080040004100420243004402450246024702550256024800490057004a024b024c024d0067004e004f0250005102520253025400580259005a025b025c005d005e025f006000610062026302640265026602680269026a026b006c020a006d026e026f0070007100720073027402750276027702}
YUBIHSM_SIGNING_AUTHKEY_ID=${YUBIHSM_SIGNING_AUTHKEY_ID:-0x0001}
YUBIHSM_SIGNING_AUTHKEY_DOMAINS=${YUBIHSM_SIGNING_AUTHKEY_DOMAINS:-all}
# Authkey capabilities are based on yubihsm-setup, with some changes for our use cases.
YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,import-wrapped,export-wrapped,exportable-under-wrap,get-option,sign-attestation-certificate,get-log-entries,change-authentication-key,decrypt-pkcs,decrypt-oaep,put-opaque,get-opaque}
YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES:-generate-asymmetric-key,sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa,derive-ecdh,exportable-under-wrap,get-option,decrypt-pkcs,decrypt-oaep}
YUBIHSM_AUDIT_AUTHKEY_ID=${YUBIHSM_AUDIT_AUTHKEY_ID:-0x0002}
YUBIHSM_AUDIT_AUTHKEY_DOMAINS=${YUBIHSM_AUDIT_AUTHKEY_DOMAINS:-all}
YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES:-get-log-entries,exportable-under-wrap,get-option}
YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES=${YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES:-none}
YUBIHSM_WRAP_KEY_ID=${YUBIHSM_WRAP_KEY_ID:-0x0010}

# Fake... We don't truly get to control these wrap key details; yubihsm-setup controls it all,
# and there is no customization...
YUBIHSM_WRAP_KEY_DOMAINS=${YUBIHSM_WRAP_KEY_DOMAINS:-all}
YUBIHSM_WRAP_KEY_CAPABILITIES=${YUBIHSM_WRAP_KEY_CAPABILITIES:-export-wrapped,import-wrapped}
YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES=${YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES:-decrypt-oaep,decrypt-pkcs,derive-ecdh,export-wrapped,exportable-under-wrap,generate-asymmetric-key,get-log-entries,get-option,import-wrapped,sign-ecdsa,sign-eddsa,sign-pkcs,sign-pss,sign-attestation-certificate,change-authentication-key}

YUBIHSM_TEMPORARY_AUTHKEY_ID=${YUBIHSM_TEMPORARY_AUTHKEY_ID:-0x00ff}
stage_file=$PROVISIONING_PATH/stage.txt
otatools_path=$PROVISIONING_PATH/otatools-keys
script_path=$otatools_path/vendor/calyx/scripts
pkcs11_path=$script_path/pkcs11
SHELL=${SHELL:-bash}

installed=
stage=
next_stage=

install_script_start=(
  copy_and_extract_tools
  relaunch_script_from_memory_if_needed
  remove_media
  source_include_scripts
  install_tools
  start_yubihsm_connector
)
install_script_primary_provisioning=(
  connect_hsm_primary
  reset_hsm_primary
  provision_auditing_primary
  provision_wrap_key_primary
  ask_authkey_passwords_if_needed
  add_temporary_authentication_key_primary
  delete_default_authentication_key_primary
  provision_authentication_primary
  delete_temporary_authentication_key_primary
  prepare_custom_metadata_for_keygen_primary
  keygen_primary
  backup_primary
  extract_logs_primary
)
install_script_secondary_provisioning=(
  connect_hsm_secondary
  reset_hsm_secondary
  provision_auditing_secondary
  restore_secondary
  add_temporary_authentication_key_secondary
  delete_default_authentication_key_secondary
  provision_authentication_secondary
  delete_temporary_authentication_key_secondary
  prepare_custom_metadata_for_keygen_secondary
  keygen_secondary
  extract_logs_secondary
)
install_script_end=(
  finish
)

main() {
  trap cleanup EXIT

  try prepare || return $?

  if [ -z "${RELAUNCHED_SCRIPT:-}" ] && [ -n "$stage" ]; then
    echo "Detected provisioning still in progress."
    if ! confirm "Do you want to continue where you left off?"; then
      stage=
    fi
  fi

  if [ "${1:-}" = "restore" ]; then
    echo "Provisioning mode: Restore."
    declare -g install_script=(
      "${install_script_start[@]}"
      "${install_script_secondary_provisioning[@]}"
      "${install_script_end[@]}"
    )
  elif [ "${1:-}" = "primary" ]; then
    echo "Provisioning mode: Primary only."
    declare -g install_script=(
      "${install_script_start[@]}"
      "${install_script_primary_provisioning[@]}"
      "${install_script_end[@]}"
    )
  elif [ "${1:-}" = "limited-keygen" ]; then
    echo "Provisioning mode: Limited keygen."
    declare -g install_script=(
      "${install_script_start[@]}"
      prepare_custom_metadata_for_keygen_primary
      ask_signing_authkey_password_if_needed
      keygen_primary
      backup_primary
      "${install_script_end[@]}"
    )
  elif [ "${1:-}" = "keygen" ]; then
    echo "Provisioning mode: Keygen."
    declare -g install_script=(
      "${install_script_start[@]}"
      ask_signing_authkey_password_if_needed
      keygen_primary
      backup_primary
      "${install_script_end[@]}"
    )
  elif [ "{1:-}" = "full" ] || [ -z "${1:-}" ]; then
    echo "Provisioning mode: Full. (Limited keygen.)"
    declare -g install_script=(
      "${install_script_start[@]}"
      "${install_script_primary_provisioning[@]}"
      "${install_script_secondary_provisioning[@]}"
      "${install_script_end[@]}"
    )
  elif [ "${1:-}" = "keygen_old" ]; then
    if [ -n "$stage" ]; then
      echo "You just wanted keygen, so we're not continuing where your provisioning left off."
    fi
    local err=0
    mkdir -p -m0700 "$KEEP_PATH" || return $?
    mkdir -p -m0700 "$KEEP_PATH/keys" || return $?
    if [ -z "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
      printf "Enter signing authkey password: "
      read -r -s YUBIHSM_SIGNING_AUTHKEY_PASSWORD || return $?
      echo
      export YUBIHSM_AUTHKEY
      export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    fi
    "$pkcs11_path/vendor.yubihsm.keygen.sh" "$KEEP_PATH/keys" || err=$?
    return $err
  elif [ "${1:-}" = "backup" ]; then
    declare -g install_script=(
    )
  elif [ -n "${1:-}" ]; then
    echo "Unrecognized provisioning mode: $1" >&2
    return 1
  fi

  set -- "${install_script[@]}"
  local skip_until=$stage
  local last_connect_hsm_step=
  while [ $# -gt 0 ]; do
    local script_stage=$1
    if [ -n "$skip_until" ] && [ "$script_stage" != "$skip_until" ]; then
      case "$1" in
        relaunch_script_from_memory_if_needed|source_include_scripts\
        |ask_*_if_needed|prepare_custom_metadata_for_keygen*)
          # Always do these things, even if we are resuming from partially-completed provisioning.
          stage=$script_stage try "$script_stage" || return $? ;;
        connect_hsm*)
          # Make sure we always repeat whichever the last check_hsm step was.
          # This ensures the user knows to connect the expected HSM.
          last_connect_hsm_step=$script_stage ;;
        install_tools)
          installed=y ;;
        source_include_scripts)
          stage=$script_stage try "$script_stage" || return $? ;;
      esac
      shift 1
      continue
    fi
    skip_until=
    next_stage=${2:-}  # The stage *after* this one.

    if [ -n "$last_connect_hsm_step" ]; then
      # Tell the user to connect the expected HSM.
      stage=$last_connect_hsm_step try "$last_connect_hsm_step" || return $?
      last_connect_hsm_step=
    fi

    set_stage "$script_stage" || return $?
    try "$script_stage" || return $?
    shift 1
  done
}

copy_and_extract_tools() {
  mkdir -p -m0700 "$PROVISIONING_PATH/packages" || return $?
  if [ "$(realpath -e "$0")" = "$(realpath -e "$our_desired_path" 2>/dev/null)" ]; then
    echo "Skipping copying and extracting tools since we are running from memory already." >&2
    return 0
  fi
  cp -u "$(dirname "$0")/packages/"*.deb "$PROVISIONING_PATH/packages/" || return $?

  local file
  for file in "$(dirname "$0")"/yubihsm2-sdk-*.tar.gz; do
    if [ ! -e "$file" ]; then
      echo "Could not find YubiHSM SDK in current directory." >&2
      return 1
    fi
    tar -xf "$file" -C "$PROVISIONING_PATH/packages" || return $?
    # Don't want or need the development package.
    rm -f "$PROVISIONING_PATH/packages/yubihsm2-sdk/"libyubihsm-dev*.deb || true
    break
  done

  file=$(dirname "$0")/otatools-keys.zip
  extract_zip "$file" "$otatools_path" || return $?
}

relaunch_script_from_memory_if_needed() {
  if [ "$(realpath -e "$0")" = "$(realpath -e "$our_desired_path" 2>/dev/null)" ]; then
    return 0
  fi
  cp -u "$0" "$our_desired_path" || return $?
  chmod +x "$our_desired_path" || return $?
  if [ -n "$next_stage" ]; then
    set_stage "$next_stage" no-announce
  fi
  trap "" EXIT
  RELAUNCHED_SCRIPT=y exec "$SHELL" "$our_desired_path"
}

remove_media() {
  echo "Everything required has now been installed or copied to memory at $PROVISIONING_PATH."
  echo "You may now remove the media containing these provisioning files."
  pause
}

source_include_scripts() {
  source "$pkcs11_path/vendor.yubihsm.include.sh" || return $?
}

install_tools() {
  echo "This step uses administrator privileges via sudo to install the packages required to provision YubiHSM 2."
  echo "You may be required to enter your administrator password."
  confirm "Would you like to continue?" || return $?

  sudo dpkg -i "$PROVISIONING_PATH/packages/"*.deb "$PROVISIONING_PATH/packages/yubihsm2-sdk/"*.deb || return $?

  installed=y
}

start_yubihsm_connector() {
  echo "This step uses administrator privileges via sudo to start the YubiHSM connector."
  echo "You may be required to enter your administrator password."
  pause || return $?
  sudo systemctl start yubihsm-connector || return $?
}

connect_hsm_primary() {
  echo "Please connect the primary YubiHSM 2."
  confirm "Enter Y when the primary YubiHSM 2 is connected, or N to quit." || return $?
}

reset_hsm_primary() {
  reset_hsm "$@" || return $?
}

provision_auditing_primary() {
  provision_auditing "$@" || return $?
}

provision_wrap_key_primary() {
  local output
  output=$(yubihsm -a list-objects -t wrap-key -i "$YUBIHSM_WRAP_KEY_ID") || return $?
  if printf "%s\n" "$output" | grep -q "^Found 0 "; then
    true  # No wrap key found. Proceed.
  elif printf "%s\n" "$output" | grep -q "^Found 1 "; then
    echo "Found an existing wrap key."
    confirm "Would you like to continue anyway?" || return $?
  else
    echo "Unexpected output when listing YubiHSM objects." >&2
    return 1
  fi
  echo
  echo "You are about to enter the yubihsm-setup wizard."
  echo "When prompted, please answer as follows (note the wrap key will be re-imported as $YUBIHSM_WRAP_KEY_ID):"
  echo "  Would you like to add RSA decryption capabilities? (y/n) y"
  echo "  Enter domains: all"
  echo "  You have selected more than one domain, are you sure? (y/n) y"
  echo "  Enter wrap key ID (0 to choose automatically): $YUBIHSM_WRAP_KEY_ID"
  echo "  Enter the number of shares: [TODO: prearranged. let's say 5]"
  echo "  Enter the privacy threshold: [TODO: prearranged. let's say 3]"
  # TODO: Prearranged mechanism is... what?
  echo "Then, prepare to record shares using the prearranged mechanism."
  echo "More questions (note that the authentication key created here will be discarded):"
  echo "  Enter application authentication key ID (0 to choose automatically): 0x0002"
  echo "  Enter application authentication key password: password"
  echo "  Would you like to create an audit key? (y/n) n"
  # TODO: Do this for them, and open with xdg-open?
  echo "You may wish to copy this information to a text file in case it scrolls off the screen."
  echo
  confirm "Are you ready to continue?" || return $?

  # Call yubihsm-setup to create the wrap key, and all the other stuff it unfortunately does
  # which we will subsequently undo.
  yhsetup --no-delete --no-export ksp || return $?

  # Undo the things we don't want.
  echo "Deleting application authentication key 0x0002..."
  yubihsm -a delete-object --object-id 0x0002 --object-type authentication-key || return $?
}

_unused_provision_wrap_key_primary_ejbca() {
  local output
  output=$(yubihsm -a list-objects -t wrap-key -i "$YUBIHSM_WRAP_KEY_ID") || return $?
  if printf "%s\n" "$output" | grep -q "^Found 0 "; then
    true  # No wrap key found. Proceed.
  elif printf "%s\n" "$output" | grep -q "^Found 1 "; then
    echo "Found an existing wrap key."
    confirm "Would you like to continue anyway?" || return $?
  else
    echo "Unexpected output when listing YubiHSM objects." >&2
    return 1
  fi
  echo
  echo "You are about to enter the yubihsm-setup wizard."
  echo "When prompted, please answer as follows (note the wrap key will be re-imported as $YUBIHSM_WRAP_KEY_ID):"
  echo "  Enter domains: all"
  echo "  You have selected more than one domain, are you sure? (y/n) y"
  echo "  Enter wrap key ID (0 to choose automatically): $YUBIHSM_TEMPORARY_WRAP_KEY_ID"
  echo "  Enter the number of shares: [TODO: prearranged. let's say 5]"
  echo "  Enter the privacy threshold: [TODO: prearranged. let's say 3]"
  # TODO: Prearranged mechanism is... what?
  echo "Then, prepare to record shares using the prearranged mechanism."
  echo "More questions (note that the authentication key created here will be discarded):"
  echo "  Enter application authentication key ID (0 to choose automatically): 0x0002"
  echo "  Enter application authentication key password: password"
  echo "  Would you like to create an audit key? (y/n) n"
  echo "  Enter asymmetric key algorithm: ecp224"
  echo "  Enter key label: delete"
  echo "  Enter domains: 1"
  # TODO: Do this for them, and open with xdg-open?
  echo "You may wish to copy this information to a text file in case it scrolls off the screen."
  echo
  confirm "Are you ready to continue?" || return $?

  # Call yubihsm-setup to create the wrap key, and all the other stuff it unfortunately does
  # which we will subsequently undo.
  yhsetup --no-delete --no-export ejbca || return $?

  # Undo the things we don't want.
  echo "Deleting application authentication key 0x0002..."
  yubihsm -a delete-object --object-id 0x0002 --object-type authentication-key || return $?

  echo "Deleting unnecessary asymmetric key..."
  local object_id
  object_id=$(yubihsm -a list-objects --label delete --object-type asymmetric-key | sed -ne 's/^id: \([^,]\+\),.*$/\1/p') || return $?
  if [ -z "$object_id" ]; then
    echo "Could not find ID for 'delete' object." >&2
    echo "Did you enter the label properly when asked?" >&2
    if ! confirm "Would you like to delete all asymmetric keys and certs found instead (recommended)?"; then
      return 1
    fi
    delete_all_asymmetric_keys_and_opaque_objects || return $?
  else
    yubihsm -a delete-object --object-id "$object_id" --object-type asymmetric-key || return $?
    yubihsm -a delete-object --object-id "$object_id" --object-type opaque || return $?
  fi
  return 0

  echo "Exporting wrap key itself to re-import it with proper capabilities..."
  rm -f "$PROVISIONING_PATH/wrap-key.yhk" || return $?
  yubihsm -a get-wrapped \
    --wrap-id "$YUBIHSM_TEMPORARY_WRAP_KEY_ID" \
    --object-id "$YUBIHSM_TEMPORARY_WRAP_KEY_ID" \
    --object-type wrap-key \
    --out "$PROVISIONING_PATH/wrap-key.yhk" || return $?
  echo "Re-importing wrap key as $YUBIHSM_WRAP_KEY_ID..."
  yubihsm -a put-wrapped \
    --wrap-id "$YUBIHSM_TEMPORARY_WRAP_KEY_ID" \
    --object-id "$YUBIHSM_WRAP_KEY_ID" \
    --object-type wrap-key \
    --domain "$YUBIHSM_WRAP_KEY_DOMAINS" \
    --capabilities "$YUBIHSM_WRAP_KEY_CAPABILITIES" \
    --delegated "$YUBIHSM_WRAP_KEY_DELEGATED_CAPABILITIES" \
    --in "$PROVISIONING_PATH/wrap-key.yhk" || return $?
  rm -f "$PROVISIONING_PATH/wrap-key.yhk" || return $?
}

ask_signing_authkey_password_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    return 0
  fi
  read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" n || return $?
}

ask_authkey_passwords_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ] && \
     [ -n "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ]; then
     return 0
  fi
  echo "Your HSM will have different authentication keys: one for signing, and one for auditing."
  echo "Each key will have its own password. Please choose these passwords now."
  if [ -z "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" || return $?
  fi
  if [ -z "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_AUDIT_AUTHKEY_PASSWORD "audit authkey password" || return $?
  fi
}

add_temporary_authentication_key_primary() {
  # Create a temporary full-access authentication key so that the default one can be removed.
  yubihsm -a put-authentication-key --object-id "$YUBIHSM_TEMPORARY_AUTHKEY_ID" \
    --new-password password --domains all --capabilities all --delegated all || return $?
}

delete_default_authentication_key_primary() {
  # Delete the original, default authentication key using the temporary authentication key.
  YUBIHSM_AUTHKEY=$YUBIHSM_TEMPORARY_AUTHKEY_ID YUBIHSM_PASSWORD=password yubihsm \
    -a delete-object --object-id 0x0001 --object-type authentication-key || return $?
}

provision_authentication_primary() {
  # WARNING: Password is on the command line.
  # --new-password does not support the "file:" construction that --password does.
  # This entire script is expected to be run in an ephemeral, trusted environment.

  # Create the authentication key to be used for signing.
  YUBIHSM_AUTHKEY=$YUBIHSM_TEMPORARY_AUTHKEY_ID YUBIHSM_PASSWORD=password yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_SIGNING_AUTHKEY_ID" \
    --domains "$YUBIHSM_SIGNING_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_SIGNING_AUTHKEY_PASSWORD" || return $?

  # Create the authentication key to be used for auditing.
  YUBIHSM_AUTHKEY=$YUBIHSM_TEMPORARY_AUTHKEY_ID YUBIHSM_PASSWORD=password yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_AUDIT_AUTHKEY_ID" \
    --domains "$YUBIHSM_AUDIT_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_AUDIT_AUTHKEY_PASSWORD" || return $?

  # change-authentication-key, create-otp-aead, decrypt-oaep, decrypt-otp, decrypt-pkcs, delete-asymmetric-key, delete-authentication-key, delete-hmac-key, delete-opaque, delete-otp-aead-key, delete-template, delete-wrap-key, derive-ecdh, export-wrapped, exportable-under-wrap, generate-asymmetric-key, generate-hmac-key, generate-otp-aead-key, generate-wrap-key, get-log-entries, get-opaque, get-option, get-pseudo-random, get-template, import-wrapped, put-asymmetric-key, put-authentication-key, put-mac-key, put-opaque, put-otp-aead-key, put-template, put-wrap-key, randomize-otp-aead, reset-device, rewrap-from-otp-aead-key, rewrap-to-otp-aead-key, set-option, sign-attestation-certificate, sign-ecdsa, sign-eddsa, sign-hmac, sign-pkcs, sign-pss, sign-ssh-certificate, unwrap-data, verify-hmac, wrap-data
}

delete_temporary_authentication_key_primary() {
  # Use the temporary authentication key to delete itself.
  YUBIHSM_AUTHKEY=$YUBIHSM_TEMPORARY_AUTHKEY_ID YUBIHSM_PASSWORD=password yubihsm \
    -a delete-object --object-id "$YUBIHSM_TEMPORARY_AUTHKEY_ID" \
    --object-type authentication-key || return $?
}

prepare_custom_metadata_for_keygen_primary() {
  if [ -z "${METADATA_FILE:-}" ]; then
    echo "Preparing metadata for generating just a few keys..."
    export METADATA_FILE=$PROVISIONING_PATH/limited_keygen_metadata
    (
      source "$script_path/metadata" || return $?
      printf 'keys_avb_partitions=(%q)\n' "${keys_avb_partitions[0]}"
      printf 'keys_core=(%q %q)\n' "${keys_core[0]}" "${keys_core[1]}"
      echo 'keys_apex=()'
      echo 'keys_apex_apk=()'
      echo "keys_app=(${keys_apps[*]@Q})"
      echo "all_devices=(${all_devices[*]@Q})"
    ) > "$METADATA_FILE" || return $?
  fi
  if [ -z "${DEVICES_FILE:-}" ]; then
    echo "Preparing devices list for generating just a few keys..."
    export DEVICES_FILE=$PROVISIONING_PATH/limited_keygen_devices
    (
      source "$otatools_path/calyx/scripts/vars/devices" || return $?
      echo "readonly -a devices=(${devices[0]})"
    ) > "$DEVICES_FILE" || return $?
  fi
}

keygen_primary() {
  (
    export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
    export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    mkdir -p -m0700 "$KEEP_PATH" || return $?
    mkdir -p -m0700 "$KEEP_PATH/keys" || return $?
    cd "$otatools_path" && "$pkcs11_path/vendor.yubihsm.keygen.sh" "$KEEP_PATH/keys" || return $?
  ) || return $?
}

backup_primary() {
  mkdir -p -m0700 "$KEEP_PATH/keys"
  echo
  echo "You are about to enter yubihsm-setup to export objects."
  echo "When prompted, please answer as follows:"
  echo "  Enter the wrapping key ID to use for exporting objects: 0x0010"
  echo
  echo "This process will fail to export the wrap-key (expected) and the 0x0001 (signing) authkey."
  echo "It will, however, successfully export the 0x0002 (audit) authkey. This is useful to verify"
  echo "that a key restore actually works. (The signing key will be re-created on the secondary HSM.)"
  echo
  echo "This will also delete any existing exported audit key."
  echo
  confirm "Are you ready to continue?" || return $?

  # Delete existing audit key, if any.
  rm -f "$KEEP_PATH/keys/0x0002-authentication-key.yhw"

  # Dump objects.
  (cd "$KEEP_PATH/keys" && YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD yhsetup dump) \
    || return $?

  # Our signing authentication key cannot be exported because the wrap key generated by
  # yubihsm-setup is missing the sign-attestation-certificate delegated capability, and we
  # need it in order to attest any keys generated on the HSM.
  #if [ ! -e "$KEEP_PATH/keys/0x0001-authentication-key.yhw" ]; then
  #  echo "Exported signing authentication key not found! Did it fail to export?" >&2
  #  return 1
  #fi
  if [ ! -e "$KEEP_PATH/keys/0x0002-authentication-key.yhw" ]; then
    echo "Exported audit authentication key not found! Did it fail to export?" >&2
    return 1
  fi
}

extract_logs_primary() {
  extract_logs_common primary || return $?
}

connect_hsm_secondary() {
  echo "Please connect the secondary YubiHSM 2."
  confirm "Enter Y when the secondary YubiHSM 2 is connected, or N to quit." || return $?
}

reset_hsm_secondary() {
  reset_hsm "$@" || return $?
}

provision_auditing_secondary() {
  provision_auditing "$@" || return $?
}

add_temporary_authentication_key_secondary() {
  # They do the same thing.
  add_temporary_authentication_key_primary "$@" || return $?
}

delete_default_authentication_key_secondary() {
  # They do the same thing.
  delete_default_authentication_key_primary "$@" || return $?
}

provision_authentication_secondary() {
  # WARNING: Password is on the command line.
  # --new-password does not support the "file:" construction that --password does.
  # This entire script is expected to be run in an ephemeral, trusted environment.

  # NOTE: If yubihsm-setup ever includes enough capabilities for the wrap key, or allows us
  # to include custom ones, then we don't need to re-create the auth key on secondary like this,
  # and can simply restore it, too.

  # Create the authentication key to be used for signing.
  YUBIHSM_AUTHKEY=$YUBIHSM_TEMPORARY_AUTHKEY_ID YUBIHSM_PASSWORD=password yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_SIGNING_AUTHKEY_ID" \
    --domains "$YUBIHSM_SIGNING_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_SIGNING_AUTHKEY_PASSWORD" || return $?
}

restore_secondary() {
  echo
  echo "You are about to enter the yubihsm-setup wizard to restore your wrap key."
  echo "When prompted, please answer as follows:"
  echo "  Enter the number of shares: [TODO: prearranged. let's say 5]"
  echo "Then, enter all of the shares recorded previously."
  echo
  echo "This process should also successfully restore your audit key from backup,"
  echo "which serves as a confirmation that the restored wrap key is valid."
  echo
  confirm "Are you ready to continue?" || return $?
  (cd "$KEEP_PATH/keys" && yhsetup --no-delete --no-export restore) \
    || return $?
  local object_id
  object_id=$(yubihsm -a list-objects --object-id "$YUBIHSM_AUDIT_AUTHKEY_ID" \
    --object-type authentication-key | sed -ne 's/^id: \([^,]\+\),.*$/\1/p') || return $?
  if [ -z "$object_id" ]; then
    echo "Audit authkey not found on the HSM! Did it fail to restore?" >&2
    echo "It is possible that one or more of the shares you entered were incorrect." >&2
    return 1
  fi
  echo "Successfully restored the wrap key and audit key."
}

delete_temporary_authentication_key_secondary() {
  # They do the same thing.
  delete_temporary_authentication_key_primary "$@" || return $?
}

prepare_custom_metadata_for_keygen_secondary() {
  # They do the same thing.
  prepare_custom_metadata_for_keygen_primary "$@" || return $?
}

keygen_secondary() {
  # They do the same thing.
  keygen_primary "$@" || return $?
}

extract_logs_secondary() {
  extract_logs_common secondary || return $?
}

finish() {
  echo "Provisioning completed successfully!"
  echo "Do not forget to save the contents of:"
  printf "%s\n" "$KEEP_PATH"
  rm -f "$stage_file"
}

reset_hsm() {
  yubihsm -a list-objects
  echo
  echo "This provisioning script expects that the provided HSM is in a clean state."
  if ! confirm "Would you like to reset this HSM? This operation cannot be undone!"; then
    return 0
  fi
  local err=
  yubihsm -a reset || err=$?
  if [ -n "$err" ]; then
    echo "Could not reset the HSM. You may need to reset it manually by removing and" >&2
    echo "re-inserting it, pressing on the metal rim for at least 10 seconds." >&2
    return 1
  fi
  # Give a moment for the HSM to reappear.
  sleep 1
}

provision_auditing() {
  # Much of this was gleaned from https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e
  local command_audit_value
  command_audit_value=$(yubihsm -a get-option --opt-name command-audit | sed -e 's/^Option value is: //') || return $?
  if [ "$command_audit_value" = "$YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE" ]; then
    echo "Command audit value is already as expected."
    return 0
  fi
  yubihsm -a put-option --opt-name command-audit --opt-value 4f01 || return $? # log PUT OPTION
  yubihsm -a put-option --opt-name command-audit --opt-value 4f02 || return $? # log PUT OPTION until factory reset
  yubihsm -a put-option --opt-name force-audit --opt-value 02 || return $? # prevent operations when audit log is full
  local -a auditable_commands=(
    # from: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html
    # command Tc values
    6c # CHANGE AUTHENTICATION KEY
    58 # DELETE OBJECT
    4a # EXPORT WRAPPED
    76 # EXPORT RSA WRAPPED
    74 # EXPORT RSA WRAPPED KEY
    46 # GENERATE ASYMMETRIC KEY
    5a # GENERATE HMAC KEY
    66 # GENERATE OTP AEAD KEY
    6e # GENERATE SYMMETRIC KEY
    5b # GENERATE WRAP KEY
    51 # GET PSEUDO RANDOM
    4b # IMPORT WRAPPED
    77 # IMPORT RSA WRAPPED
    75 # IMPORT RSA WRAPPED KEY
    45 # PUT ASYMMETRIC KEY
    44 # PUT AUTHENTICATION KEY / PUT ASYMMETRIC AUTHENTICATION KEY
    52 # PUT HMAC KEY
    42 # PUT OPAQUE
    65 # PUT OTP AEAD KEY
    73 # PUT PUBLIC WRAP KEY
    6d # PUT SYMMETRIC KEY
    5e # PUT TEMPLATE
    4c # PUT WRAP KEY
    62 # RANDOMIZE OTP AEAD
    63 # REWRAP OTP AEAD
    # 4f # SET OPTION (PUT OPTION) - already set earlier
    64 # SIGN ATTESTATION CERTIFICATE
    56 # SIGN ECDSA
    6a # SIGN EDDSA
    53 # SIGN HMAC
    47 # SIGN RSA PKCS1
    55 # SIGN RSA PSS
    69 # UNWRAP DATA
    68 # WRAP DATA
  )
  local cmd
  for cmd in "${auditable_commands[@]}"; do
    yubihsm -a put-option --opt-name command-audit --opt-value "${cmd}02" || return $? # force audit of given command until factory reset
  done
  command_audit_value=$(yubihsm -a get-option --opt-name command-audit | sed -e 's/^Option value is: //') || return $?
  if [ "$command_audit_value" != "$YUBIHSM_EXPECTED_COMMAND_AUDIT_VALUE" ]; then
    # TODO: Maybe allow this enforcement to be skipped? But maybe not.
    echo "Command audit value is not as expected after provisioning!" >&2
    return 1
  fi
  echo "Successfully provisioned auditing options."

  # TODO: Check this automatically?
  #yubihsm -a get-logs   # witness that there are many 4f entries now, since PUT OPTION is logged
}

extract_logs_common() {
  mkdir -p -m0700 "$KEEP_PATH"
  mkdir -p -m0700 "$KEEP_PATH/logs"
  export AUDIT_LOG_PATH=$KEEP_PATH/logs/provision-$1.log
  export AUDIT_LOG_PATH_HEX=${AUDIT_LOG_PATH/.log/.hex.log}
  YUBIHSM_AUTHKEY=$YUBIHSM_AUDIT_AUTHKEY_ID \
  YUBIHSM_PASSWORD=$YUBIHSM_AUDIT_AUTHKEY_PASSWORD \
  PREPEND_LINE="PROVISION $1" \
  APPEND_LINE="---" \
  extract_logs || return $?
}

delete_all_asymmetric_keys_and_opaque_objects() {
  for object_id in $(yubihsm -a list-objects --object-type asymmetric-key | sed -ne 's/^id: \([^,]\+\),.*$/\1/p'); do
    yubihsm -a delete-object --object-id "$object_id" --object-type asymmetric-key || return $?
  done
  for object_id in $(yubihsm -a list-objects --object-type opaque | sed -ne 's/^id: \([^,]\+\),.*$/\1/p'); do
    yubihsm -a delete-object --object-id "$object_id" --object-type opaque || return $?
  done
}

# The vendor/calyx/scripts/pkcs11/vendor.yubihsm.include.sh script contains an implementation
# of this function, so when source_include_scripts is run, this function is overridden.
yubihsm() {
  yubihsm-shell --connector "$YUBIHSM_CONNECTOR" --authkey "$YUBIHSM_AUTHKEY" --password file:<(printf "%s" "$YUBIHSM_PASSWORD") "$@" || return $?
}

yhsetup() {
  # WARNING: Password is on the command line.
  # yubihsm-setup does not support the "file:" construction that yubihsm-shell does.
  # This entire script is expected to be run in an ephemeral, trusted environment.
  yubihsm-setup --connector "$YUBIHSM_CONNECTOR" --authkey "$YUBIHSM_AUTHKEY" --password "$YUBIHSM_PASSWORD" "$@" || return $?
}

set_stage() {
  if [ "$1" != "$stage" ]; then
    stage=$1
    case "$stage" in
      connect_hsm*|source_include_scripts)
        # Don't store these stages.
        true ;;
      *)
        printf "%s\n" "$1" > "$stage_file" || return $? ;;
    esac
  fi
  if [ "${2:-}" != "no-announce" ]; then
    echo "Now performing: $stage"
  fi
}

prepare() {
  if [ ! -d "$PROVISIONING_PATH" ]; then
    mkdir -m0700 -p "$PROVISIONING_PATH" || return $?
  else
    stage=$(cat "$stage_file" 2>/dev/null)
  fi
  if [ -n "${stage:-}" ]; then
    return 0
  fi
}

try() {
  local failed_again=
  while true; do
    local err=
    "$@" || err=$?
    if [ -n "$err" ]; then
      if ! confirm "$(printf "%s failed%s (code %s). Try again?" "$1" "$failed_again" "$err")"; then
        echo "$* failed (code $err). Giving up..." >&2
        return $err
      fi
    else
      return 0
    fi
  done
}

confirm() {
  while true; do
    printf "%s" "$1 (Y/N) "
    local response
    read -r response
    case "$response" in
      Y|y)
        break ;;
      N|n)
        return 1 ;;
      *)
        echo "Please enter Y or N." >&2
        continue ;;
    esac
  done
}

extract_zip() {
  local file=$1
  local outdir=$2
  if command -v 7z; then
    7z x "$file" -o"$outdir" || return $?
  elif command -v 7za; then
    7za x "$file" -o"$outdir" || return $?
  elif command -v unzip; then
    unzip "$file" -d "$outdir" || return $?
  fi
}

pause() {
  printf "%s " "${1:-Press Enter to continue...}"
  local response
  read -r response
}

read_password() {
  local variable=$1
  local prompt=$2
  local confirm=${3:-y}
  while true; do
    local try1
    local try2
    printf "Enter %s: " "$prompt"
    read -r -s try1
    echo
    if [ "$confirm" = "y" ]; then
      printf "Confirm %s: " "$prompt"
      read -r -s try2
      echo
      if [ -z "$try1" ] && [ -z "$try2" ]; then
        return 1
      fi
    else
      try2=$try1
    fi
    if [ "$try1" = "$try2" ]; then
      declare -g "$variable=$try1"
      return 0
    else
      echo "Passwords do not match." >&2
    fi
  done
}

cleanup() {
  if [ -d "$KEEP_PATH" ]; then
    echo "IMPORTANT: You must save the contents of '$KEEP_PATH'! Copy it somewhere safe!" >&2
  fi
  if [ "${RELAUNCHED_SCRIPT:-}" = "y" ] && \
     [ "$(realpath -e "$0")" = "$(realpath -e "$our_desired_path" 2>/dev/null)" ]; then
    echo "Remember to use this command if you want to launch the script again: " >&2
    printf "%q %q\n" "$SHELL" "$our_desired_path" >&2
  fi
}

main "$@"
