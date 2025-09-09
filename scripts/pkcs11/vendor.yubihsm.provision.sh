#!/bin/bash
set -euo pipefail
ourpath=$(cd "$(dirname "$0")";pwd -P)
PROVISIONING_PATH=${PROVISIONING_PATH:-/dev/shm/hsmp}
declare -g SOURCE_DIRECTORY
declare -g KEEP_PATH
YUBIHSM_CONNECTOR=${YUBIHSM_CONNECTOR:-http://127.0.0.1:12345}
YUBIHSM_AUTHKEY=${YUBIHSM_AUTHKEY:-1}
YUBIHSM_PASSWORD=${YUBIHSM_PASSWORD:-password}

stage_file=$PROVISIONING_PATH/stage.txt
mode_file=$PROVISIONING_PATH/mode.txt
script_relpath=vendor/calyx/scripts
pkcs11_relpath=$script_relpath/pkcs11
devices_relpath=calyx/scripts/vars/devices
our_desired_relpath=$pkcs11_relpath/$(basename "$0")
# our_desired_path is established in set_mode.

manifest_filename=vendor.yubihsm.provision.manifest.tsv
source_manifest_relpath=$pkcs11_relpath/$manifest_filename
shipped_manifest_relpath=$manifest_filename
declare -g manifest_path

SHELL=${SHELL:-bash}

script_args=()
# basepath is established in set_mode.
is_provisioning_mode=
provisioning_started=
asked_resume=
asked_reset=
installed=
mode=
stage=
next_stage=
no_recover=
no_exit_recommendations=

# These are updated in source_include_scripts too, just in case.
yubihsm_original_authkey=$YUBIHSM_AUTHKEY
yubihsm_original_password=$YUBIHSM_PASSWORD

# Stop sourced scripts from managing yubihsm-connector. We will do that ourselves.
export NEVER_START_YUBIHSM_CONNECTOR=y

wizard_script_start=(
  copy_files
  verify_copied_files
  extract_tools
  relaunch_script_from_memory_if_needed
  remove_media
  maybe_install_tools
  source_include_scripts
  maybe_start_yubihsm_connector_service
)
wizard_script_primary=(
  connect_hsm_primary
  maybe_reset_hsm_primary
  provision_auditing_primary
  provision_wrap_key_primary
  ask_authkey_passwords_if_needed
  provision_admin_authentication_primary
  use_admin_authkey_for_primary
  delete_default_authentication_key_primary
  provision_authentication_primary
  use_signing_authkey_for_primary
  create_custom_metadata_for_keygen_primary
  keygen_primary
  check_exports_primary
  log_end_primary
)
wizard_script_secondary=(
  ask_authkey_passwords_if_needed
  use_original_authkey_for_secondary
  connect_hsm_secondary
  maybe_reset_hsm_secondary
  provision_auditing_secondary
  restore_secondary
  provision_admin_authentication_secondary
  use_admin_authkey_for_secondary
  delete_default_authentication_key_secondary
  provision_authentication_secondary
  use_signing_authkey_for_secondary
  create_custom_metadata_for_keygen_secondary
  keygen_secondary
  log_end_secondary
)
wizard_script_end=(
  finish
)

main() {
  trap cleanup EXIT

  script_args=("$@")

  recover_previous_state || true

  set_mode "${1:-}" || exit $?

  set -- "${wizard_script[@]}"
  local skip_until=$stage
  local last_connect_hsm_stage=
  local last_authkey_stage=
  while [ $# -gt 0 ]; do
    local script_stage=$1
    if [ -n "$skip_until" ] && [ "$script_stage" != "$skip_until" ]; then
      case "$1" in
        relaunch_script_from_memory_if_needed|source_include_scripts\
        |ask_*_if_needed|create_custom_metadata_for_keygen*)
          # Always do these things, even if we are resuming from partially-completed provisioning.
          stage=$script_stage try "$script_stage" || return $? ;;
        connect_hsm*)
          # Make sure we always repeat whichever the last check_hsm step was.
          # This ensures the user knows to connect the expected HSM.
          last_connect_hsm_stage=$script_stage ;;
        use_*_authkey*)
          last_authkey_stage=$script_stage ;;
        maybe_install_tools)
          installed=y ;;
        source_include_scripts)
          stage=$script_stage try "$script_stage" || return $? ;;
      esac
      shift 1
      continue
    fi
    skip_until=
    next_stage=${2:-}  # The stage *after* this one.

    if [ -n "$last_authkey_stage" ]; then
      # Use the appropriate authkey password.
      stage=$last_authkey_stage try "$last_authkey_stage" || return $?
      last_authkey_stage=
    fi

    if [ -n "$last_connect_hsm_stage" ]; then
      # Tell the user to connect the expected HSM.
      stage=$last_connect_hsm_stage try "$last_connect_hsm_stage" || return $?
      last_connect_hsm_stage=
    fi

    set_stage "$script_stage" || return $?
    try "$script_stage" || return $?
    shift 1
  done
}

start_new_provisioning_or_handle_resume() {
  if [ "$asked_resume" = "y" ]; then return 0; fi
  asked_resume=y
  local new_mode=${1:-}
  initialize_provisioning_mode || return $?
  if [ -z "${RELAUNCHED_SCRIPT:-}" ] && [ -n "$stage" ]; then
    echo "Detected provisioning still in progress (mode $mode, stage $stage)."
    local msg
    if [ "$new_mode" != "$mode" ]; then
      echo "Your requested mode '$new_mode' is different from the previous mode '$mode'."
      msg="Do you want to use '$mode' instead and continue where you left off?"
    else
      msg="Do you want to continue where you left off?"
    fi
    if ! confirm "$msg"; then
      stage=
      mode=
      return 0
    fi

    # Start again using the mode read from the provisioning path.
    set_mode "$mode" || exit $?
    return 1
  fi
}

start_new_provisioning() {
  initialize_provisioning_mode || return $?
  stage=
  mode=
}

set_mode() {
  local new_mode=${1:-}
  if [ "$new_mode" = "restore" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      "${wizard_script_secondary[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "primary" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      "${wizard_script_primary[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "limited-keygen" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      ask_signing_authkey_password_if_needed
      use_signing_authkey_for_primary
      connect_hsm_primary
      create_custom_metadata_for_keygen_primary
      keygen_primary
      check_exports_primary
      log_end_primary
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "keygen" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      ask_signing_authkey_password_if_needed
      use_signing_authkey_for_primary
      connect_hsm
      keygen_primary
      check_exports_primary
      log_end
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "full" ] || [ -z "$new_mode" ]; then
    new_mode=full
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      "${wizard_script_primary[@]}"
      "${wizard_script_secondary[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "backup" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
      backup_primary
      check_exports_primary
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "load-keys" ]; then
    stage=
    declare -g wizard_script=(
      source_include_scripts
      ask_signing_authkey_password_if_needed
      use_signing_authkey_for_primary
      maybe_start_yubihsm_connector_service
      connect_hsm
      load_keys
      log_end
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "prepare-directory" ]; then
    stage=
    declare -g wizard_script=(
      prepare_directory
      verify_prepared_manifest_files
      "${wizard_script_end[@]}"
    )
  else
    echo "Unrecognized mode: $new_mode" >&2
    return 1
  fi

  if [ -z "${SOURCE_DIRECTORY:-}" ]; then
    # Update this if this script's relative path changes!
    SOURCE_DIRECTORY=${ourpath%vendor/calyx/*}
    SOURCE_DIRECTORY=${SOURCE_DIRECTORY%/}
  fi
  if [ "$is_provisioning_mode" = "y" ]; then
    basepath=$PROVISIONING_PATH
    KEY_DIR=${KEY_DIR:-$KEEP_PATH/keys}
    manifest_path=$basepath/$shipped_manifest_relpath
  else
    basepath=$SOURCE_DIRECTORY
    KEY_DIR=${KEY_DIR:-$(pwd)/keys}
    manifest_path=$basepath/$source_manifest_relpath
  fi

  our_desired_path=$basepath/$our_desired_relpath
  start_path=$basepath/start.sh

  if [ "$new_mode" != "$mode" ] && [ "$is_provisioning_mode" = "y" ]; then
    # If this is a provisioning mode that initialized our provisioning path, save it there.
    printf "%s\n" "$new_mode" > "$mode_file" || return $?
  fi
  mode=$new_mode

  if [ -z "${RELAUNCHED_SCRIPT:-}" ]; then
    echo "Mode: $mode"
  fi
}

copy_files() {
  if paths_exist_and_are_equal "$0" "$our_desired_path"; then
    echo "Skipping copying files since we are running from memory already." >&2
    return 0
  fi
  # TODO: Just copy everything to simplify? Or, copy everything from the manifest,
  #       and also the manifest itself?
  local -a manifest_files
  local source_manifest_path=$SOURCE_DIRECTORY/$shipped_manifest_relpath
  mapfile -t manifest_files < \
    <(cat "$source_manifest_path" | cut -d$'\t' -f 1 | grep -Fxv filename) || return $?
  local file
  for file in "${manifest_files[@]}"; do
    mkdir -p "$PROVISIONING_PATH/$(dirname "$file")" || return $?
    cp -pr "$SOURCE_DIRECTORY/$file" "$PROVISIONING_PATH/$file" || return $?
  done
  mkdir -p "$PROVISIONING_PATH/$(dirname "$shipped_manifest_relpath")" || return $?
  cp -pr "$source_manifest_path" \
    "$PROVISIONING_PATH/$shipped_manifest_relpath" || return $?
}

verify_copied_files() {
  local manifest_path=$SOURCE_DIRECTORY/$shipped_manifest_relpath
  verify_files "$manifest_path" "$PROVISIONING_PATH" || return $?
}

extract_tools() {
  mkdir -p -m0700 "$PROVISIONING_PATH/sdk_packages" || return $?
  if paths_exist_and_are_equal "$0" "$our_desired_path"; then
    echo "Skipping extracting tools since we are running from memory already." >&2
    return 0
  fi

  local file
  for file in "$PROVISIONING_PATH/sdk"/yubihsm2-sdk-*.tar.gz; do
    if [ ! -e "$file" ]; then
      echo "Could not find YubiHSM SDK in '$PROVISIONING_PATH/sdk'." >&2
      return 1
    fi
    tar -xf "$file" -C "$PROVISIONING_PATH/sdk_packages" || return $?
    # Don't want or need the development package.
    rm -f "$PROVISIONING_PATH/sdk_packages/yubihsm2-sdk/"libyubihsm-dev*.deb || true
    break
  done
}

relaunch_script_from_memory_if_needed() {
  if paths_exist_and_are_equal "$0" "$our_desired_path"; then
    return 0
  fi
  cp -Pu "$0" "$our_desired_path" || return $?
  chmod +x "$our_desired_path" || return $?
  if [ -n "$next_stage" ]; then
    set_stage "$next_stage" no-announce
  fi
  trap "" EXIT
  RELAUNCHED_SCRIPT=y exec "$SHELL" "$our_desired_path" "${script_args[@]}"
}

paths_exist_and_are_equal() {
  local path1
  local path2
  path1=$(realpath -e --no-symlinks "$1" 2>/dev/null) || return $?
  path2=$(realpath -e --no-symlinks "$2" 2>/dev/null) || return $?
  [ "$path1" = "$path2" ]
}

remove_media() {
  echo "Everything required has now been installed or copied to memory at $PROVISIONING_PATH."
  echo "You may now remove the media containing these provisioning files."
  pause
}

source_include_scripts() {
  source "$basepath/$script_relpath/metadata" || return $?
  # Regrettably, the devices array is readonly, and this causes problems in
  # create_custom_metadata_for_keygen, even in a subshell, so we cheat our way out of it.
  source <(cat "$basepath/$devices_relpath" | sed -e 's/^readonly /declare -g /') || return $?
  source "$basepath/$script_relpath/common.include.sh" || return $?
  source "$basepath/$pkcs11_relpath/vendor.yubihsm.include.sh" || return $?
  try load_keymapper || return $?
  yubihsm_original_authkey=$YUBIHSM_AUTHKEY
  yubihsm_original_password=$YUBIHSM_PASSWORD
}

maybe_install_tools() {
  echo
  echo "This step uses administrator privileges via sudo to install the packages required to provision YubiHSM 2."
  echo "You may be required to enter your administrator password."
  if ! confirm "Would you like to install these tools?"; then
    return 0
  fi

  sudo dpkg -i "$PROVISIONING_PATH/packages/"*.deb "$PROVISIONING_PATH/sdk_packages/yubihsm2-sdk/"*.deb || return $?

  installed=y
}

maybe_start_yubihsm_connector_service() {
  echo
  echo "This step uses administrator privileges via sudo to start the YubiHSM connector."
  echo "You may be required to enter your administrator password."
  if ! confirm "Would you like to start the yubihsm connector?"; then
    return 0
  fi
  sudo systemctl start yubihsm-connector || return $?
}

connect_hsm_primary() {
  echo
  echo "Please connect the primary YubiHSM 2."
  confirm "Enter Y when the primary YubiHSM 2 is connected, or N to quit." || return $?
  log_start primary || return $?
}

maybe_reset_hsm_primary() {
  maybe_reset_hsm "$@" || return $?
}

provision_auditing_primary() {
  provision_auditing "$@" || return $?
}

provision_wrap_key_primary() {
  local output
  output=$(yubihsm_nolog -a list-objects -t wrap-key -i "$YUBIHSM_WRAP_KEY_ID") || return $?
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
  echo "When prompted, please answer as follows (note the wrap key will be created as $YUBIHSM_WRAP_KEY_ID):"
  echo "  Would you like to add RSA decryption capabilities? (y/n) y"
  echo "  Enter domains: all"
  echo "  You have selected more than one domain, are you sure? (y/n) y"
  echo "  Enter wrap key ID (0 to choose automatically): $YUBIHSM_WRAP_KEY_ID"
  echo "  Enter the number of shares: [prearranged, e.g. 5]"
  echo "  Enter the privacy threshold: [prearranged, e.g. 3]"
  # TODO: Prearranged mechanism is... what?
  echo "Then, prepare to record shares using the prearranged mechanism."
  echo "More questions appear, pertaining to authentication keys that we will discard."
  echo "You may enter any values for these next questions. It does not matter."
  echo "Here are some preferred values to get you moving quickly:"
  echo "  Enter application authentication key ID (0 to choose automatically): 0"
  echo "  Enter application authentication key password: n"
  echo "  Would you like to create an audit key? (y/n) n"
  # TODO: Do this for them, and open with xdg-open?
  echo "You may wish to copy this information to a text file in case it scrolls off the screen."
  echo
  confirm "Are you ready to input this information and record shares?" || return $?

  # Call yubihsm-setup to create the wrap key, and all the other stuff it unfortunately does
  # which we will subsequently undo.
  yhsetup --no-delete --no-export ksp || return $?

  local will_exit=
  output=$(yubihsm_nolog -a list-objects -t wrap-key -i "$YUBIHSM_WRAP_KEY_ID") || return $?
  if printf "%s\n" "$output" | grep -q "^Found 0 "; then
    echo "Could not find a wrap key with the expected ID!" >&2
    will_exit=y
  else
    output=$(yubihsm_nolog -a get-object-info -i "$YUBIHSM_WRAP_KEY_ID" -t wrap-key \
      | grep -v '^Found ')
    echo "Wrap key: $output" >&2
    if [ "$output" != "$YUBIHSM_EXPECTED_WRAP_KEY_INFO" ]; then
      echo "Expected: $YUBIHSM_EXPECTED_WRAP_KEY_INFO" >&2
      echo >&2
      echo "Found a wrap key, but its details do not match what we expect." >&2
      echo "It is not recommended to continue!" >&2
      if ! confirm "Would you like to proceed anyway?"; then
        will_exit=y
      fi
    else
      echo "Wrap key matches our expected info."
    fi
  fi
  if [ "$will_exit" = "y" ]; then
    echo >&2
    echo "Unfortunately, you must restart this entire process from the beginning," >&2
    echo "resetting the device in the process." >&2
    no_recover=y
    no_exit_recommendations=y
    return 1
  fi

  # Undo the things we don't want.
  echo "Deleting authentication keys added by the wizard..."

  mapfile -t authkeys < <(yubihsm_nolog -a list-objects -t authentication-key) || return $?
  local -a authkeys_to_delete
  local authkey
  local found_default_authkey=
  for authkey in "${authkeys[@]}"; do
    case "$authkey" in
      "id: 0x0001,"*DEFAULT*)
        found_default_authkey=y
        true ;;  # Skip the default authkey. We only expect this authkey to exist right now.
      "id: 0x"*","*)
        authkey=${authkey#id: }
        authkey=${authkey%%,*}
        authkeys_to_delete+=("$authkey")
        ;;
      *)
        true ;;  # Not an authkey
    esac
  done
  if [ -z "$authkey" ]; then
    echo "No authkeys detected. This is not expected. What happened?" >&2
    return 1
  fi
  if [ "$found_default_authkey" != "y" ]; then
    echo "Did not find default authkey. Cannot safely remove other authkeys." >&2
    return 1
  fi
  for authkey in "${authkeys_to_delete[@]}"; do
    yubihsm -a delete-object -i "$authkey" -t authentication-key || return $?
    echo "Deleting authkey $authkey."
  done
}

ask_signing_authkey_password_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    return 0
  fi
  read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" n || return $?
}

ask_authkey_passwords_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ] && \
     [ -n "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ] && \
     [ -n "${YUBIHSM_ADMIN_AUTHKEY_PASSWORD:-}" ]; then
     return 0
  fi
  echo
  echo "Your HSM will have different authentication keys: signing, audit, and admin."
  echo "The signing key is used for most operations. Audit is used of course for auditing."
  echo "The admin key is able to create new authentication keys if needed in the future"
  echo "and has more capabilities than the others, but still lacks the ability to create"
  echo "or import any new wrap keys to ensure that the key shares are required for this."
  echo
  echo "Each key will have its own password. Please choose these passwords now."
  if [ -z "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" || return $?
  fi
  if [ -z "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_AUDIT_AUTHKEY_PASSWORD "audit authkey password" || return $?
  fi
  if [ -z "${YUBIHSM_ADMIN_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_ADMIN_AUTHKEY_PASSWORD "admin authkey password" || return $?
  fi
}

use_admin_authkey_for_primary() {
  export YUBIHSM_AUTHKEY=$YUBIHSM_ADMIN_AUTHKEY_ID
  export YUBIHSM_PASSWORD=$YUBIHSM_ADMIN_AUTHKEY_PASSWORD
}

delete_default_authentication_key_primary() {
  # Delete the original, default authentication key using the temporary authentication key.
  yubihsm -a delete-object --object-id 0x0001 --object-type authentication-key \
    || return $?
}

provision_admin_authentication_primary() {
  # WARNING: Password is on the command line.
  # --new-password does not support the "file:" construction that --password does.
  # This entire script is expected to be run in an ephemeral, trusted environment.

  # Create the authentication key to be used for admin.
  yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_ADMIN_AUTHKEY_ID" \
    --domains "$YUBIHSM_ADMIN_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_ADMIN_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_ADMIN_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_ADMIN_AUTHKEY_PASSWORD" || return $?
}

provision_authentication_primary() {
  # WARNING: Password is on the command line.
  # --new-password does not support the "file:" construction that --password does.
  # This entire script is expected to be run in an ephemeral, trusted environment.

  # Create the authentication key to be used for signing.
  YUBIHSM_AUTHKEY=$YUBIHSM_ADMIN_AUTHKEY_ID YUBIHSM_PASSWORD=$YUBIHSM_ADMIN_AUTHKEY_PASSWORD \
    yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_SIGNING_AUTHKEY_ID" \
    --domains "$YUBIHSM_SIGNING_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_SIGNING_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_SIGNING_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_SIGNING_AUTHKEY_PASSWORD" || return $?

  # Create the authentication key to be used for auditing.
  YUBIHSM_AUTHKEY=$YUBIHSM_ADMIN_AUTHKEY_ID YUBIHSM_PASSWORD=$YUBIHSM_ADMIN_AUTHKEY_PASSWORD \
    yubihsm \
    -a put-authentication-key \
    --object-id "$YUBIHSM_AUDIT_AUTHKEY_ID" \
    --domains "$YUBIHSM_AUDIT_AUTHKEY_DOMAINS" \
    --capabilities "$YUBIHSM_AUDIT_AUTHKEY_CAPABILITIES" \
    --delegated "$YUBIHSM_AUDIT_AUTHKEY_DELEGATED_CAPABILITIES" \
    --new-password "$YUBIHSM_AUDIT_AUTHKEY_PASSWORD" || return $?
}

use_signing_authkey_for_primary() {
  export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
  export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
}

create_custom_metadata_for_keygen_primary() {
  if [ -z "${METADATA_FILE:-}" ]; then
    echo "Preparing metadata for generating just a few keys..."
    export METADATA_FILE=$PROVISIONING_PATH/limited_keygen_metadata
    (
      source "$basepath/$script_relpath/metadata" || return $?
      # We include the original as well so we don't miss a spot in terms of key arrays.
      cat "$basepath/$script_relpath/metadata" || return $?
      # These override what came before.
      printf 'keys_avb=(%q)\n' "${keys_avb[0]}"
      printf 'keys_core=(%q)\n' "${keys_core[1]}"
      echo 'keys_apex=()'
      echo 'keys_apex_apk=()'
      echo "keys_app=()"
    ) > "$METADATA_FILE" || return $?
  fi
  if [ -z "${DEVICES_FILE:-}" ]; then
    echo "Preparing devices list for generating just a few keys..."
    export DEVICES_FILE=$PROVISIONING_PATH/limited_keygen_devices
    (
      source "$basepath/$devices_relpath" || return $?
      echo "readonly -a devices=(${devices[0]})"
    ) > "$DEVICES_FILE" || return $?
  fi
}

keygen_primary() {
  (
    export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
    export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    mkdir -p -m0700 "$KEEP_PATH" || return $?
    KEY_DIR=${KEY_DIR:-$KEEP_PATH/keys}
    mkdir -p -m0700 "$KEEP_PATH/keys" || return $?
    cd "$basepath" || return $?
    "$basepath/$pkcs11_relpath/vendor.yubihsm.keygen.sh" "$KEY_DIR" || return $?
  ) || return $?
}

backup_primary() {
  # Back up / export objects.
  (cd "$KEY_DIR" && YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD yhsetup dump) \
    || return $?
}

check_exports_primary() {
  local key
  for key in "$KEY_DIR/"*.yhw; do
    if [ ! -e "$key" ]; then
      echo "No exported keys found! Did they all fail to export?" >&2
      return 1
    fi
    break
  done
}

log_end_primary() {
  log_end primary || return $?
}

connect_hsm_secondary() {
  echo
  echo "Please connect the secondary (restoration target) YubiHSM 2."
  confirm "Enter Y when the specified HSM is connected, or N to quit." || return $?
  log_start secondary || return $?
}

connect_hsm() {
  echo
  echo "Please connect the YubiHSM 2."
  confirm "Enter Y when the HSM is connected, or N to quit." || return $?
  log_start || return $?
}

use_original_authkey_for_secondary() {
  export YUBIHSM_AUTHKEY=$yubihsm_original_authkey
  export YUBIHSM_PASSWORD=$yubihsm_original_password
}

maybe_reset_hsm_secondary() {
  maybe_reset_hsm "$@" || return $?
}

provision_auditing_secondary() {
  provision_auditing "$@" || return $?
}

provision_admin_authentication_secondary() {
  # They do the same thing.
  provision_admin_authentication_primary "$@" || return $?
}

use_admin_authkey_for_secondary() {
  # They do the same thing.
  use_admin_authkey_for_primary "$@" || return $?
}

delete_default_authentication_key_secondary() {
  # They do the same thing.
  delete_default_authentication_key_primary "$@" || return $?
}

provision_authentication_secondary() {
  # They do the same thing.
  provision_authentication_primary "$@" || return $?
}

use_signing_authkey_for_secondary() {
  # They do the same thing.
  use_signing_authkey_for_primary "$@" || return $?
}

restore_secondary() {
  echo
  echo "You are about to enter the yubihsm-setup wizard to restore your wrap key."
  echo "When prompted, please answer as follows:"
  echo "  Enter the number of shares: [TODO: prearranged. let's say 5]"
  echo "Then, enter all of the shares recorded previously."
  echo
  echo "This process should also successfully restore your keys from backup,"
  echo "which serves as a confirmation that the restored wrap key is valid."
  echo
  confirm "Are you ready to continue?" || return $?
  local file
  for file in "$KEY_DIR/"*.yhw; do
    if [ ! -e "$file" ]; then
      echo "No wrapped keys found. Please place keys (.yhw files) in: $KEY_DIR" >&2
      if ! confirm "Do you want to continue without restoring wrapped keys?"; then
        return 1
      fi
    fi
    break
  done

  # We just want to restore the wrap key, here, so let's hope to choose a working directory
  # with no keys inside.
  (cd /dev/shm && yhsetup --no-delete --no-export restore) \
    || return $?

  echo
  echo "Finished restoring wrap key with yubihsm-setup. Now trying to restore all available"
  echo "keys to ensure that works, making room as needed with ondemand keys..."
  load_keys || return $?

  local object_id
  object_id=$(yubihsm_nolog -a list-objects \
    --object-type asymmetric-key | sed -ne 's/^id: \([^,]\+\),.*$/\1/p') || return $?
  if [ -z "$object_id" ]; then
    echo >&2
    echo "No asymmetric keys were found on the HSM! Did it fail to restore?" >&2
    echo "It is possible that one or more of the shares you entered were incorrect." >&2
    return 1
  fi
  echo
  echo "Restore completed without errors, and asymmetric keys were found."
}

load_keys() {
  echo
  echo "Restoring all keys and certs..."
  try restore_all_keys_and_certs "$@" || return $?
}

create_custom_metadata_for_keygen_secondary() {
  # They do the same thing.
  create_custom_metadata_for_keygen_primary "$@" || return $?
}

keygen_secondary() {
  # They do the same thing.
  keygen_primary "$@" || return $?
}

log_end_secondary() {
  log_end secondary || return $?
}

finish() {
  if [ "$is_provisioning_mode" = "y" ]; then
    echo "Provisioning completed successfully!"
    echo "Do not forget to save the contents of:"
    printf "%s\n" "$KEEP_PATH"
    rm -f "$stage_file"
  else
    echo "Done!"
  fi
}

log_start() {
  local err=
  provisioning_started=y
  read_yubihsm_deviceinfo || err=$?
  if [ -n "$err" ] || [ -z "$yubihsm_deviceinfo" ]; then
    return ${err:-1}
  fi

  export YUBIHSM_LOGS_DIR=${YUBIHSM_LOGS_DIR:-${KEEP_PATH:-.}/logs}
  export AUDIT_LOG_PATH=provision-$(get_name_for_hsm_and_session "${1:-}").log

  local info
  info=$(show_yubihsm_info 2>&1) || err=$?
  if [ -n "$err" ]; then
    asked_reset=y
    echo "Gathering HSM info failed. Wrong password?" >&2
    reset_hsm_manual || { err=$?; asked_reset=; return $err; }
    err=
  fi
  local manifest
  manifest=$(cat "$manifest_path") || return $?
  add_input_to_log <<EOF || return $?
Begin mode $mode${1:+for $1}
$info
-Manifest-
$manifest
EOF
}

reset_hsm() {
  local err=
  local info=${1:-}
  yubihsm_nolog -a reset || err=$?
  add_input_to_log <<EOF || return $?
Command: yubihsm-shell -a reset
Result: ${err:-0}$info
EOF
  if [ -z "$err" ]; then
    # No error, so give a moment for the HSM to reappear.
    sleep 2
    while ! read_yubihsm_deviceinfo; do
      echo "Could not read from the HSM after reset. Try reconnecting it." >&2
      if ! confirm "Have you tried reconnecting the HSM?"; then
        return 1
      fi
    done
  fi
  return ${err:-0}
}

reset_hsm_manual() {
  local info=${1:-}
  {
    echo
    echo "Either the HSM could not be found, or we could not communicate with it."
    echo "If the HSM is connected, you likely need to reset it manually by removing and"
    echo "re-inserting it, pressing on the metal rim for at least 10 seconds."
    echo
    echo "If you'd like to do so, please do so now."
    echo "Press Y if you have manually reset the device and want to reset it again,"
    echo "to be certain that this step was completed, or N if you don't want to reset."
    echo
  } >&2
  if confirm "Would you like to reset this HSM? This cannot be undone!"; then
    try reset_hsm "$info" || return $?
  else
    return 1
  fi
}

maybe_reset_hsm() {
  if [ "$asked_reset" = "y" ]; then
    echo "Already asked to reset. Skipping..."
    asked_reset=
    return 0
  fi
  local err=
  local info
  info=$(show_yubihsm_info 2>&1) || err=$?
  if [ -n "$info" ]; then
    info=$'\n''-Pre-reset info-'$'\n'"$info"
  fi
  printf "%s\n" "$info"
  echo
  echo "This provisioning script expects that the provided HSM is in a clean state."
  if [ -z "$err" ]; then
    if ! confirm "Would you like to reset this HSM? This cannot be undone!"; then
      return 0
    fi
    reset_hsm "$info" || err=$?
  fi
  if [ -n "$err" ]; then
    reset_hsm_manual "$info" || return $?
  fi
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

provision_auditing_the_long_way() {
  # Much of this was gleaned from https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e
  if check_command_audit_value; then
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
    # Force audit of given command until factory reset.
    yubihsm -a put-option --opt-name command-audit --opt-value "${cmd}02" || return $?
  done
  if ! check_command_audit_value; then
    # TODO: Maybe allow this enforcement to be skipped? But maybe not.
    echo "Command audit value is not as expected after provisioning!" >&2
    return 1
  fi
  echo "Successfully provisioned auditing options."

  # TODO: Check this automatically?
  #yubihsm -a get-logs   # witness that there are many 4f entries now, since PUT OPTION is logged
}

log_end() {
  YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID \
  YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD \
  add_input_to_log <<EOF || return $?
End mode $mode${1:+for $1}
$(show_yubihsm_info)
EOF
}

delete_all_asymmetric_keys_and_opaque_objects() {
  for object_id in $(yubihsm_nolog -a list-objects --object-type asymmetric-key \
    | sed -ne 's/^id: \([^,]\+\),.*$/\1/p');
  do
    yubihsm -a delete-object --object-id "$object_id" --object-type asymmetric-key || return $?
  done
  for object_id in $(yubihsm_nolog -a list-objects --object-type opaque \
    | sed -ne 's/^id: \([^,]\+\),.*$/\1/p');
  do
    yubihsm -a delete-object --object-id "$object_id" --object-type opaque || return $?
  done
}

verify_files() {
  local manifest_path=$1
  local check_directory=$2
  local check_for_extra_files=${3:-}
  local -a manifest_lines
  mapfile -t manifest_lines < "$manifest_path" || return $?
  local line
  local header_done=
  local -a failed_files=()
  local -a mismatched_files=()
  local -a successful_files=()
  local -A manifest_files=()
  for line in "${manifest_lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    if [ -z "$header_done" ]; then
      header_done=y
      if [ "$1" = "filename" ]; then
        # skip header
        continue
      fi
    fi
    local filename=$1
    manifest_files[$filename]=1
    local sha256sum=$2
    local actual_sum=$(cd "$check_directory" && sha256sum "$filename" | cut -d' ' -f1) || true
    if [ -z "$actual_sum" ]; then
      failed_files+=("$filename")
    elif [ "$actual_sum" != "$sha256sum" ]; then
      mismatched_files+=("$filename")
    else
      successful_files+=("$filename")
    fi
  done
  local returnval=0
  if [ "${#failed_files[@]}" -eq 0 ] && [ "${#mismatched_files[@]}" -eq 0 ]; then
    echo "All files verified successfully."
  else
    echo >&2
    if [ "${#failed_files[@]}" -gt 0 ]; then
      echo "The following files were missing or sha256sum failed to run:" >&2
      printf "  %s\n" "${failed_files[@]}" >&2
    fi
    if [ "${#mismatched_files[@]}" -gt 0 ]; then
      echo "The following files FAILED sha256sum verification:" >&2
      printf "  %s\n" "${mismatched_files[@]}" >&2
    fi
    returnval=1
  fi
  if [ "${check_for_extra_files:-}" = "y" ]; then
    # This won't result in an error, just informational.
    local -a all_actual_files=()
    mapfile -t -d '' all_actual_files < <(cd "$check_directory"; find -type f -print0 | sort -z)
    local actual_file
    local -a extra_files=()
    for actual_file in "${all_actual_files[@]}"; do
      actual_file=${actual_file#./}
      case "$manifest_path" in
        *$actual_file)
          # The manifest cannot contain an entry for itself.
          continue ;;
      esac
      if [ "${manifest_files[$actual_file]:-}" != "1" ]; then
        extra_files+=("$actual_file")
      fi
    done
    if [ "${#extra_files[@]}" -gt 0 ]; then
      echo "The following extra files were found:" >&2
      printf "  %s\n" "${extra_files[@]}" >&2
    fi
  fi
  return $returnval
}

generate_start_script() {
  cat <<EOF
#!/bin/bash
ourpath=\$(cd "\$(dirname "\$0")";pwd -P)
SOURCE_DIRECTORY="\$ourpath" exec "\$ourpath/$our_desired_relpath" "\$@"
EOF
}

prepare_directory() {
  local output_directory=${script_args[1]:-}
  if [ -z "$output_directory" ]; then
    echo "You must supply an output directory argument." >&2
    return 1
  fi
  echo "We will now prepare $output_directory with the files needed for provisioning."
  echo "If the directory already contains files, they may be updated."
  echo "This process will download any missing files."
  pause
  if [ ! -d "$output_directory" ]; then
    mkdir -p "$output_directory" || return $?
  fi
  generate_start_script > "$output_directory/start.sh" || return $?
  chmod +x "$output_directory/start.sh" || true # If this does not work, oh well.
  prepare_manifest_and_files "$output_directory" || return $?
}

verify_prepared_manifest_files() {
  local output_directory=${script_args[1]:-}
  verify_files \
    "$output_directory/$shipped_manifest_relpath" \
    "$output_directory" \
    y \
    || return $?
}

prepare_manifest_and_files() {
  local output_directory=$(realpath --no-symlinks "$1")
  local -a manifest_lines
  local -a new_manifest_lines=($'filename\tsha256sum\tfilesize\tlink')
  mapfile -t manifest_lines < "$basepath/$source_manifest_relpath" \
    || return $?
  local line
  local header_done=
  for line in "${manifest_lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    if [ -z "$header_done" ]; then
      header_done=y
      if [ "$1" = "filename" ]; then
        # skip header
        continue
      fi
    fi
    local filename=${1:-}
    local sha256sum=${2:-}
    local filesize=${3:-}
    local link=${4:-}
    local dest_file=$output_directory/$filename
    local output_path=$(realpath -m --no-symlinks "$dest_file")
    case "$output_path" in
      "$output_directory"/*)
        true ;; # Expected, no weird path traversal
      *)
        echo "Unacceptable path traversal in $filename" >&2
        return 1 ;;
    esac

    # Make the directories needed by this file.
    mkdir -p "$(dirname "$dest_file")" || return $?

    if [ -n "$link" ]; then
      # Download the file if it does not already exist or does not match the sha256sum.
      if [ -e "$dest_file" ]; then
        if [ "$(sha256sum "$dest_file" | cut -d' ' -f1)" != "$sha256sum" ]; then
          printf "%s does not match expected sha256sum. Deleting and re-downloading..." \
            "$dest_file" >&2
          rm -f "$dest_file" || return $?
        fi
      fi
      if [ ! -e "$dest_file" ]; then
        echo "Downloading $dest_file..."
        (ulimit -f "$filesize" || true; wget -O "$dest_file" "$link") || return $?
      fi
    else
      # Copy the file.
      local source_file=
      local we_generated=
      case "$filename" in
        bin/avbtool)
          source_file=${AVBTOOL_BIN:-${ANDROID_HOST_OUT:-$SOURCE_DIRECTORY}/bin/avbtool}
          if [ ! -e "$source_file" ]; then
            echo "avbtool not found. Try setting AVBTOOL_BIN to its path." >&2
          fi ;;
        start.sh)
          # We generate it, so no need to copy, etc.
          we_generated=y ;;
        *)
          source_file=${ANDROID_BUILD_TOP:-$SOURCE_DIRECTORY}/$filename ;;
      esac
      if [ "$we_generated" != "y" ] && [ ! -e "$source_file" ]; then
        echo "Cannot find $filename." >&2
        echo "Run this script from a lunch'd Android build environment, or run it from" >&2
        echo "an extracted otatools-keys.zip directory:" >&2
        echo "  unzip otatools-keys.zip -d otatools-keys" >&2
        echo "  cd otatools-keys" >&2
        echo "  ${our_desired_relpath@Q} ${script_args[*]@Q}" >&2
        echo "(otatools-keys.zip is built with: m otatools-keys-package)" >&2
        return 1
      fi
      if [ -n "$sha256sum" ] && [ "$(sha256sum "$dest_file" | cut -d' ' -f1)" != "$sha256sum" ];
      then
        printf "%s does not match expected sha256sum and no link provided!" \
          "$dest_file" >&2
      fi
      if [ "$we_generated" != "y" ]; then
        filesize=$(stat -c%s "$source_file") || return $?
        cp -p "$source_file" "$dest_file" || return $?
      else
        filesize=$(stat -c%s "$dest_file") || return $?
      fi
    fi
    if [ -z "$sha256sum" ]; then
      sha256sum=$(sha256sum "$dest_file" | cut -d' ' -f1) || return $?
    fi
    new_manifest_lines+=("$filename"$'\t'"$sha256sum"$'\t'"$filesize"$'\t'"$link")
  done
  mkdir -p "$(dirname "$output_directory/$shipped_manifest_relpath")" || return $?
  printf "%s\n" "${new_manifest_lines[@]}" > "$output_directory/$shipped_manifest_relpath" || return $?
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
  local err=
  yubihsm-setup --connector "$YUBIHSM_CONNECTOR" --authkey "$YUBIHSM_AUTHKEY" --password "$YUBIHSM_PASSWORD" "$@" || err=$?
  extract_logs "" "Command: yubihsm-setup $(printf '%q ' "$@")"$'\n'"Result: ${err:-0}" \
    || \
    {
      err=${err:-$?}
      echo "Failed to extract logs" >&2
      return $err
    }
  return ${err:-0}
}

set_stage() {
  if [ "$1" != "$stage" ]; then
    stage=$1
    case "$stage" in
      connect_hsm*|source_include_scripts)
        # Don't store these stages.
        true ;;
      *)
        # If this is a provisioning mode that initialized our provisioning path, save it there.
        if [ "$is_provisioning_mode" = "y" ]; then
          printf "%s\n" "$1" > "$stage_file" || return $?
        fi ;;
    esac
  fi
  if [ "${2:-}" != "no-announce" ]; then
    echo "Now performing: $stage"
    if [ "$provisioning_started" = "y" ]; then
      add_input_to_log <<EOF || return $?
Stage: $stage
EOF
    fi
  fi
}

recover_previous_state() {
  stage=$(cat "$stage_file" 2>/dev/null) || true
  mode=$(cat "$mode_file" 2>/dev/null) || true
}

initialize_provisioning_mode() {
  is_provisioning_mode=y
  if [ ! -d "$PROVISIONING_PATH" ]; then
    mkdir -p -m0700 "$PROVISIONING_PATH" || return $?
  fi
  KEEP_PATH=${KEEP_PATH:-/dev/shm/keep}
}

try() {
  local failed_again=
  while true; do
    local err=
    "$@" || err=$?
    if [ -n "$err" ]; then
      if [ "$no_recover" = "y" ] || \
        ! confirm "$(printf "%s failed%s (code %s). Try again?" "$1" "$failed_again" "$err")"; then
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
        echo "Please enter Y or N." >&2 ;;
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
  if [ "$no_exit_recommendations" != "y" ]; then
    if [ -d "${KEEP_PATH:-}" ]; then
      echo "IMPORTANT: You must save the contents of '$KEEP_PATH'! Copy it somewhere safe!" >&2
    fi
    if [ "${RELAUNCHED_SCRIPT:-}" = "y" ] && \
      paths_exist_and_are_equal "$0" "$our_desired_path"; then
      echo "Remember to use this command if you want to launch the script again: " >&2
      printf "%q %q\n" "$SHELL" "$start_path" >&2
    fi
  fi
}

main "$@"
