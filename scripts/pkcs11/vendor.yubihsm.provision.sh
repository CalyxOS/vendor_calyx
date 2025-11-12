#!/bin/bash
set -euo pipefail
ourpath=$(cd "$(dirname "$0")";pwd -P)
PROVISIONING_PATH=${PROVISIONING_PATH:-/dev/shm/hsmp}
declare -g SOURCE_DIRECTORY
# KEEP_PATH is established in initialize_provisioning_mode and set_mode.
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
# manifest_path is established in set_mode.
declare -g manifest_path

SHELL=${SHELL:-bash}

script_args=()
# basepath is established in set_mode.
basepath=
is_provisioning_mode=
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

wizard_script_provisioning_prerequisites=(
  copy_files
  verify_copied_files
  extract_tools
  relaunch_script_from_memory_if_needed
  remove_media
  maybe_install_tools
)
wizard_script_start=(
  source_include_scripts
  maybe_start_yubihsm_connector_service
)
wizard_script_main=(
  connect_hsm
  maybe_reset_hsm
  ask_authkey_passwords_if_needed
  provision_hsm
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
        |ask_*_if_needed|create_custom_metadata_for_keygen)
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
  local act_like_not_provisioning=
  local new_mode=${1:-}
  if [ "$new_mode" = "restore" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_provisioning_prerequisites[@]}"
      "${wizard_script_start[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "primary" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_provisioning_prerequisites[@]}"
      "${wizard_script_start[@]}"
      "${wizard_script_main[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "limited-keygen" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_provisioning_prerequisites[@]}"
      "${wizard_script_start[@]}"
      ask_signing_authkey_password_if_needed
      use_signing_authkey
      connect_hsm
      create_custom_metadata_for_keygen
      keygen
      check_exports
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "keygen" ]; then
    declare -g wizard_script=()
    # Keygen can be run outside of the provisioning environment, for example directly from an
    # extracted otatools-package / otatools-keys-package. In that case, the manifest file is not
    # in the root, but in the source relative path.
    # So, let's try to figure out how we are running right now and what we need to do.
    if [ ! -e "$PROVISIONING_PATH/$shipped_manifest_relpath" ]; then
      act_like_not_provisioning=y
      KEEP_PATH=${KEEP_PATH:-$(pwd)}
    else
      wizard_script=("${wizard_script_provisioning_prerequisites[@]}")
    fi
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script[@]}"
      "${wizard_script_start[@]}"
      ask_signing_authkey_password_if_needed
      use_signing_authkey
      connect_hsm
      keygen
      check_exports
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "full" ] || [ -z "$new_mode" ]; then
    new_mode=full
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_provisioning_prerequisites[@]}"
      "${wizard_script_start[@]}"
      "${wizard_script_main[@]}"
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "backup" ]; then
    start_new_provisioning_or_handle_resume "$new_mode" || return 0
    declare -g wizard_script=(
      "${wizard_script_provisioning_prerequisites[@]}"
      "${wizard_script_start[@]}"
      backup_primary
      check_exports
      "${wizard_script_end[@]}"
    )
  elif [ "$new_mode" = "load-keys" ]; then
    stage=
    declare -g wizard_script=(
      source_include_scripts
      ask_signing_authkey_password_if_needed
      use_signing_authkey
      maybe_start_yubihsm_connector_service
      connect_hsm
      load_keys
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
  if [ "$is_provisioning_mode" = "y" ] && [ "$act_like_not_provisioning" != "y" ]; then
    basepath=${basepath:-$PROVISIONING_PATH}
    export KEY_DIR=${KEY_DIR:-$KEEP_PATH/keys}
    manifest_path=${manifest_path:-$basepath/$shipped_manifest_relpath}
  else
    basepath=${basepath:-$SOURCE_DIRECTORY}
    export KEY_DIR=${KEY_DIR:-$(pwd)/keys}
    manifest_path=${manifest_path:-$basepath/$source_manifest_relpath}
    if [ ! -e "$manifest_path" ]; then
      manifest_path=${manifest_path:-$basepath/$shipped_manifest_relpath}
    fi
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
    echo "Skipping copying files since we are already where we want to be." >&2
    return 0
  fi
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

connect_hsm() {
  echo
  echo "Please connect the primary YubiHSM 2."
  confirm "Enter Y when the primary YubiHSM 2 is connected, or N to quit." || return $?
  log_start primary || return $?
}

provision_hsm() {
  (
    export YUBIHSM_ADMIN_AUTHKEY_PASSWORD=$YUBIHSM_ADMIN_AUTHKEY_PASSWORD
    export YUBIHSM_SIGNING_AUTHKEY_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    export YUBIHSM_AUDIT_AUTHKEY_PASSWORD=$YUBIHSM_AUDIT_AUTHKEY_PASSWORD
    export KEEP_PATH=$KEEP_PATH
    "$basepath/$pkcs11_relpath/vendor.yubihsm.setup.py" || return $?
  ) || return $?

  if ! check_command_audit_value; then
    # TODO: Maybe allow this enforcement to be skipped? But maybe not.
    echo "Command audit value is not as expected after provisioning!" >&2
    return 1
  fi

  extract_logs "provisioning: 4f is for audit log options, the rest is key setup" || return $?
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

use_signing_authkey() {
  export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
  export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
}

create_custom_metadata_for_keygen() {
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

keygen() {
  # shellcheck disable=SC2030
  (
    export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
    export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    export KEY_DIR=${KEY_DIR:-$KEEP_PATH/keys}
    mkdir -p -m0700 "$KEY_DIR" || return $?
    cd "$basepath" || return $?
    "$basepath/$pkcs11_relpath/vendor.yubihsm.keygen.sh" "$KEY_DIR" || return $?
  ) || return $?
}

backup_primary() {
  # Back up / export objects.
  # shellcheck disable=SC2031
  (cd "$KEY_DIR" && YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD dump) \
    || return $?
}

check_exports() {
  local key
  for key in "$KEY_DIR/"*.yhw; do
    if [ ! -e "$key" ]; then
      echo "No exported keys found! Did they all fail to export?" >&2
      return 1
    fi
    break
  done
}

connect_hsm() {
  echo
  echo "Please connect the YubiHSM 2."
  confirm "Enter Y when the HSM is connected, or N to quit." || return $?
  log_start || return $?
}

load_keys() {
  echo
  echo "Restoring all keys and certs..."
  try restore_all_keys_and_certs "$@" || return $?
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
  read_yubihsm_deviceinfo || err=$?
  if [ -n "$err" ] || [ -z "$yubihsm_deviceinfo" ]; then
    return ${err:-1}
  fi

  export YUBIHSM_LOGS_DIR="$KEEP_PATH/logs"
  AUDIT_LOG_PATH="$YUBIHSM_LOGS_DIR/$(get_name_for_hsm)/$(get_formatted_date)-provision.log"
  mkdir -p "$YUBIHSM_LOGS_DIR/$(get_name_for_hsm)" || return $?
  export AUDIT_LOG_PATH
}

reset_hsm() {
  local err=
  local info=${1:-}
  yubihsm_nolog -a reset || err=$?
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
