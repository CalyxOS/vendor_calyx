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

# basepath is established in set_mode.
basepath=
is_provisioning_mode=
installed=
mode=
stage=
no_recover=
no_exit_recommendations=

# These are updated in source_include_scripts too, just in case.
yubihsm_original_authkey=$YUBIHSM_AUTHKEY
yubihsm_original_password=$YUBIHSM_PASSWORD

# Stop sourced scripts from managing yubihsm-connector. We will do that ourselves.
export NEVER_START_YUBIHSM_CONNECTOR=y

wizard_script_start=(
  source_include_scripts
  maybe_start_yubihsm_connector_service
)
wizard_script_end=(
  finish
)

main() {
  trap cleanup EXIT

  set_mode "${1:-}" || exit $?

  set -- "${wizard_script[@]}"
  local skip_until=$stage
  local last_connect_hsm_stage=
  local last_authkey_stage=
  while [ $# -gt 0 ]; do
    local script_stage=$1
    if [ -n "$skip_until" ] && [ "$script_stage" != "$skip_until" ]; then
      case "$1" in
        source_include_scripts|ask_*_if_needed|create_custom_metadata_for_keygen)
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

set_mode() {
  local act_like_not_provisioning=
  local new_mode=${1:-}
  if [ "$new_mode" = "restore" ]; then
    initialize_provisioning_mode || return 0
    declare -g wizard_script=(
      "${wizard_script_start[@]}"
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
    fi
    initialize_provisioning_mode || return 0
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
  elif [ "$new_mode" = "backup" ]; then
    initialize_provisioning_mode || return 0
    declare -g wizard_script=(
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

  mode=$new_mode

  if [ -z "${RELAUNCHED_SCRIPT:-}" ]; then
    echo "Mode: $mode"
  fi
}

paths_exist_and_are_equal() {
  local path1
  local path2
  path1=$(realpath -e --no-symlinks "$1" 2>/dev/null) || return $?
  path2=$(realpath -e --no-symlinks "$2" 2>/dev/null) || return $?
  [ "$path1" = "$path2" ]
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

maybe_start_yubihsm_connector_service() {
  echo
  echo "This step uses administrator privileges via sudo to start the YubiHSM connector."
  echo "You may be required to enter your administrator password."
  if ! confirm "Would you like to start the yubihsm connector?"; then
    return 0
  fi
  sudo systemctl start yubihsm-connector || return $?
}

ask_signing_authkey_password_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    return 0
  fi
  read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" n || return $?
}

use_signing_authkey() {
  export YUBIHSM_AUTHKEY=$YUBIHSM_SIGNING_AUTHKEY_ID
  export YUBIHSM_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
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
    esac
  fi
  if [ "${2:-}" != "no-announce" ]; then
    echo "Now performing: $stage"
  fi
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
