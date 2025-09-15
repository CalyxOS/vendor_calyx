#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$0")";pwd -P)
scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
devices_path=$(realpath "$scriptpath/../../../calyx/scripts/vars/devices")

ORIGINAL_TMPDIR=${TMPDIR:-/dev/shm}
TMPDIR=
do_cleanup=
no_sign=
no_incremental=
maybe_dry_run=

declare -ga signable_devices=()
declare -ga target_files=()
declare -gA device_to_next_build=()
declare -gA next_build_to_devices=()
declare -gA device_to_prev_build=()
declare -ga prev_builds_sorted=()
declare -gA prev_build_to_devices=()
declare -ga devices_with_loaded_keys=()
declare -ga devices_without_loaded_keys=()
declare -ga sign_pairs_with_loaded_keys=()
declare -ga sign_pairs_without_loaded_keys=()
declare -ga incremental_triples_with_loaded_keys=()
declare -ga incremental_triples_without_loaded_keys=()

source_includes() {
  source "$scriptpath/common.include.sh" || return $?
  source "$pkcs11_scriptpath/include.sh" || return $?
  source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || return $?
  source "$devices_path" || return $?
  source "$scriptpath/metadata" || return $?
}

prompt_missing_variables() {
  ask_variable BUILD_NUMBER "$(deduce_build_number)" n y || return $?
  ask_variable PREV_BUILD_NUMBER "$(deduce_prev_build_number)" n n || return $?
  if [ -z "${PREV_BUILD_NUMBER:-}" ]; then
    no_incremental=y
  fi
  ask_variable YUBIHSM_AUTHKEY "0x0001" n y || return $?
  ask_variable YUBIHSM_PASSWORD "" y y || return $?
  ask_variable NUM_SIGN_JOBS "3" n y || return $?
  ask_variable NUM_INCREMENTAL_JOBS "3" n y || return $?
}

main() {
  trap cleanup EXIT
  find_target_files || return $?
  find_prev_signed_device_builds || return $?
  source_includes || return $?
  gather_signable_devices_from_metadata || return $?
  gather_latest_device_builds || return $?
  prompt_missing_variables || return $?
  gather_device_builds_to_sign || return $?
  maybe_ask_about_prev_signed_device_builds || return $?
  load_keymapper || return $?
  maybe_handle_already_existing_builds || return $?
  maybe_ask_about_missing_target_files || return $?
  check_free_space || return $?
  initialize || return $?
  sort_and_separate_devices_by_key_availability || return $?
  final_confirmation || return $?

  do_or_show || return $?

  finish || return $?
}

do_or_show() {
  # Sign and generate incrementals for devices with keys already loaded in the HSM.
  if [ "$no_sign" != "y" ] && [ "${#sign_pairs_with_loaded_keys[@]}" -gt 0 ]; then
    $maybe_dry_run sign_builds "${sign_pairs_with_loaded_keys[@]}" || return $?
  fi

  if [ "$no_incremental" != "y" ] && [ ${#incremental_triples_with_loaded_keys[@]} -gt 0 ]; then
    $maybe_dry_run generate_incrementals "${incremental_triples_with_loaded_keys[@]}" || return $?
  fi

  # Sign and generate incrementals for devices with keys not yet loaded in the HSM.
  if [ "${#devices_without_loaded_keys[@]}" -gt 0 ]; then
    $maybe_dry_run ensure_all_keys_available_for_devices "${devices_without_loaded_keys[@]}"
  fi

  if [ "$no_sign" != "y" ] && [ "${#sign_pairs_without_loaded_keys[@]}" -gt 0 ]; then
    $maybe_dry_run sign_builds "${sign_pairs_without_loaded_keys[@]}" || return $?
  fi

  if [ "$no_incremental" != "y" ] && [ ${#incremental_triples_without_loaded_keys[@]} -gt 0 ]; then
    $maybe_dry_run generate_incrementals "${incremental_triples_without_loaded_keys[@]}" \
      || return $?
  fi
}

finish() {
  echo
  echo "Done signing and/or generating incrementals for $BUILD_NUMBER"
  echo

  echo "Please minisign -SHm archive/release-*-${BUILD_NUMBER}/*-factory-${BUILD_NUMBER}.zip -t 'CalyxOS x.y.z - [Message goes here]'"
}

sign_builds() {
  # Sign
  local err=
  echo
  echo "Signing release for: $*"
  parallel -j "$NUM_SIGN_JOBS" --match '(.*),(.*)' --tag --line-buffer \
    "BUILD_NUMBER={1.2}" "$pkcs11_scriptpath/vendor.yubihsm.release.sh" "{1.1}" \
      "calyx_{1.1}-target_files-{1.2}.zip" \
    "&&" mv "out/release-{1.1}-{1.2}" archive/. \
    ::: "$@" || err=$?

  if [ -n "$err" ]; then
    echo >&2
    echo "Signing failed for $err devices." >&2
    echo "You can run this script again to sign the devices that failed." >&2
    return 1
  fi

  maybe_stop_apksigner_batch "$STATEDIR" || return $?

  rm -rf "$TMPDIR" || return $?
}

generate_incrementals() {
  local err=
  # Deltas
  export TMPDIR=$(mktemp -d -p "${ORIGINAL_TMPDIR:-/dev/shm}" incremental_tmp.XXXXXXXX)
  echo
  echo "Generating incremental updates for: $*"

  parallel -j "$NUM_DELTA_JOBS" --match '(.*),(.*),(.*)' --tag --line-buffer \
    "$pkcs11_scriptpath/vendor.yubihsm.generate_delta.sh" "{1.1}" "{1.2}" "{1.3}" \
    ::: "$@" || err=$?

  if [ -n "$err" ]; then
    echo >&2
    echo "Generating incrementals failed for $err devices." >&2
    echo "You can run this script again to generate incrementals for the devices that failed." >&2
    return 1
  fi

  rm -rf "$TMPDIR" || return $?
}

initialize() {
  do_cleanup=y
  echo
  echo "Initializing HSM and related components..."
  initialize_vendor || return $?
  if [ -z "${YUBIHSM_LOGS_DIR+x}" ]; then
    export YUBIHSM_LOGS_DIR=$(pwd)/logs
  fi
  export TMPDIR=$(mktemp -d -p "$ORIGINAL_TMPDIR" sign_tmp.XXXXXXXX)
  export STATEDIR=$(mktemp -d -p /dev/shm sign_state.XXXXXXXX)

  maybe_start_yubihsm_connector "$STATEDIR/yubihsm_connector.pid" || return $?
  if [ -z "${YUBIHSM_CONNECTOR_PIDFILE:-}" ]; then
    echo
    echo "yubihsm-connector is already running."
    echo "This means we will not be able to restart it if it messes up."
    echo "Before running this script, please stop the existing connector by stopping its service,"
    echo "if any, or by running killall yubihsm-connector"
    confirm "Continue anyway?" || return $?
  fi

  export YUBIHSM_LOCKFILE=$STATEDIR/yubihsm.lock

  if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
    export YUBIHSM_PKCS11_CONF=$STATEDIR/yubihsm_pkcs11.conf
    generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF" || return $?
  fi
  maybe_start_apksigner_batch "$STATEDIR" || return $?
}

cleanup() {
  if [ "$do_cleanup" != "y" ]; then
    return 0
  fi
  maybe_stop_yubihsm_connector "$STATEDIR/yubihsm_connector.pid" || true
  maybe_stop_apksigner_batch "$STATEDIR" || true
  local jobs=$(jobs -p) || true
  if [ -n "$jobs" ]; then
    kill $jobs 2>/dev/null || true
    jobs=$(jobs -p)
    if [ -n "$jobs" ]; then
      kill -9 $jobs 2>/dev/null || true
    fi
  fi
  rm -rf "$TMPDIR"
  rm -rf "$STATEDIR"
  do_cleanup=n
}

check_free_space() {
  # Estimating 20GB required per device.
  echo
  local estimated_required_free_space=$((20 * ${#device_to_next_build[@]}))
  df -h .
  echo
  confirm "Is there at least ${estimated_required_free_space}GB of free space?" \
    || return $?
}

gather_signable_devices_from_metadata() {
  mapfile -d "" -t signable_devices < \
    <(comm -z --nocheck-order -12 \
      <(printf '%s\0' "${devices[@]}" | sort -z) \
      <(printf '%s\0' "${all_devices[@]}" | sort -z)
     ) || return $?
}

gather_latest_device_builds() {
  local file
  for file in "${target_files[@]}"; do
    local build=${file##*-}
    build=${build%.zip}
    local device=${file#calyx_}
    device=${device%-target_files-*.zip}
    local next_build=${device_to_next_build[$device]:-}
    if [ -z "$next_build" ] || [ "$build" -gt "$next_build" ]; then
      device_to_next_build[$device]=$build
    fi
  done
  _update_next_builds || return $?
}

gather_device_builds_to_sign() {
  device_to_next_build=()
  local file
  for file in "${target_files[@]}"; do
    local build=${file##*-}
    build=${build%.zip}
    local found=
    local buildnum
    for buildnum in $BUILD_NUMBER; do
      if [ "$build" = "$buildnum" ]; then
        found=y
      fi
    done
    if [ "$found" != "y" ]; then
      continue
    fi
    local device=${file#calyx_}
    device=${device%-target_files-*.zip}
    local next_build=${device_to_next_build[$device]:-}
    if [ -z "$next_build" ] || [ "$build" -gt "$next_build" ]; then
      device_to_next_build[$device]=$build
    fi
  done
  _update_next_builds || return $?
}

_update_next_builds() {
  next_build_to_devices=()
  local device
  for device in "${!device_to_next_build[@]}"; do
    local build=${device_to_next_build[$device]}
    local current=${next_build_to_devices[$build]:-}
    if [ -n "$current" ]; then
      next_build_to_devices[$build]="$current,$device"
    else
      next_build_to_devices[$build]="$device"
    fi
  done
  mapfile -d "" -t next_builds_sorted < <(printf '%s\0' "${!next_build_to_devices[@]}" | sort -z -n)
}

maybe_ask_about_missing_target_files() {
  local -a missing_target_files
  mapfile -d "" -t missing_target_files < <(comm -z --nocheck-order -23 \
    <(printf "%s\0" "${signable_devices[@]}" | sort -z) \
    <(printf "%s\0" "${device_to_next_build[@]}" | sort -z)) || return $?
  if [ "${#missing_target_files[@]}" -gt 0 ]; then
    echo
    echo "Out of ${#signable_devices[@]} signable devices, only found "\
"${#device_to_next_build[@]} target files to sign:"
    printf "  %s\n" "${!device_to_next_build[*]}"
    echo "These target files are missing for the selected build number(s):"
    printf "  %s\n" "${missing_target_files[*]}"
    echo
    confirm "Continue?" || return $?
  fi
}

maybe_handle_already_existing_builds() {
  local buildnum
  local any_already_signed=
  for buildnum in $BUILD_NUMBER; do
    if [ -n "${prev_build_to_devices[$buildnum]:-}" ]; then
      any_already_signed=y
    fi
  done
  if [ "$any_already_signed" = "y" ]; then
    echo
    echo "The following devices appear to already be signed (in archive/):"
    for buildnum in $BUILD_NUMBER; do
      local devices_to_show=${prev_build_to_devices[$buildnum]:-}
      [ -n "$devices_to_show" ] || continue
      printf " %s: %s\n" "$buildnum" "$devices_to_show"
    done
    echo
    echo "If you continue, these devices will not be signed again."
    echo "(If you want them to be signed again, remove them from archive/ first.)"
    echo
    confirm "Continue?" || return $?
  fi
  local device
  for device in "${!device_to_next_build[@]}"; do
    for buildnum in $BUILD_NUMBER; do
      if [ "${device_to_prev_build[$device]:-}" = "$buildnum" ]; then
        unset device_to_next_build[$device]
      fi
    done
  done
  if [ "${#device_to_next_build[@]}" = "0" ]; then
    echo
    echo "There is nothing left to sign."
    no_sign=y
    if [ "$no_incremental" != "y" ]; then
      confirm "Continue anyway for incremental build generation?" || return $?
    else
      echo "There are also no incremental builds to generate, so there is nothing to do."
      echo "Bye!"
      exit 0
    fi
  fi
}

find_target_files() {
  mapfile -d "" -t target_files < \
    <(find -maxdepth 1 -type f -name 'calyx_*-target_files-*.zip' -printf '%f\0' | sort -z -n)
}

find_prev_signed_device_builds() {
  if [ ! -d archive ]; then
    return 0
  fi
  local -a prev_signed_dirs
  mapfile -d "" -t prev_signed_dirs < \
    <(find archive -maxdepth 1 -type d -name 'release-*-*' -printf '%f\0')
  local dir
  for dir in "${prev_signed_dirs[@]}"; do
    local build=${dir##*-}
    local device=${dir#release-}
    device=${device%-*}
    if [ -f "archive/$dir/$device-target_files-$build.zip" ]; then
      local prev_build=${device_to_prev_build[$device]:-}
      if [ -z "$prev_build" ] || [ "$build" -gt "$prev_build" ]; then
        device_to_prev_build[$device]=$build
      fi
    fi
  done
  local device
  for device in "${!device_to_prev_build[@]}"; do
    local build=${device_to_prev_build[$device]}
    local current=${prev_build_to_devices[$build]:-}
    if [ -n "$current" ]; then
      prev_build_to_devices[$build]="$current,$device"
    else
      prev_build_to_devices[$build]="$device"
    fi
  done
  mapfile -d "" -t prev_builds_sorted < <(printf '%s\0' "${!prev_build_to_devices[@]}" | sort -z -n)
}

maybe_ask_about_prev_signed_device_builds() {
  if [ "$no_incremental" = "y" ]; then
    return 0
  fi
  if [ ! -d archive ]; then
    echo
    echo "Could not find an archive/ directory."
    echo "If you proceed, we will create it, but we will not be able to generate incrementals."
    echo "If this is a mistake, please ensure you are running this script from the proper"
    echo "directory, which should contain an archive/ subdirectory."
    echo
    confirm "WARNING: Create archive/ and continue without incrementals?" || return $?
    no_incremental=y
    mkdir archive || return $?
    return 0
  fi
  local any_found=
  echo
  printf "%s\n" "Found the following previous builds:"
  local build
  for build in "${prev_builds_sorted[@]}"; do
    [ -n "$build" ] || continue
    if [ "$BUILD_NUMBER" = "$build" ]; then
      # We'll deal with previous builds matching our current build later.
      continue
    fi
    any_found=y
    printf "  %s: %s\n" "$build" "${prev_build_to_devices[$build]}"
  done
  if [ -z "$any_found" ]; then
    echo "  None."
    echo
    confirm "WARNING: Proceed without generating any incremental builds?" \
      || return $?
    no_incremental=y
    return 0
  fi
  local -a missing_prior_builds=()
  for device in "${!device_to_next_build[@]}"; do
    if [ -z "${device_to_prev_build[$device]:-}" ]; then
      missing_prior_builds+=("$device")
    fi
  done
  if [ "${#missing_prior_builds[@]}" -gt 0 ]; then
    echo
    echo "Found no prior builds for ${#missing_prior_builds[@]} devices we plan to sign:"
    printf "  %s\n" "${missing_prior_builds[*]}"
    echo
    confirm "WARNING: Continue without incremental builds for these devices?" || return $?
  fi
}

sort_and_separate_devices_by_key_availability() {
  local device
  local -a device_to_next_build_sorted

  # 1. Sort devices by their order in all_devices
  for device in "${all_devices[@]}"; do
    if [ -n "${device_to_next_build[$device]:-}" ]; then
      device_to_next_build_sorted+=("$device")
    fi
  done

  # 2. Separate into keys that are loaded or not loaded in the HSM.
  local err=
  populate_devices_with_loaded_keys_arrays "${device_to_next_build_sorted[@]}" || err=$?
  if [ -n "$err" ]; then
    {
      echo "Could not determine which devices have keys loaded into the HSM."
      echo "Is the HSM connected?"
    } >&2
    return $err
  fi

  for device in "${devices_with_loaded_keys[@]}"; do
    local next_build=${device_to_next_build[$device]:-}
    if [ -n "$next_build" ]; then
      sign_pairs_with_loaded_keys+=("$device,$next_build")
    fi
    local prev_build=${device_to_prev_build[$device]:-}
    if [ -n "$prev_build" ]; then
      incremental_triples_with_loaded_keys+=("$device,$prev_build,$next_build")
    fi
  done
  for device in "${devices_without_loaded_keys[@]}"; do
    local next_build=${device_to_next_build[$device]:-}
    if [ -n "$next_build" ]; then
      sign_pairs_without_loaded_keys+=("$device,$next_build")
    fi
    local prev_build=${device_to_prev_build[$device]:-}
    if [ -n "$prev_build" ]; then
      incremental_triples_without_loaded_keys+=("$device,$prev_build,$next_build")
    fi
  done
}

final_confirmation() {
  echo
  echo "Here's the plan:"
  maybe_dry_run=echo do_or_show
  echo
  confirm "Ready?" || return $?
}

deduce_build_number() {
  printf "%s\n" "${next_builds_sorted[*]}"
}

deduce_prev_build_number() {
  printf "%s\n" "${prev_builds_sorted[*]}"
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

ask_variable() {
  local var=$1
  local default_val=${2:-}
  local private=${3:-}
  local needs_val=${4:-y}
  if [ -n "${!var:-}" ] || { [ "$needs_val" != "y" ] && [ -n "${!var+x}" ]; }; then
    # Already set.
    if [ "$private" = "y" ]; then
      echo "Using $var from environment."
    else
      echo "Using $var=${!var} from environment."
    fi
    return 0
  fi
  if [ "$private" = "y" ]; then
    private=-s
  else
    private=
  fi
  local prompt="Enter $var"
  if [ -n "$default_val" ]; then
    prompt="$prompt [$default_val]"
    if [ "$needs_val" != "y" ]; then
      prompt="$prompt ("'""'" for none)"
    fi
  fi
  while [ -z "${!var:-}" ]; do
    read -r $private -p "$prompt: " "$var"
    if [ -n "$private" ]; then
      echo
    fi
    declare -g "$var=${!var:-$default_val}"
    if [ "$needs_val" != "y" ]; then
      if [ "${!var}" = '""' ]; then
        declare -g "$var="
      fi
      break
    fi
  done
}

err=0
main "$@" || err=$?
cleanup || true
exit $err
