#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$0")";pwd -P)
scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
devices_path=$(realpath "$scriptpath/../../../calyx/scripts/vars/devices")

declare -g ORIGINAL_TMPDIR=${TMPDIR:-/dev/shm}
TMPDIR=

declare -ga signable_devices=()
declare -ga target_files=()
declare -ga devices_to_sign=()
declare -gA device_to_prev_build=()
declare -gA build_to_devices=()
declare -ga delta_pairs=()
do_cleanup=

declare -g no_sign=
declare -g no_delta=

PREV_BUILD_NUMBER_PXL="25608200"
PREV_BUILD_NUMBER_MOST="25608210"

source_includes() {
  source "$scriptpath/common.include.sh" || return $?
  source "$pkcs11_scriptpath/include.sh" || return $?
  source "$pkcs11_scriptpath/vendor.yubihsm.include.sh" || return $?
  source "$devices_path" || return $?
  source "$scriptpath/metadata" || return $?
}

prompt_missing_variables() {
  ask_variable BUILD_NUMBER "$(deduce_build_number)" n y || return $?
  ask_variable YUBIHSM_AUTHKEY "0x0001" n y || return $?
  ask_variable YUBIHSM_PASSWORD "" y y || return $?
  ask_variable NUM_SIGN_JOBS "3" n y || return $?
  ask_variable NUM_INCREMENTAL_JOBS "3" n y || return $?
}

main() {
  find_target_files || return $?
  prompt_missing_variables || return $?
  find_prev_signed_device_builds || return $?
  gather_devices_to_sign || return $?
  source_includes || return $?
  load_keymapper || return $?
  gather_signable_devices_from_metadata || return $?
  maybe_handle_already_existing_builds || return $?
  maybe_ask_about_missing_target_files || return $?
  check_free_space || return $?
  initialize || return $?

  if [ "$no_sign" != "y" ]; then
    sign_builds || return $?
  fi

  if [ "$no_delta" != "y" ]; then
    generate_deltas || return $?
  fi

  finish || return $?
}

finish() {
  echo
  echo "Done signing and making deltas for $BUILD_NUMBER"
  echo

  echo "Please minisign -SHm archive/release-*-${BUILD_NUMBER}/*-factory-${BUILD_NUMBER}.zip -t 'CalyxOS x.y.z - [Message goes here]'"
}

sign_builds() {
  # Sign
  local err=
  echo
  echo "Signing release for: ${devices_to_sign[@]}"
  parallel -j "$NUM_SIGN_JOBS" --tag --line-buffer \
    "$pkcs11_scriptpath/vendor.yubihsm.release.sh" "{}" \
      "calyx_{}-target_files-${BUILD_NUMBER}.zip" \
    "&&" mv "out/calyx_{}-target_files-${BUILD_NUMBER}" archive/. \
    ::: "${devices_to_sign[@]}" || err=$?

  if [ -n "$err" ]; then
    echo >&2
    echo "Signing failed for $err devices." >&2
    echo "You can run this script again to sign the devices that failed." >&2
    return 1
  fi

  maybe_stop_apksigner_batch "$STATEDIR" || return $?

  rm -rf "$TMPDIR" || return $?
}

generate_deltas() {
  local err=
  # Deltas
  export TMPDIR=$(mktemp -d -p "${ORIGINAL_TMPDIR:-/dev/shm}" delta_tmp.XXXXXXXX)
  echo
  echo "Generating incremental updates"

  parallel -j "$NUM_DELTA_JOBS" --match '(.*),(.*)' --tag --line-buffer \
    "$pkcs11_scriptpath/vendor.yubihsm.generate_delta.sh" "{1.1}" "{1.2}" ${BUILD_NUMBER} \
    ::: "${delta_pairs[@]}" || err=$?

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
  local estimated_required_free_space=$((20 * ${#devices_to_sign[@]}))
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

gather_devices_to_sign() {
  local file
  for file in "${target_files[@]}"; do
    case "$file" in
      *-$BUILD_NUMBER.zip)
        true ;;  # What we're looking for.
      *)
        continue ;;
    esac
    local device
    device=${file#calyx_}
    device=${device%-target_files-*.zip}
    devices_to_sign+=("$device")
  done
}

maybe_ask_about_missing_target_files() {
  local -a missing_target_files
  mapfile -d "" -t missing_target_files < <(comm -z --nocheck-order -23 \
    <(printf "%s\0" "${signable_devices[@]}" | sort -z) \
    <(printf "%s\0" "${devices_to_sign[@]}" | sort -z)) || return $?
  if [ "${#missing_target_files[@]}" -gt 0 ]; then
    echo
    echo "Out of ${#signable_devices[@]} signable devices, only found "\
"${#devices_to_sign[@]} target files to sign."
    echo "These target files are missing for $BUILD_NUMBER:"
    printf "  %s\n" "${missing_target_files[*]}"
    echo
    confirm "Would you like to continue anyway?" || return $?
  fi
}

maybe_handle_already_existing_builds() {
  if [ -n "${build_to_devices[$BUILD_NUMBER]:-}" ]; then
    echo
    echo "The following devices appear to already be signed for $BUILD_NUMBER (in archive/):"
    printf " %s\n" "${build_to_devices[$BUILD_NUMBER]}"
    echo
    echo "If you continue, these devices will not be signed again."
    echo "(If you want them to be signed again, remove them from archive/ first.)"
    confirm "Would you like to continue?" || return $?
  fi
  local -a these_devices=("${devices_to_sign[@]}")
  devices_to_sign=()
  local device
  for device in "${these_devices[@]}"; do
    if [ "${device_to_prev_build[$device]:-}" != "$BUILD_NUMBER" ]; then
      devices_to_sign+=("$device")
    fi
  done
  if [ "${#devices_to_sign[@]}" = "0" ]; then
    echo
    echo "There is nothing left to sign."
    no_sign=y
    if [ "$no_delta" != "y" ]; then
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
    echo
    echo "Could not find an archive/ directory."
    echo "If you proceed, we will create it, but we will not be able to generate incrementals."
    echo "If this is a mistake, please ensure you are running this script from the proper"
    echo "directory, which should contain an archive/ subdirectory."
    echo
    confirm "Do you want to create archive/ and continue without incrementals?" || return $?
    no_delta=y
    mkdir archive || return $?
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
    delta_pairs+=("$device,$build")
    local current=${build_to_devices[$build]:-}
    if [ -n "$current" ]; then
      build_to_devices[$build]="$current,$device"
    else
      build_to_devices[$build]="$device"
    fi
  done
  local -a builds_in_order
  mapfile -d "" -t builds_in_order < <(printf '%s\0' "${!build_to_devices[@]}" | sort -z -n)
  local any_found=
  echo
  printf "%s\n" "Found the following previous builds:"
  local build
  for build in "${builds_in_order[@]}"; do
    [ -n "$build" ] || continue
    if [ "$BUILD_NUMBER" = "$build" ]; then
      # We'll deal with previous builds matching our current build later.
      continue
    fi
    any_found=y
    printf "  %s: %s\n" "$build" "${build_to_devices[$build]}"
  done
  if [ -z "$any_found" ]; then
    echo "  None."
    confirm "Do you want to proceed without generating incremental builds?" || return $?
    no_delta=y
    delta_pairs=()
    return 0
  fi
}

deduce_build_number() {
  printf "%s\0" "${target_files[@]}" \
    | sed -z -n -e 's/^calyx_.*-target_files-\(.*\)\.zip$/\1/p' \
    | sort -z -n \
    | tail -z -n1 \
    | tr '\0' '\n' \
    || return $?
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
  if [ -n "${!var:-}" ]; then
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
  fi
  while [ -z "${!var:-}" ]; do
    read -r $private -p "$prompt: " "$var"
    if [ -n "$private" ]; then
      echo
    fi
    declare -g "$var=${!var:-$default_val}"
    if [ "$needs_val" != "y" ]; then
      break
    fi
  done
}

err=0
main "$@" || err=$?
cleanup || true
exit $err
