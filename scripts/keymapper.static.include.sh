#!/bin/bash
# Use generate_keymap.sh to create a static keymap based on a given KEYMAPPER.
# Example: KEYMAPPER=id2b vendor/calyx/scripts/generate_keymap.sh > keymap.tsv
# Then, to use this keymapper with that static output:
# export KEYMAPPER=static
# export KEYMAP_FILE=keymap.tsv

### BEGIN CONFIGURABLE SECTION ###
# Set payload signer max signature size to 512 to accommodate RSA4096 keys.
# Otherwise, a payload_signer crash: padded_signature_size >= signature.size() failed.
# If you don't need keys of such size, you can set this to the default of 256.
PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE=512
### END CONFIGURABLE SECTION ###

# Keymapper files are sourced by release.sh.
[ -n "${KEY_DIR+x}" ] || export KEY_DIR=keys
[ -z "$KEY_DIR" ] || export KEY_DIR=${KEY_DIR%/}/

# Set KEY_SUFFIX= (empty) for no key suffix, e.g. for PKCS#11 key labels.
[ -n "${KEY_SUFFIX+x}" ] || KEY_SUFFIX=.pem

# IMPORTANT: This map may be read directly by vendor-specific scripts for convenience.
declare -g -A device_specific_key_ids_map=()

# Returns true if the key ID provided is within the range designated for per-device keys.
get_key_id_is_per_device_yn() {
  local key_id=$1
  local lines

  # tail -n+2: Skip the first line of the keymap file, as it is the header.
  # grep [...]: Limit the lines to ones containing the key ID followed by a tab.
  #             (Confirmed later since this does not check from the beginning of the line.)
  # sed [...]: To accommodate parsing, replace empty fields with "", which we will treat as empty.
  #            The approach using IFS and the set command treat multiple tabs as a single delimiter,
  #            so this works around that.
  mapfile -t lines < <(tail -n+2 "$KEYMAP_FILE" | grep -F -- "$key_id"$'\t' \
    | sed -e 's/\t\t/\t""\t/g' || exit $?) || return $?
  local line
  for line in "${lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    local line_key_id=${1:-}
    local line_device=${2:-}
    [ "$line_key_id" != '""' ] || line_key_id=
    [ "$line_device" != '""' ] || line_device=
    if [ "$line_key_id" = "$key_id" ] && [ -n "$line_device" ]; then
      echo y
      return 0
    fi
  done
  echo n
}

# Returns true if, within a given key type, a given key name should be
# considered per-device. Contains special handling for the release key.
# Also contains special handling for the OTA key, which may be different.
get_key_is_per_device_yn() {
  local key_type=$1
  local key_name=$2
  if [ "$key_name" = "build/make/target/product/security/devkey" ]; then
    key_name=build/make/target/product/security/testkey
  fi
  local lines
  # grep [...]: Limit the lines to ones containing fields with this key type and key name,
  #             confirmed later since this checks any arbitrary part of the line.
  mapfile -t lines < <(tail -n+2 "$KEYMAP_FILE" | grep -F -- $'\t'"$key_type"$'\t'"$key_name" \
    | sed -e 's/\t\t/\t""\t/g' || exit $?) || return $?
  local line
  local found_any=
  for line in "${lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    local line_key_id=${1:-}
    local line_device=${2:-}
    local line_key_type=${3:-}
    local line_key_name=${4:-}
    [ "$line_key_id" != '""' ] || line_key_id=
    [ "$line_device" != '""' ] || line_device=
    [ "$line_key_type" != '""' ] || line_key_type=
    [ "$line_key_name" != '""' ] || line_key_name=
    if [ "$line_key_type" = "$key_type" ] && [ "$line_key_name" = "$key_name" ]; then
      if [ -n "$line_device" ]; then
        echo y
        return 0
      fi
      found_any=y
    fi
  done
  if [ -z "$found_any" ]; then
    echo "Could not find key type '$key_type' name '$key_name' in KEYMAP_FILE '$KEYMAP_FILE'" >&2
    return 1
  fi
  echo n
}

# Returns the key ID for the given key type and key name. This ID may not be unique.
get_key_id() {
  local key_type=$1
  local key_name=$2
  if [ "$key_name" = "build/make/target/product/security/devkey" ]; then
    key_name=build/make/target/product/security/testkey
  fi
  local lines
  # grep [...]: Limit the lines to ones containing fields with this key type and key name,
  #             confirmed later since this checks any arbitrary part of the line.
  mapfile -t lines < <(tail -n+2 "$KEYMAP_FILE" | grep -F -- $'\t'"$key_type"$'\t'"$key_name" \
    | sed -e 's/\t\t/\t""\t/g' || exit $?) || return $?
  local line
  for line in "${lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    local line_key_id=${1:-}
    local line_device=${2:-}
    local line_key_type=${3:-}
    local line_key_name=${4:-}
    [ "$line_key_id" != '""' ] || line_key_id=
    [ "$line_device" != '""' ] || line_device=
    [ "$line_key_type" != '""' ] || line_key_type=
    [ "$line_key_name" != '""' ] || line_key_name=
    if [ "$line_key_type" = "$key_type" ] && [ "$line_key_name" = "$key_name" ] && \
        { [ -z "$line_device" ] || [ "$line_device" = "${DEVICE:-}" ]; }; then
      printf "%s\n" "$line_key_id"
      return 0
    fi
  done
  return 1
}

get_key() {
  local key_type=$1
  local key_name=$2
  local suffix=${3:-}
  case "$key_type" in
    apex_payload|avb)
      true ;; # keep suffix for these, if any
    *)
      suffix= ;; # no suffix for others
  esac
  local key_id
  key_id=$(get_key_id "$key_type" "$key_name") || return $?
  printf "%s\n" "${KEY_DIR}${key_id}$suffix"
}

fill_avb_arguments() {
  local avb_algorithm=SHA256_RSA${AVB_RSA_KEY_SIZE:-${RSA_KEY_SIZE:-4096}}
  avb_arguments=()
  for partition in "${keys_avb[@]}"; do
    local avb_algorithm
    if declare -F get_key_algorithm >/dev/null; then
      avb_algorithm=$(get_key_algorithm avb "$partition")
      case "$avb_algorithm" in
        RSA:*)
          # RSA:4096 becomes SHA256_RSA4096
          avb_algorithm=SHA256_${avb_algorithm/:/} ;;
        *)
          echo "Unexpected AVB algorithm '$avb_algorithm' for $partition" >&2
          return 1 ;;
      esac
    fi
    avb_arguments+=(
      "--avb_${partition}_key" "$(get_key avb "$partition" "$KEY_SUFFIX")"
      "--avb_${partition}_algorithm" "$avb_algorithm"
    )
  done
}

# Result is key_type:key_name pairs, separated by tabs.
get_key_type_and_name_pairs_for_id() {
  local key_id=$1
  local pairs=
  local lines
  # grep [...]: Limit the lines to ones containing the key ID followed by a tab.
  #             (Confirmed later since this does not check from the beginning of the line.)
  mapfile -t lines < <(tail -n+2 "$KEYMAP_FILE" | grep -F -- "$key_id"$'\t' \
    | sed -e 's/\t\t/\t""\t/g' || exit $?) || return $?
  local line
  for line in "${lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    local line_key_id=${1:-}
    local line_device=${2:-}
    [ "$line_key_id" != '""' ] || line_key_id=
    [ "$line_device" != '""' ] || line_device=
    if [ "$key_id" != "$line_key_id" ] || \
        { [ -n "$line_device" ] && [ "$line_device" != "${DEVICE:-}" ]; }; then
      continue
    fi
    local line_key_type=${3:-}
    local line_key_name=${4:-}
    pairs=$pairs$'\t'$line_key_type:$line_key_name
    pairs=${pairs#$'\t'}
  done
  printf "%s\n" "$pairs"
}

has_device_specific_key_ids_map() {
  true
}

_generate_device_specific_key_ids_map() {
  # grep [...]: Find lines that have a filled device field.
  mapfile -t lines < <(tail -n+2 "$KEYMAP_FILE" | grep $'^[^\t]*\t[^\t]\+' \
    | sed -e 's/\t\t/\t""\t/g' || exit $?) || return $?
  local line
  for line in "${lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    local line_key_id=${1:-}
    local line_device=${2:-}
    local line_key_type=${3:-}
    local line_key_name=${4:-}
    [ "$line_key_id" != '""' ] || line_key_id=
    [ "$line_device" != '""' ] || line_device=
    [ "$line_key_type" != '""' ] || line_key_type=
    [ "$line_key_name" != '""' ] || line_key_name=
    if [ -z "$line_device" ]; then
      echo "No device on this line. Impossible..." >&2
      return 1
    fi
    local current_map_value=${device_specific_key_ids_map[$line_device]:-}
    case "$current_map_value" in
      *$'\t'"$line_key_id"$'\t'*)
        true ;; # Already in there.
      "")
        device_specific_key_ids_map[$line_device]=$'\t'"$line_key_id"$'\t' ;;
      *)
        device_specific_key_ids_map[$line_device]=$current_map_value$line_key_id$'\t' ;;
    esac
  done
}

initialize_keymapper() {
  if [ -z "${KEYMAP_FILE:-}" ]; then
    echo "Please set KEYMAP_FILE to a tab-separated values file generated by generate_keymap.sh" >&2
    return 1
  fi
  if [ ! -e "$KEYMAP_FILE" ]; then
    echo "Cannot find KEYMAP_FILE $KEYMAP_FILE" >&2
    return 1
  fi
  _generate_device_specific_key_ids_map || return $?
}
