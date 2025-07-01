#!/bin/bash
set -euo pipefail
scriptpath=$(cd "$(dirname "$0")";pwd -P)
source "$scriptpath/metadata" || exit $?
source "${DEVICES_FILE:-$scriptpath/../../../calyx/scripts/vars/devices}" || exit $?

load_keymapper() {
  local keymapper_path
  if [ -n "${KEYMAPPER_FILE:-}" ]; then
    keymapper_path=$(cd "$scriptpath"; realpath -e "$KEYMAPPER_FILE") || return $?
  else
    local keymapper=${KEYMAPPER:-legacy}
    keymapper_path=$(cd "$scriptpath"; realpath -e "keymapper.$keymapper.include.sh" || true)
    if [ -z "$keymapper_path" ]; then
      echo "Could not find keymapper '$keymapper'." >&2
      return 1
    fi
  fi
  source "$keymapper_path" || return $?
}

main() {
  KEYMAPPER=${KEYMAPPER:-id2b} load_keymapper
  if [ -z "${devices[@]+x}" ] || [ "${#devices[@]}" -lt 1 ]; then
    echo "ERROR: No defined devices for which to generate keys." >&2
    echo "       Ensure the devices array is populated in \$DEVICES_FILE ($DEVICES_FILE)." >&2
    return 1
  fi
  declare -A already_generated
  # Each key type has an array whose names begins with keys_ defined in metadata.
  # So, keys_avb, keys_core, keys_apex_container, etc.
  local key_types=(
    avb
    core
    apex_container
    apex_payload
    apex_apk
    app
  )
  printf "%s\t%s\t%s\t%s\t%s\t%s\n" "ID" "Device" "Key Type" "Key" "Exportable" "On Demand"
  local key_type
  for key_type in "${key_types[@]}"; do
    local array_name
    case "$key_type" in
      avb)
        array_name=keys_avb_partitions ;;
      apex_container|apex_payload)
        array_name=keys_apex ;;
      *)
        array_name=keys_${key_type} ;;
    esac
    local indirect_array
    indirect_array="${array_name}[@]" || return $?
    local key
    for key in "${!indirect_array}"; do
      # Skip getting key value for each device if it's not a per-device key.
      local -a devices_array
      local per_device=
      per_device=$(get_key_is_per_device_yn "$key_type" "$key")
      if [ "$per_device" = "n" ]; then
        devices_array=("")
      else
        devices_array=("${devices[@]}")
      fi

      local device
      for device in "${devices_array[@]}"; do
        local value exportable ondemand
        value=$(KEY_DIR= DEVICE=$device get_key "$key_type" "$key") || return $?
        #if [ -z "$value" ]; then continue; fi
        exportable=$(DEVICE=$device get_key_id_is_exportable_yn "$value") || return $?
        ondemand=$(DEVICE=$device get_key_id_is_ondemand_yn "$value") || return $?
        printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$value" "$device" "$key_type" "$key" "$exportable" "$ondemand"
      done
    done || return $?
  done | sort
}

main "$@"
