#!/bin/bash
set -euo pipefail
SCRIPTPATH=$(cd "$(dirname "$BASH_SOURCE")";pwd -P)

main() {
  source "$SCRIPTPATH/metadata" || return $?
  source "$SCRIPTPATH/keymapper_yubihsm.sh" || return $?
  source "${DEVICES_FILE:-$SCRIPTPATH/../../../calyx/scripts/vars/devices}" || return $?

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
  printf "%s\t%s\t%s\t%s\n" "ID" "Device" "Key Type" "Key"
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
        devices_array=(any)
      else
        devices_array=("${devices[@]}")
      fi

      local device
      local value
      for device in "${devices_array[@]}"; do
        value=$(KEY_DIR= DEVICE=$device get_key "$key_type" "$key") || return $?
        printf "%s\t%s\t%s\t%s\n" "$value" "$device" "$key_type" "$key"
      done
    done || return $?
  done | sort
}

main "$@"
