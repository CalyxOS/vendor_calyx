#!/bin/bash
set -euo pipefail
scriptpath=$(cd "$(dirname "$0")";pwd -P)
source "$scriptpath/common.include.sh" || exit $?
source "$scriptpath/metadata" || exit $?
source "${DEVICES_FILE:-$scriptpath/../../../calyx/scripts/vars/devices}" || exit $?

main() {
  export KEYMAPPER=${KEYMAPPER:-legacy}
  load_keymapper || return $?
  echo "Using keymapper: $KEYMAPPER" >&2
  if [ -z "${devices+x}" ] || [ "${#devices[@]}" -lt 1 ]; then
    echo "ERROR: No defined devices for which to generate keys." >&2
    echo "       Ensure the devices array is populated in \$DEVICES_FILE ($DEVICES_FILE)." >&2
    return 1
  fi
  declare -A already_generated
  printf "%s\t%s\t%s\t%s\n" "ID" "Device" "Key Type" "Key"
  local key_type
  for key_type in "${key_types[@]}"; do
    local array_name
    case "$key_type" in
      avb)
        array_name=keys_avb ;;
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
      per_device=$(get_key_is_per_device_yn "$key_type" "$key" || exit $?) || return $?
      if [ "$per_device" = "n" ]; then
        devices_array=("")
      else
        devices_array=("${devices[@]}")
      fi

      local device
      for device in "${devices_array[@]}"; do
        local value
        value=$(KEY_DIR= DEVICE=$device get_key "$key_type" "$key" || exit $?) || return $?
        if [ -z "$value" ]; then continue; fi
        printf "%s\t%s\t%s\t%s\n" "$value" "$device" "$key_type" "$key"
      done
    done || return $?
  done | sort
}

main "$@"
