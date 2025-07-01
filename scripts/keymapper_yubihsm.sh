SCRIPTPATH="$(cd "$(dirname "$BASH_SOURCE")";pwd -P)"
source "$SCRIPTPATH/keymapper_modern.sh"

KEY_AVB_VBMETA_PER_DEVICE=y
KEY_AVB_OTHER_PER_DEVICE=n
KEY_AVB_CONSOLIDATION=all
KEY_CORE_RELEASE_IS_AVB_DELEGATED=n
KEY_CORE_PER_DEVICE=n
KEY_APEX_PER_DEVICE=n
KEY_APEX_CONSOLIDATION=single

declare -g -A core_keymap=(
  [media]=device/akita/avb/vbmeta
  [shared]=device/bangkk/avb/vbmeta
  [platform]=device/caiman/avb/vbmeta
  [networkstack]=device/comet/avb/vbmeta
  [bluetooth]=device/comet/avb/vbmeta
  [sdk_sandbox]=device/husky/avb/vbmeta
  [nfc]=device/komodo/avb/vbmeta
)

# Hexadecimal prefix for a key type when the type is shared across devices, or empty if none.
declare -g -A key_type_to_prefix=(
  [avb]="10"
  [core]="11"
  [apex_container]="12"
  [apex_payload]="13"
  [apex_apk]="14"
  [app]="15"
)

# Hexadecimal offset for a key type when per-device.
declare -g -A per_device_key_type_to_offset=(
  [avb]="00"
  [core]="10"
  [apex_container]="30"
  [apex_payload]="80"
  [apex_apk]="d0"
  [app]="00" # N/A
)

declare -g -A key_type_to_array=(
  [avb]=keys_avb_partitions
  [core]=keys_core
  [apex_container]=keys_apex
  [apex_payload]=keys_apex
  [apex_apk]=keys_apex_apk
  [app]=keys_app
)

# ID prefixes
# 00-0f Reserved
#    10 AOSP shared AVB keys (if any)
#    11 AOSP shared core keys
#    12 AOSP shared APEX container keys (single=0x1200)
#    13 AOSP shared APEX payload keys (single=0x1200)
#    14 AOSP shared APEX APK keys (single=0x1200)
#    15 Updatable apps
#    16 F-Droid /other
# 17-1f Reserved
# 20-fe AOSP per-device key prefixes
#       - Segmented as specified in per_device_key_type_to_offset.
#    ff Reserved
device_key_prefix_base=0x20 # as per above, AOSP per-device key prefixes range

_get_key_id_base() {
  local key_type=$1
  local key_name=$2
  local per_device
  per_device=$(get_key_is_per_device_yn "$key_type" "$key_name") || return $?
  if [ "$per_device" = "y" ]; then
    local prefix=${all_devices_id_lookup[$DEVICE]:-}
    if [ -z "$prefix" ]; then
      echo "ERROR: Device '$DEVICE' not found in all_devices array (check metadata file)." >&2
      return 1
    fi
    local offset=${per_device_key_type_to_offset[$key_type]:-}
    if [ -z "$offset" ]; then
      echo "ERROR: Offset not found for key type '$key_type'." >&2
      return 1
    fi
    printf "%x\n" "$((0x$prefix << 8 | 0x$offset))"
  else
    local prefix=${key_type_to_prefix[$key_type]:-}
    if [ -z "$prefix" ]; then
      echo "ERROR: Prefix not found for key type '$key_type'." >&2
      return 1
    fi
    printf "%x\n" "$((0x$prefix << 8))"
  fi
}

get_key_id() {
  local key_type=$1
  local key_name=$2
  local base
  if [ "$key_type" = "avb" ]; then
    case "$KEY_AVB_CONSOLIDATION" in
      all) key_name=vbmeta ;; # every AVB key uses vbmeta key
      delegated|other)
        if [ "$key_name" != "vbmeta" ]; then
          key_name=avb_delegated
        fi ;;
      none) true ;; # all discrete AVB keys
      *) echo "Unknown value for KEY_AVB_CONSOLIDATION." >&2; exit 1 ;;
    esac
  fi
  if [ "$key_type" = "apex_container" ] || [ "$key_type" = "apex_payload" ] || \
     [ "$key_type" = "apex_apk" ]; then
    case "$KEY_APEX_CONSOLIDATION" in
      none) true ;; # change nothing
      combined) key_type=apex_container ;; # just use apex_container
      single) key_type=apex_container; key_name=${keys_apex[0]} ;; # just use the first key
      *) echo "Unknown value for KEY_APEX_CONSOLIDATION." >&2; exit 1 ;;
    esac
  fi
  base=$(_get_key_id_base "$key_type" "$key_name") || return $?
  local array_name=${key_type_to_array[$key_type]:-}
  if [ -z "$array_name" ]; then
    echo "ERROR: Key type '$key_type' is not present in the key_type_to_array map." >&2
    return 1
  fi
  array_name=${array_name}_id_lookup
  local lookup_reference="${array_name}[$key_name]"
  local lookup_result="${!lookup_reference:-}"
  if [ -z "$lookup_result" ]; then
    echo "ERROR: Could not find '$key_name' in our ID lookup map for the '$array_name' array." >&2
    return 1
  fi
  printf "%x\n" "$((0x$base | 0x$lookup_result))"
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

_old_get_key() {
  local key_type=$1
  shift 1
  case "$key_type" in
    avb)
      _get_key_avb "$@" || return $? ;;
    core)
      _get_key_core "$@" || return $? ;;
    apex_container)
      _get_key_apex_container "$@" || return $? ;;
    apex_payload)
      _get_key_apex_payload "$@" || return $? ;;
    apex_apk)
      _get_key_apex_apk "$@" || return $? ;;
    app)
      _get_key_app "$@" || return $? ;;
    *)
      echo "ERROR: Key type '$key_type' is not handled by get_key." >&2
      return 1 ;;
  esac
}

_get_key_core() {
  local key=$(basename "$1")
  if [ "$key" = "testkey" ]; then
    key=releasekey
  fi
  if [ "$key" = "releasekey" ] && [ "$KEY_CORE_RELEASE_IS_AVB_DELEGATED" = "y" ]; then
    _get_key_avb avb_delegated
    return 0
  fi
  local mapped
  mapped=${core_keymap[$key]:-}
  if [ -n "$mapped" ]; then
    key=$mapped
  elif [ "$KEY_CORE_PER_DEVICE" = "y" ]; then
    key=device/$DEVICE/core/$key
  else
    key=shared/core/$key
  fi
  printf "%s\n" "${KEY_DIR}$key"
}

# Create maps that translate a given key into a hexadecimal ID based on the key's position
# in its array in the metadata file.
_generate_key_id_maps() {
  local array_name
  for array_name in "${key_type_to_array[@]}" all_devices; do
    local lookup_array_name=${array_name}_id_lookup
    declare -g -A "${lookup_array_name}=()"
    local array="${array_name}[@]"
    local i=0
    if [ "$array_name" = "all_devices" ]; then
      i=$(($device_key_prefix_base)) # all_devices is used for ID prefixes.
    fi
    local key
    for key in "${!array}"; do
      local id=$(printf "%02x" "$i")
      declare -g "${lookup_array_name}[$key]=$id"
      i=$((i+1))
    done
  done
}
_generate_key_id_maps

# Set AVB custom key path for generate-factory-images-common.sh.
[ -z "${DEVICE:-}" ] || AVB_CUSTOM_KEY=$PWD/$(get_key avb vbmeta).avbpubkey
