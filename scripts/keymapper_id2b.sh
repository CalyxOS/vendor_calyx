# id2b: 2-byte IDs for keys (hexadecimal), suitable e.g. for PKCS#11 devices
# that use such a scheme.

# ID first byte (prefix), as defined in associative arrays and variables below.
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

# ID second byte potentially begins at a given offset, depending on whether it
# is a per-device key. The key is calculated based on its index in its array
# added to that offset. So, with an offset of 00, a key that appears at the top
# of its array (index 0) has a second byte of 00. The eleventh key (index 10)
# is byte 0a.

# You can use generate_keymap.sh to see which IDs are associated with which keys.

### BEGIN CONFIGURABLE SECTION ###
# AOSP per-device key starting prefix, as per above.
device_key_prefix_base=0x20

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

# AVB key consolidation strategy: all, delegated, or none.
#         all: Every AVB partition is signed with the vbmeta key.
#   delegated: The vbmeta partition is signed with the vbmeta key, and a single
#              separate key (ID+1 of the vbmeta key) is used for everything else.
#        none: Every AVB partition is signed with a unique key.
key_avb_consolidation=all

# APEX key consolidation strategy: single, combined, or none.
#     single: A single key is used to sign every APEX container, payload, and APK.
#             The ID used is that of the first APEX container key.
#   combined: Every APEX has a key of its own that is used to sign its container,
#             payload, and APKs.
#       none: Every APEX has a unique key for its container, payload, and APKs.
key_apex_consolidation=single

# For each key type, indicate whether or not its associated keys should be generated
# separately for each device (y) or should instead be shared among all devices (n).
# "releasekey" is handled specially (see releasekey_type and releasekey_name).
declare -g -A key_is_per_device=(
  [avb]=y
  [releasekey]=y
  [core]=n
  [app]=n
  [apex_container]=n
  [apex_payload]=n
  [apex_apk]=n
)

# If set, allows the release key (OTA key) to refer to the same key as some
# other key. With releasekey_type=avb and releasekey_name=vbmeta, the release key
# will be be the same as a device's AVB vbmeta key (avb_custom_key.img).
releasekey_type=avb
releasekey_name=vbmeta
### END CONFIGURABLE SECTION ###

# Mapping of a particular key type to which array (from the metadata file) to use.
declare -g -A key_type_to_array=(
  [avb]=keys_avb_partitions
  [core]=keys_core
  [apex_container]=keys_apex
  [apex_payload]=keys_apex
  [apex_apk]=keys_apex_apk
  [app]=keys_app
)

# Returns true if, within a given key type, a given key name should be
# considered per-device. Contains special handling for the release key.
get_key_is_per_device_yn() {
  local key_type=$1
  local key_name=${2:-}
  local value
  if [ "$key_type" = "core" ] && \
     [ "$key_name" = "build/make/target/product/security/testkey" ]; then
    key_type=${releasekey_type:-$key_type}
    key_name=${releasekey_name:-$key_name}
    value=${key_is_per_device[releasekey]:-${key_is_per_device[$key_type]}}
  else
    value=${key_is_per_device[$key_type]:-}
  fi
  if [ -z "$value" ]; then
    echo "ERROR: Key type '$key_type' is not handled by get_key_type_is_per_device_yn." >&2
    return 1
  fi
  printf "%s\n" "$value"
}

# Returns the base ID for a given key type. The second argument, key name,
# is necessary to aid in determining if it's a per-device key due to the release
# key's special handling.
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

# Returns the key ID for the given key type and key name. This ID may not be unique
get_key_id() {
  local key_type=$1
  local key_name=$2
  local base
  if [ "$key_type" = "avb" ]; then
    case "$key_avb_consolidation" in
      all) key_name=vbmeta ;; # every AVB key uses vbmeta key
      delegated|other)
        if [ "$key_name" != "vbmeta" ]; then
          key_name=${keys_avb_partitions[1]} # just use the second key
        fi ;;
      none) true ;; # all discrete AVB keys
      *) echo "Unknown value '$key_avb_consolidation' for key_avb_consolidation." >&2; exit 1 ;;
    esac
  fi
  if [ "$key_type" = "apex_container" ] || [ "$key_type" = "apex_payload" ] || \
     [ "$key_type" = "apex_apk" ]; then
    case "$key_apex_consolidation" in
      none) true ;; # change nothing
      combined) key_type=apex_container ;; # just use apex_container
      single) key_type=apex_container; key_name=${keys_apex[0]} ;; # just use the first key
      *) echo "Unknown value '$key_apex_consolidation' for key_apex_consolidation." >&2; exit 1 ;;
    esac
  fi
  if [ "$key_type" = "core" ] && \
     [ "$key_name" = "build/make/target/product/security/testkey" ]; then
    key_type=$releasekey_type
    key_name=$releasekey_name
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

fill_avb_arguments() {
  local rsa_key_size
  case "$DEVICE" in
    redfin|bramble)
      rsa_key_size=2048 ;;
    *)
      rsa_key_size=4096 ;;
  esac
  if [ -n "${RSA_KEY_SIZE:-}" ] && [ "$RSA_KEY_SIZE" -lt "$rsa_key_size" ]; then
    rsa_key_size=$RSA_KEY_SIZE
  fi
  avb_algorithm=SHA256_RSA$rsa_key_size
  avb_arguments=()
  for partition in "${keys_avb_partitions[@]}"; do
    avb_arguments+=(
      "--avb_${partition}_key" "$(get_key avb "$partition" "$KEY_SUFFIX")"
      "--avb_${partition}_algorithm" "$avb_algorithm"
    )
  done
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
