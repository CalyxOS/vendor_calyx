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
#    16 F-Droid / other
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
device_key_prefix_start=0x20
device_key_prefix_end=0xfe

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
#       dual: One key is used to sign every APEX container and APK, and another is
#             used to sign every payload.
#     triple: One key for APEX containers, one for payloads, and one for APKs.
#   combined: Every APEX has a key of its own that is used to sign its container,
#             payload, and APKs.
#       none: Every APEX has a unique key for its container, payload, and APKs.
key_apex_consolidation=dual

# For each key type, indicate whether or not its associated keys should be generated
# separately for each device (y) or should instead be shared among all devices (n).
# "ota" is handled specially (see ota_key_type and ota_key_name).
declare -g -A key_is_per_device=(
  [avb]=y
  [ota]=y
  [release]=y
  [core]=n
  [app]=n
  [apex_container]=n
  [apex_payload]=n
  [apex_apk]=n
)

# If set, allows the OTA key to refer to the same key as some other key.
# With ota_key_type=avb and ota_key_name=vbmeta, the OTA key will be the
# same as a device's AVB vbmeta key (avb_custom_key.img).
ota_key_type=avb
ota_key_name=vbmeta

release_key_type=avb
release_key_name=vbmeta

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

declare -g -A key_id_to_type_and_name_pairs=()

# Returns true if the key ID provided is within a range eligible to be exported.
get_key_id_is_exportable_yn() {
  # At the moment, everything should be exportable until there is further testing and
  # validation that key rotation works, and a known-working process. It seems that
  # rotating core keys can lead to problems if done as a simple replacement, such as
  # platform apps not working. There are ways around this, as mentioned on the LineageOS
  # wiki for example, but it's not a sure- and secure-enough thing to go for right now.
  # Once we figure it out, we can always rotate the relevant keys and make non-exportable.
  # TODO: The above.
  echo y
  return 0
  # Core keys are not exportable for transparency reasons.
  # Core keys can be rotated, so they do not need to be exported. This provides an assurance
  # that the same HSM has been used to sign everything that uses these important core keys,
  # as the attestation will show that the key was generated on device and not exportable.
  # This makes it possible to determine if the secondary HSM - or any other device - is used
  # for signing these components, which could provide a clue in case somehow the keys are
  # used without proper authorization.
  local key_id=$1
  local ota_key_id
  local key_lookup=${key_id_to_type_and_name_pairs[$key_id]:-}
  local pair
  if [ -z "$key_lookup" ]; then
    echo "ERROR: get_key_id_is_exportable_yn: Could not find key information for key ID $key_id." >&2
    return 1
  fi
  local exportable=y
  local oldIFS=$IFS
  IFS=$'\t'; set -- $key_lookup; IFS=$oldIFS
  for pair in "$@"; do
    case "$pair" in
      avb:*|ota:*)
        # AVB cannot be rotated, and OTA needs the prior key to be rotated,
        # so these keys are essential and we cannot do without a backup.
        exportable=y
        break ;;
      core:*)
        # A key ID that solely represents a core key is not exportable because
        # these keys can be rotated without requiring the old keys.
        # TODO: How exactly? In recent testing, it is broken thanks to SELinux, with
        #       platform apps like Settings crashing. In earlier testing, it was fine...
        exportable=n ;;
      *)
        # It's exportable if it represents anything else.
        exportable=y
        break ;;
    esac
  done
  echo $exportable
}

# Returns true if the key ID provided is within the range designated for on-demand keys,
# meaning the key has been exported under wrap and can be removed and re-imported to the
# HSM any time in order to make room for other keys as needed.
get_key_id_is_ondemand_yn() {
  get_key_id_is_per_device_yn "$@" || return $?
}

# Returns true if the key ID provided is within the range designated for per-device keys.
get_key_id_is_per_device_yn() {
  local key_id=$1
  local key_id_decimal
  local start_decimal
  local end_decimal
  key_id_decimal=$(($key_id))
  start_decimal=$(($device_key_prefix_start << 8))
  end_decimal=$(($device_key_prefix_end << 8 | 0xff))
  if [ "$key_id_decimal" -ge "$start_decimal" ] && [ "$key_id_decimal" -le "$end_decimal" ]; then
    echo y
  else
    echo n
  fi
}

# Returns true if, within a given key type, a given key name should be
# considered per-device. Contains special handling for the OTA key.
get_key_is_per_device_yn() {
  local key_type=$1
  local key_name=${2:-}
  local value
  if [ "$key_type" = "other" ] && \
     [ "$key_name" = "ota" ]; then
    key_type=${ota_key_type:-$key_type}
    key_name=${ota_key_name:-$key_name}
    value=${key_is_per_device[ota]:-${key_is_per_device[$key_type]}}
  else
    value=${key_is_per_device[$key_type]:-}
  fi
  if [ "$key_type" = "core" ] && \
     { [ "$key_name" = "build/make/target/product/security/testkey" ] ||
       [ "$key_name" = "build/make/target/product/security/devkey" ]; }; then
    key_type=${release_key_type:-$key_type}
    key_name=${release_key_name:-$key_name}
    value=${key_is_per_device[release]:-${key_is_per_device[$key_type]}}
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
# is necessary to aid in determining if it's a per-device key due to the ota key's
# special handling.
_get_key_id_base() {
  local key_type=$1
  local key_name=$2
  local per_device
  per_device=$(get_key_is_per_device_yn "$key_type" "$key_name") || return $?
  if [ "$per_device" = "y" ]; then
    local prefix=${all_devices_id_lookup[$DEVICE]:-}
    if [ -z "$prefix" ]; then
      echo "ERROR: Device '$DEVICE' not found in all_devices array (check metadata file)" >&2
      echo "       while looking up key type '$key_type' name '$key_name'." >&2
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

# Returns the key ID for the given key type and key name. This ID may not be unique.
get_key_id() {
  local key_type=$1
  local key_name=$2
  local base
  if [ "$key_type" = "avb" ]; then
    case "$key_avb_consolidation" in
      all) key_name=vbmeta ;; # every AVB key uses vbmeta key
      delegated|other)
        if [ "$key_name" != "vbmeta" ]; then
          key_name=${keys_avb[1]} # just use the second key
        fi ;;
      none) true ;; # all discrete AVB keys
      *) echo "Unknown value '$key_avb_consolidation' for key_avb_consolidation." >&2; exit 1 ;;
    esac
  elif [ "$key_type" = "apex_container" ] || [ "$key_type" = "apex_payload" ] || \
       [ "$key_type" = "apex_apk" ]; then
    case "$key_apex_consolidation" in
      none) true ;; # change nothing
      combined) key_type=apex_container ;; # just use apex_container
      single) key_type=apex_container; key_name=${keys_apex[0]} ;; # just use the first key
      dual)
        if [ "$key_type" = "apex_container" ] || [ "$key_type" = "apex_apk" ]; then
          key_type=apex_container
        fi
        key_name=${keys_apex[0]} ;;
      triple)
        key_name=${keys_apex[0]} ;;
      *) echo "Unknown value '$key_apex_consolidation' for key_apex_consolidation." >&2; exit 1 ;;
    esac
  elif [ "$key_type" = "core" ] && \
     { [ "$key_name" = "build/make/target/product/security/testkey" ] ||
       [ "$key_name" = "build/make/target/product/security/devkey" ]; }; then
    key_type=${release_key_type:-core}
    key_name=${release_key_name:-build/make/target/product/security/testkey}
  elif [ "$key_type" = "other" ] && [ "$key_name" = "ota" ]; then
    key_type=${ota_key_type:-core}
    key_name=${ota_key_name:-build/make/target/product/security/testkey}
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
  printf "0x%x\n" "$((0x$base | 0x$lookup_result))"
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
  for partition in "${keys_avb[@]}"; do
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
      i=$(($device_key_prefix_start)) # all_devices is used for ID prefixes.
    fi
    local key
    for key in "${!array}"; do
      local id=$(printf "%02x" "$i")
      declare -g "${lookup_array_name}[$key]=$id" || return $?
      i=$((i+1))
    done
  done
}

_generate_reverse_key_id_map() {
  local -a devices_to_use
  if [ -z "${devices+x}" ] || [ "${#devices[@]}" = "0" ]; then
    devices_to_use=("${all_devices[@]}")
  else
    devices_to_use=("${devices[@]}")
  fi
  local key_type
  for key_type in "${!key_type_to_array[@]}"; do
    local array_name
    array_name=${key_type_to_array[$key_type]} || return $?
    local array="${array_name}[@]"
    local key
    # Device does not really matter, so use the first one.
    local first_device=${all_devices[0]}
    for key in "${!array}"; do
      local key_id
      local is_per_device
      is_per_device=$(get_key_is_per_device_yn "$key_type" "$key") || return $?
      local device
      for device in "${devices_to_use[@]}"; do
        key_id=$(DEVICE=$device get_key_id "$key_type" "$key") || return $?
        local new_map_value
        new_map_value="${key_id_to_type_and_name_pairs[$key_id]:-}"$'\t'"$key_type:$key"
        new_map_value=${new_map_value#$'\t'}
        key_id_to_type_and_name_pairs[$key_id]=$new_map_value
        if [ "$is_per_device" = "n" ]; then
          break
        fi
      done
    done
  done
}

_ensure_all_devices_contains_devices() {
  if [ -n "${devices+x}" ]; then
    local missing_devices
    local err
    missing_devices=$(comm --nocheck-order -23 \
      <(printf "%s\n" "${devices[@]}" | sort) \
      <(printf "%s\n" "${all_devices[@]}" | sort)) || return $?
    if [ -n "$missing_devices" ]; then
      echo "devices array contains the following entries missing from all_devices:" >&2
      printf "  %s\n" "$missing_devices" >&2
      echo >&2
      echo "Please update the all_devices array in the metadata file to include them." >&2
      return 1
    fi
  else
    echo "Warning: Keymapper initialization cannot validate metadata's all_devices array" >&2
    echo "         because devices array is not yet populated." >&2
  fi
}

# Result is key_type:key_name pairs, separated by tabs.
get_key_type_and_name_pairs_for_id() {
  local key_id=$1
  local key_lookup=${key_id_to_type_and_name_pairs[$key_id]:-}
  if [ -z "$key_lookup" ]; then
    echo "ERROR: get_key_type_and_name_pairs_for_id: Could not find key information for key ID $key_id." >&2
    return 1
  fi
  printf "%s\n" "$key_lookup"
}

initialize_keymapper() {
  local err
  if [ -z "${devices+x}" ] || [ "${#devices[@]}" = "0" ]; then
    # TODO: This can probably be better...
    local devices_path=$(dirname "$BASH_SOURCE")/../../../calyx/scripts/vars/devices
    source <(cat "$devices_path" | sed -e 's/^readonly /declare -g /') || true
  fi
  _generate_key_id_maps \
    || { err=$?; echo "Failed to generate ID maps." >&2; return $err; }
  _generate_reverse_key_id_map \
    || { err=$?; echo "Failed to generate reverse ID map." >&2; return $err; }
  (_ensure_all_devices_contains_devices) \
    || { err=$?; echo "Failed to validate all_devices array." >&2; return $err; }

  local per_device
  per_device=$(get_key_is_per_device_yn avb vbmeta) || return $?

  if [ -n "${DEVICE:-}" ] || [ "$per_device" = "n" ]; then
    local avb_key
    avb_key=$(get_key avb vbmeta) \
      || { err=$?; echo "Failed to determine a key to use for AVB_CUSTOM_KEY."; return $err; }
    # Set AVB custom key path for generate-factory-images-common.sh.
    [ -z "${DEVICE:-}" ] || declare -g AVB_CUSTOM_KEY=$PWD/$avb_key.avbpubkey
  else
    declare -g AVB_CUSTOM_KEY=/nonexistent
  fi
}
