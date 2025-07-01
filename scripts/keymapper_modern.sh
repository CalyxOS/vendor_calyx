# Keymapper files are sourced by release.sh.
[ -n "${KEY_DIR+x}" ] || export KEY_DIR=keys/

# Set KEY_SUFFIX= (empty) for no key suffix, e.g. for PKCS#11 key labels.
[ -n "${KEY_SUFFIX+x}" ] || KEY_SUFFIX=.pem
KEY_AVB_VBMETA_PER_DEVICE=n
KEY_AVB_OTHER_PER_DEVICE=n
KEY_AVB_CONSOLIDATION=delegated
KEY_CORE_RELEASE_IS_AVB_DELEGATED=n
KEY_CORE_PER_DEVICE=n
KEY_APEX_PER_DEVICE=n
KEY_APEX_CONSOLIDATION=single

if [ -z "${keys_avb_partitions[@]+x}" ]; then
  echo "ERROR: keys_avb_partitions not found." >&2
  echo "       metadata should be sourced before keymapper." >&2
  exit 1
fi

# Set payload signer max signature size to 512 to accommodate RSA4096 keys.
# Otherwise, a payload_signer crash: padded_signature_size >= signature.size() failed
# If you don't need keys of such size, you can set this to the default of 256.
PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE=512

get_key() {
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

get_key_is_per_device_yn() {
  local key_type=$1
  shift 1
  case "$key_type" in
    avb)
      _get_key_avb "$@" "" per-device ;;
    core)
      echo "$KEY_CORE_PER_DEVICE" ;;
    apex_container|apex_payload|apex_apk)
      echo "$KEY_APEX_PER_DEVICE" ;;
    app)
      echo n ;;
    *)
      echo "ERROR: Key type '$key_type' is not handled by get_key_type_is_per_device_yn." >&2
      return 1 ;;
  esac
}

_get_key_avb() {
  local key=$(basename "$1")
  local suffix=${2:-}
  case "$KEY_AVB_CONSOLIDATION" in
    all)
      key=vbmeta ;;
    delegated|other)
      if [ "$key" != "vbmeta" ]; then
        key=avb_delegated
      fi ;;
    none)
      true ;; # all discrete AVB keys
    *)
      echo "Unknown value for KEY_AVB_CONSOLIDATION." >&2
      exit 1 ;;
  esac
  case "$key" in
    vbmeta)
      per_device=$KEY_AVB_VBMETA_PER_DEVICE ;;
    *)
      per_device=$KEY_AVB_OTHER_PER_DEVICE ;;
  esac
  if [ "${3:-}" = "per-device" ]; then
    printf "%s\n" "$per_device"
    return 0
  fi
  if [ "$per_device" = "y" ]; then
    key=device/$DEVICE/avb/$key
  else
    key=shared/avb/$key
  fi
  printf "%s\n" "${KEY_DIR}$key$suffix"
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
  if [ "$KEY_CORE_PER_DEVICE" = "y" ]; then
    key=device/$DEVICE/core/$key
  else
    key=shared/core/$key
  fi
  printf "%s\n" "${KEY_DIR}$key"
}

_get_key_apex_container() {
  local key=$(basename "$1")
  case "$KEY_APEX_CONSOLIDATION" in
    none)
      key=apex/container/$key ;;
    combined)
      key=apex/$key ;;
    single)
      key=apex/single ;;
  esac
  if [ "$KEY_APEX_PER_DEVICE" = "y" ]; then
    key=device/$DEVICE/$key
  else
    key=shared/$key
  fi
  printf "%s\n" "${KEY_DIR}$key"
}

_get_key_apex_payload() {
  local key=$(basename "$1")
  local suffix=${2:-}
  case "$KEY_APEX_CONSOLIDATION" in
    none)
      key=apex/payload/$key ;;
    combined)
      key=apex/$key ;;
    single)
      key=apex/single ;;
  esac
  if [ "$KEY_APEX_PER_DEVICE" = "y" ]; then
    key=device/$DEVICE/key
  else
    key=shared/$key
  fi
  printf "%s\n" "${KEY_DIR}$key$suffix"
}

_get_key_apex_apk() {
  local key=$(basename "$1")
  case "$KEY_APEX_CONSOLIDATION" in
    none)
      key=apex/apk/$key ;;
    combined)
      key=apex/$key ;;
    single)
      key=apex/single ;;
  esac
  if [ "$KEY_APEX_PER_DEVICE" = "y" ]; then
    key=device/$DEVICE/$key
  else
    key=shared/$key
  fi
  printf "%s\n" "${KEY_DIR}$key"
}

_get_key_app() {
  local key=$(basename "$1")
  key=shared/app/$key
  printf "%s\n" "${KEY_DIR}$key"
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

# Set AVB custom key path for generate-factory-images-common.sh.
[ -z "${DEVICE:-}" ] || AVB_CUSTOM_KEY=$PWD/$(dirname "$(get_key avb vbmeta)")/avb_custom_key.img
