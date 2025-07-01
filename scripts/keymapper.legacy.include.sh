# Keymapper files are sourced by release.sh.
export KEY_DIR=keys/

get_key() {
  local key_type=$1
  shift 1
  if [ "$key_type" = "other" ] && [ "$1" = "ota" ]; then
    _get_key_core build/make/target/product/security/testkey
    return $?
  fi
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

get_key_id_is_ondemand_yn() {
  echo n
}

get_key_id_is_exportable_yn() {
  echo y
}

get_key_id_is_per_device_yn() {
  echo y
}

get_key_is_per_device_yn() {
  local key_type=$1
  local key_name=${2:-}
  if [ "$key_type" = "other" ] && [ "$key_name" = "ota" ]; then
    echo y
    return 0
  fi
  case "$key_type" in
    app)
      echo n ;;
    avb|core|apex_container|apex_payload|apex_apk)
      echo y ;;
    *)
      echo "ERROR: Key type '$key_type' is not handled by get_key_is_per_device_yn." >&2
      return 1 ;;
  esac
}

_get_key_avb() {
  local key_suffix=.pem
  [ -z "${KEY_SUFFIX+x}" ] || key_suffix=$KEY_SUFFIX
  printf "%s\n" "$KEY_DIR$DEVICE/avb$key_suffix"
}

_get_key_core() {
  local key=$(basename "$1")
  if [ "$key" = "testkey" ] || [ "$key" = "devkey" ]; then
    key=releasekey
  fi
  printf "%s\n" "$KEY_DIR$DEVICE/${core_key[$key]:-$key}"
}

_get_key_apex_container() {
  local key=$(basename "$1")
  printf "%s\n" "$KEY_DIR$DEVICE/${apex_container_key[$key]:-$key}"
}

_get_key_apex_payload() {
  local key=$(basename "$1")
  local key_suffix=.pem
  [ -z "${KEY_SUFFIX+x}" ] || key_suffix=$KEY_SUFFIX
  printf "%s\n" "$KEY_DIR$DEVICE/${apex_payload_key[$key]:-$key}${key_suffix}"
}

_get_key_apex_apk() {
  local key=$1
  if [ "$key" = "device/google/gs-common/uwb-certs/com.qorvo.uwb" ]; then
    case "$DEVICE" in
      raven|cheetah|tangorpro|felix)
        true ;; # Only map this key for these devices.
      *)
        return 0 ;; # Output nothing to indicate we do not want to map this key.
    esac
  fi
  printf "%s\n" "$KEY_DIR$DEVICE/${apex_apk_key[$key]:-$key}"
}

_get_key_app() {
  local key=$1
  printf "%s\n" "${KEY_DIR}common/${app_key[$key]:-$(basename "$key")}"
}

fill_avb_arguments() {
  case "$DEVICE" in
    redfin|bramble)
      avb_arguments=(--avb_vbmeta_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_algorithm SHA256_RSA2048
                     --avb_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_algorithm SHA256_RSA2048
                     --avb_vbmeta_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA2048)
      ;;
    barbet|FP4|FP5|devon|hawao|rhode|fogos|bangkk|fogo|otter)
      avb_arguments=(--avb_vbmeta_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                     --avb_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_algorithm SHA256_RSA4096
                     --avb_vbmeta_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096)
      ;;
    oriole|raven|bluejay)
      avb_arguments=(--avb_vbmeta_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                     --avb_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_algorithm SHA256_RSA4096
                     --avb_system_other_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_other_algorithm SHA256_RSA4096
                     --avb_vbmeta_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096
                     --avb_vbmeta_vendor_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_vendor_algorithm SHA256_RSA4096
                     --avb_boot_key "$KEY_DIR$DEVICE/avb.pem" --avb_boot_algorithm SHA256_RSA4096)
      ;;
    panther|cheetah|lynx|tangorpro|felix|shiba|husky|akita|tokay|caiman|komodo|comet|tegu)
      avb_arguments=(--avb_vbmeta_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                     --avb_system_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_algorithm SHA256_RSA4096
                     --avb_system_other_key "$KEY_DIR$DEVICE/avb.pem" --avb_system_other_algorithm SHA256_RSA4096
                     --avb_vbmeta_system_key "$KEY_DIR$DEVICE/avb_vbmeta_system.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096
                     --avb_vbmeta_vendor_key "$KEY_DIR$DEVICE/avb.pem" --avb_vbmeta_vendor_algorithm SHA256_RSA4096
                     --avb_boot_key "$KEY_DIR$DEVICE/avb.pem" --avb_boot_algorithm SHA256_RSA4096
                     --avb_init_boot_key "$KEY_DIR$DEVICE/avb.pem" --avb_init_boot_algorithm SHA256_RSA4096)
      ;;
  esac
}

declare -gA core_key=(
  [bluetooth]=com.android.bluetooth
  [nfc]=com.android.nfcservices
)

declare -gA apex_container_key=(
  [com.android.tethering]=releasekey
  [com.android.support.apexer]=releasekey
  [com.android.hardware.biometrics.face.virtual]=com.android.hardware
  [com.android.resolv]=testcert
  [com.android.bluetooth]=com.android.btservices
  [com.android.hardware.biometrics.fingerprint.virtual]=com.android.hardware
  [com.android.ondevicepersonalization]=releasekey
  [com.android.vndk.current.on_vendor]=com.android.vndk.current
  [com.android.scheduling]=releasekey
  [com.android.hardware.cas]=com.android.hardware
)

declare -gA apex_payload_key=(
  [com.android.hardware.biometrics.face.virtual]=com.android.hardware
  [com.android.bluetooth]=com.android.btservices
  [com.android.hardware.biometrics.fingerprint.virtual]=com.android.hardware
  [com.android.vndk.current.on_vendor]=com.android.vndk.current
  [com.android.hardware.cas]=com.android.hardware
)

declare -gA apex_apk_key=(
  [packages/modules/Connectivity/service/ServiceConnectivityResources/resources-certs/com.android.connectivity.resources]=com.android.connectivity.resources
  [packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin]=com.android.hotspot2.osulogin
  [packages/modules/Wifi/service/ServiceWifiResources/resources-certs/com.android.wifi.resources]=com.android.wifi.resources
  [packages/modules/AdServices/adservices/apk/com.android.adservices.api]=com.android.adservices.api
  [packages/modules/Bluetooth/android/app/certs/com.android.bluetooth]=com.android.bluetooth
  [packages/modules/Permission/SafetyCenter/Resources/com.android.safetycenter.resources]=com.android.safetycenter.resources
  [packages/modules/Wifi/WifiDialog/certs/com.android.wifi.dialog]=com.android.wifi.dialog
  [packages/modules/Uwb/service/ServiceUwbResources/resources-certs/com.android.uwb.resources]=com.android.uwb.resources
  [packages/modules/Connectivity/nearby/halfsheet/apk-certs/com.android.nearby.halfsheet]=com.android.nearby.halfsheet
  [packages/providers/MediaProvider/pdf/apk/com.android.graphics.pdf]=com.android.graphics.pdf
  [packages/modules/AppSearch/apk/com.android.appsearch.apk]=com.android.appsearch.apk
  [packages/modules/HealthFitness/apk/com.android.healthconnect.controller]=com.android.healthconnect.controller
  [packages/modules/HealthFitness/backuprestore/com.android.health.connect.backuprestore]=com.android.health.connect.backuprestore
  [packages/modules/OnDevicePersonalization/federatedcompute/apk/com.android.federatedcompute]=com.android.federatedcompute
  # Device-specific: raven, cheetah, tangorpro, felix.
  # (It doesn't hurt to override/generate it anyway.)
  [device/google/gs-common/uwb-certs/com.qorvo.uwb]=com.qorvo.uwb
)

declare -gA app_key=(
  [prebuilts/calyx/microg/certs/microg]=microg
  [external/calyx/chromium/certs/chromium]=chromium
)

get_key_type_name_pairs_for_id() {
  echo "get_key_type_name_pairs_for_id is not implemented for the legacy keymapper" >&2
  return 1
}

initialize_keymapper() {
  # Set AVB custom key path for generate-factory-images-common.sh.
  [ -z "${DEVICE:-}" ] || declare -g AVB_CUSTOM_KEY=$PWD/$(dirname "$(get_key avb vbmeta)")/avb_custom_key.img
}
