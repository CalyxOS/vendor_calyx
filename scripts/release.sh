#!/bin/bash
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 device [target-files.zip]"
  exit 1
}

[[ $# -le 2 ]] || error "incorrect number of arguments"
[[ -n $BUILD_NUMBER ]] || error "BUILD_NUMBER not set, did you source envsetup.sh ?"

source device/common/clear-factory-images-variables.sh

DEVICE=$1
PRODUCT=$1
KEY_DIR=keys/$DEVICE
OUT=out/release-$DEVICE-$BUILD_NUMBER
BUILD=$BUILD_NUMBER
SIGNED_TARGET_FILES=$OUT/$DEVICE-target_files-$BUILD.zip

if [[ -z $2 ]] ; then
  TARGET_FILES=out/target/product/$DEVICE/obj/PACKAGING/target_files_intermediates/calyx_$DEVICE-target_files-$BUILD.zip
  RELEASETOOLS_PATH=build/tools
else
  TARGET_FILES=$2
  # For usage with otatools.zip
  RELEASETOOLS_PATH="$(pwd -P)"
  EXTRA_RELEASETOOLS_ARGS="-p $RELEASETOOLS_PATH"
fi

VERSION=$(unzip -c $TARGET_FILES SYSTEM/build.prop | grep "ro.build.id=" | cut -d = -f 2 | tr '[:upper:]' '[:lower:]')

if [[ $DEVICE == marlin || $DEVICE == sailfish || $DEVICE == taimen || $DEVICE == walleye ||
	$DEVICE == blueline || $DEVICE == crosshatch || $DEVICE == sargo || $DEVICE == bonito ||
	$DEVICE == coral || $DEVICE == flame || $DEVICE == sunfish ||
  $DEVICE == redfin || $DEVICE == bramble || $DEVICE == barbet ||
  $DEVICE == oriole || $DEVICE == raven || $DEVICE == bluejay ||
  $DEVICE == panther || $DEVICE == cheetah || $DEVICE == lynx ||
  $DEVICE == felix || $DEVICE == husky || $DEVICE == shiba ]]; then
  BOOTLOADER=$(unzip -c $TARGET_FILES OTA/android-info.txt | grep version-bootloader | cut -d = -f 2)
  BOOTLOADERSRC=bootloader-${DEVICE}-${BOOTLOADER,,}.img
  RADIO=$(unzip -c $TARGET_FILES OTA/android-info.txt | grep version-baseband | cut -d = -f 2)
  RADIOSRC=radio-${DEVICE}-${RADIO,,}.img
elif [[ $DEVICE == tangorpro ]]; then
  BOOTLOADER=$(unzip -c $TARGET_FILES OTA/android-info.txt | grep version-bootloader | cut -d = -f 2)
  BOOTLOADERSRC=bootloader-${DEVICE}-${BOOTLOADER,,}.img
elif [[ $DEVICE == jasmine_sprout ]]; then
  MI_A2="true"
elif [[ $DEVICE == FP4 ]]; then
  FP4="true"
elif [[ $DEVICE == FP5 ]]; then
  FP5="true"
elif [[ $DEVICE == axolotl ]]; then
  AXOLOTL="true"
  FASTBOOT_PRODUCT="sdm845"
elif [[ $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ]]; then
  MOTO="true"
elif [[ $DEVICE == kebab || $DEVICE == lemonade || $DEVICE == lemonadep ]]; then
  : # Do nothing, for now.
else
  error "Unsupported device $DEVICE"
fi

mkdir -p $OUT || exit 1

if [[ $DEVICE == marlin || $DEVICE == sailfish || $DEVICE == jasmine_sprout ]]; then
  VERITY_SWITCHES=(--replace_verity_public_key "$KEY_DIR/verity_key.pub" --replace_verity_private_key "$KEY_DIR/verity"
                   --replace_verity_keyid "$KEY_DIR/verity.x509.pem")
elif [[ $DEVICE == blueline || $DEVICE == crosshatch || $DEVICE == sargo || $DEVICE == bonito ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA2048
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA2048)
  EXTRA_OTA_ARGS="--retrofit_dynamic_partitions"
elif [[ $DEVICE == taimen || $DEVICE == walleye ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA2048)
elif [[ $DEVICE == coral || $DEVICE == flame || $DEVICE == sunfish ||
  $DEVICE == redfin || $DEVICE == bramble ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA2048
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA2048
                   --avb_vbmeta_system_key "$KEY_DIR/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA2048)
elif [[ $DEVICE == barbet || $DEVICE == FP4 || $DEVICE == FP5 || $DEVICE == kebab || $DEVICE == lemonade || $DEVICE == lemonadep ||
  $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_system_key "$KEY_DIR/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096)
elif [[ $DEVICE == axolotl ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_system_key "$KEY_DIR/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_vendor_key "$KEY_DIR/avb.pem" --avb_vbmeta_vendor_algorithm SHA256_RSA4096)
elif [[ $DEVICE == oriole || $DEVICE == raven || $DEVICE == bluejay ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_system_key "$KEY_DIR/avb.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_vendor_key "$KEY_DIR/avb.pem" --avb_vbmeta_vendor_algorithm SHA256_RSA4096
                   --avb_boot_key "$KEY_DIR/avb.pem" --avb_boot_algorithm SHA256_RSA4096)
elif [[ $DEVICE == cheetah || $DEVICE == panther || $DEVICE == lynx || $DEVICE == tangorpro || $DEVICE == felix ||
  $DEVICE == husky || $DEVICE == shiba ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA4096
                   --avb_system_key "$KEY_DIR/avb.pem" --avb_system_algorithm SHA256_RSA4096
                   --avb_system_other_key "$KEY_DIR/avb.pem" --avb_system_other_algorithm SHA256_RSA4096
                   --avb_vbmeta_system_key "$KEY_DIR/avb_vbmeta_system.pem" --avb_vbmeta_system_algorithm SHA256_RSA4096
                   --avb_vbmeta_vendor_key "$KEY_DIR/avb.pem" --avb_vbmeta_vendor_algorithm SHA256_RSA4096
                   --avb_boot_key "$KEY_DIR/avb.pem" --avb_boot_algorithm SHA256_RSA4096
                   --avb_init_boot_key "$KEY_DIR/avb.pem" --avb_init_boot_algorithm SHA256_RSA4096)
fi

if [[ $DEVICE == taimen || $DEVICE == walleye || $DEVICE == blueline || $DEVICE == crosshatch ||
  $DEVICE == sargo || $DEVICE == bonito || $DEVICE == coral || $DEVICE == flame ||
  $DEVICE == sunfish || $DEVICE == redfin || $DEVICE == bramble || $DEVICE == barbet ||
  $DEVICE == oriole || $DEVICE == raven || $DEVICE == bluejay ||
  $DEVICE == panther || $DEVICE == cheetah || $DEVICE == lynx || $DEVICE == tangorpro || $DEVICE == felix ||
  $DEVICE == husky || $DEVICE == shiba ||
  $DEVICE == FP4 || $DEVICE == FP5 ||
  $DEVICE == kebab || $DEVICE == lemonade || $DEVICE == lemonadep ||
  $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ]]; then
  AVB_CUSTOM_KEY="$PWD/$KEY_DIR/avb_custom_key.img"
  for apex in "${apexes[@]}"; do
    EXTRA_SIGNING_ARGS+=(--extra_apks $apex=$KEY_DIR/${apex_container_key[$apex]})
    EXTRA_SIGNING_ARGS+=(--extra_apex_payload_key $apex=$KEY_DIR/${apex_payload_key[$apex]}.pem)
  done
fi

if [[ $DEVICE == jasmine_sprout || $DEVICE == axolotl ]]; then
  for apex in "${apexes[@]}"; do
    EXTRA_SIGNING_ARGS+=(--extra_apks $apex=$KEY_DIR/${apex_container_key[$apex]})
    EXTRA_SIGNING_ARGS+=(--extra_apex_payload_key $apex=$KEY_DIR/${apex_payload_key[$apex]}.pem)
  done
fi

EXTRA_SIGNING_ARGS+=(-k prebuilts/calyx/microg/certs/microg=$KEY_DIR/../common/microg)
EXTRA_SIGNING_ARGS+=(-k external/calyx/chromium/certs/chromium=$KEY_DIR/../common/chromium)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Connectivity/service/ServiceConnectivityResources/resources-certs/com.android.connectivity.resources=$KEY_DIR/com.android.connectivity.resources)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin=$KEY_DIR/com.android.hotspot2.osulogin)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Wifi/service/ServiceWifiResources/resources-certs/com.android.wifi.resources=$KEY_DIR/com.android.wifi.resources)
EXTRA_SIGNING_ARGS+=(-k packages/modules/AdServices/adservices/apk/com.android.adservices.api=$KEY_DIR/com.android.adservices.api)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Bluetooth/android/app/certs/com.android.bluetooth=$KEY_DIR/com.android.bluetooth)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Permission/SafetyCenter/Resources/com.android.safetycenter.resources=$KEY_DIR/com.android.safetycenter.resources)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Wifi/WifiDialog/certs/com.android.wifi.dialog=$KEY_DIR/com.android.wifi.dialog)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Uwb/service/ServiceUwbResources/resources-certs/com.android.uwb.resources=$KEY_DIR/com.android.uwb.resources)
EXTRA_SIGNING_ARGS+=(-k packages/modules/Connectivity/nearby/halfsheet/apk-certs/com.android.nearby.halfsheet=$KEY_DIR/com.android.nearby.halfsheet)
EXTRA_SIGNING_ARGS+=(-k packages/providers/MediaProvider/pdf/apk/com.android.graphics.pdf=$KEY_DIR/com.android.graphics.pdf)
EXTRA_SIGNING_ARGS+=(-k build/make/target/product/security/bluetooth=$KEY_DIR/com.android.bluetooth)
EXTRA_SIGNING_ARGS+=(-k build/make/target/product/security/sdk_sandbox=$KEY_DIR/sdk_sandbox)

if [[ $DEVICE == raven || $DEVICE == cheetah || $DEVICE == tangorpro || $DEVICE == felix ]]; then
  EXTRA_SIGNING_ARGS+=(-k device/google/gs-common/uwb-certs/com.qorvo.uwb=$KEY_DIR/com.qorvo.uwb)
fi

if [[ -n $AVB_ROLLBACK_INDEX_OVERRIDE ]]; then
  if [[ $DEVICE == FP5 || $DEVICE == FP4 ||
        $DEVICE == hawao || $DEVICE == rhode || $DEVICE == devon ]]; then
    EXTRA_SIGNING_ARGS+=(--avb_rollback_index_override $AVB_ROLLBACK_INDEX_OVERRIDE)
  else
    echo "Unsupported device for AVB Rollback Index override: $DEVICE"
    exit 1
  fi
fi

echo "Creating signed targetfiles zip"
$RELEASETOOLS_PATH/bin/sign_target_files_apks $EXTRA_RELEASETOOLS_ARGS -o -d "$KEY_DIR" \
  "${EXTRA_SIGNING_ARGS[@]}" "${VERITY_SWITCHES[@]}" \
  $TARGET_FILES $SIGNED_TARGET_FILES || exit 1

if [[ -n $AVB_ROLLBACK_INDEX_OVERRIDE ]]; then
echo "Skipping OTA update zip for AVB Rollback Index override build"
else
echo "Create OTA update zip"
$RELEASETOOLS_PATH/bin/ota_from_target_files $EXTRA_RELEASETOOLS_ARGS -k "$KEY_DIR/releasekey" $EXTRA_OTA_ARGS $SIGNED_TARGET_FILES \
  $OUT/$DEVICE-ota_update-$BUILD.zip || exit 1

sha256sum $OUT/$DEVICE-ota_update-$BUILD.zip | awk '{printf $1}' > $OUT/$DEVICE-ota_update-$BUILD.zip.sha256sum

if [ ! -z $OTA_ONLY ]; then
  echo "Not creating factory images due to OTA_ONLY=$OTA_ONLY"
  exit 0
fi
fi

echo "Creating factory images"
$RELEASETOOLS_PATH/bin/img_from_target_files $EXTRA_RELEASETOOLS_ARGS $SIGNED_TARGET_FILES \
  $OUT/$DEVICE-img-$BUILD.zip || exit 1

pushd $OUT || exit 1

if [ ! -z $ANDROID_BUILD_TOP ]; then
	source $ANDROID_BUILD_TOP/device/common/generate-factory-images-common.sh
else
	source $RELEASETOOLS_PATH/device/common/generate-factory-images-common.sh
fi

mv $DEVICE-$VERSION-factory-*.zip $DEVICE-factory-$BUILD.zip
sha256sum $DEVICE-factory-$BUILD.zip | awk '{printf $1}' > $DEVICE-factory-$BUILD.zip.sha256sum

popd

echo "Removing intermediate file after factory image generation: $DEVICE-img-$BUILD.zip"
rm $OUT/$DEVICE-img-$BUILD.zip

if [[ -n $OTATEST ]]; then
OTATEST_TARGET_FILES=$OUT/$DEVICE-target_files-$OTATEST.zip
echo "Creating OTA test update zip"
$RELEASETOOLS_PATH/bin/sign_target_files_apks $EXTRA_RELEASETOOLS_ARGS --otatest -o -d "$KEY_DIR" \
 "${EXTRA_SIGNING_ARGS[@]}" "${VERITY_SWITCHES[@]}" \
  $TARGET_FILES $OTATEST_TARGET_FILES || exit 1

$RELEASETOOLS_PATH/bin/ota_from_target_files $EXTRA_RELEASETOOLS_ARGS -k "$KEY_DIR/releasekey" $EXTRA_OTA_ARGS $OTATEST_TARGET_FILES \
  $OUT/$DEVICE-ota_update-$OTATEST.zip || exit 1
sha256sum $OUT/$DEVICE-ota_update-$OTATEST.zip | awk '{printf $1}' > $OUT/$DEVICE-ota_update-$OTATEST.zip.sha256sum
fi
