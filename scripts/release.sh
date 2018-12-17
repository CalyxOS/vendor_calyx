#!/bin/bash
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

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
  TARGET_FILES=out/target/product/$DEVICE/obj/PACKAGING/target_files_intermediates/calyx_$DEVICE-target_files-$BUILD_NUMBER.zip
  RELEASETOOLS_PATH=build/tools
else
  TARGET_FILES=$2
  # For usage with otatools.zip
  RELEASETOOLS_PATH=.
fi

VERSION=$(unzip -c $TARGET_FILES SYSTEM/build.prop | grep "ro.build.id=" | cut -d = -f 2 | tr '[:upper:]' '[:lower:]')

if [[ $DEVICE == marlin || $DEVICE == sailfish || $DEVICE == taimen || $DEVICE == walleye ]]; then
  BOOTLOADER=$(unzip -c $TARGET_FILES SYSTEM/build.prop | grep "ro.build.expect.bootloader=" | cut -d = -f 2)
  RADIO=$(unzip -c $TARGET_FILES SYSTEM/build.prop | grep "ro.build.expect.baseband=" | cut -d = -f 2)
elif [[ $DEVICE == jasmine ]]; then
  : # TODO
else
  error "Unsupported device $DEVICE"
fi

mkdir -p $OUT || exit 1

if [[ $DEVICE == marlin || $DEVICE == sailfish || $DEVICE == jasmine ]]; then
  VERITY_SWITCHES=(--replace_verity_public_key "$KEY_DIR/verity_key.pub" --replace_verity_private_key "$KEY_DIR/verity"
                   --replace_verity_keyid "$KEY_DIR/verity.x509.pem")
elif [[ $DEVICE == taimen || $DEVICE == walleye ]]; then
  VERITY_SWITCHES=(--avb_vbmeta_key "$KEY_DIR/avb.pem" --avb_vbmeta_algorithm SHA256_RSA2048)
  AVB_PKMD="$PWD/$KEY_DIR/avb_pkmd.bin"
fi

echo "Creating signed targetfiles zip"
$RELEASETOOLS_PATH/releasetools/sign_target_files_apks -p . -o -d "$KEY_DIR" "${VERITY_SWITCHES[@]}" \
  $TARGET_FILES $SIGNED_TARGET_FILES || exit 1

echo "Create OTA update zip"
$RELEASETOOLS_PATH/releasetools/ota_from_target_files -p . -k "$KEY_DIR/releasekey" "${EXTRA_OTA[@]}" $TARGET_FILES \
  $OUT/$DEVICE-ota_update-$BUILD.zip || exit 1

echo "Creating factory images"
$RELEASETOOLS_PATH/releasetools/img_from_target_files -p . $SIGNED_TARGET_FILES \
  $OUT/$DEVICE-img-$BUILD.zip || exit 1

cd $OUT || exit 1

source ../../device/common/generate-factory-images-common.sh

mv $DEVICE-$VERSION-factory-*.zip $DEVICE-factory-$BUILD_NUMBER.zip