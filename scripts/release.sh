#!/bin/bash
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

EXTRA_RELEASETOOLS_ARGS=(${EXTRA_RELEASETOOLS_ARGS:-})
EXTRA_OTA_ARGS=(${EXTRA_OTA_ARGS:-})

source "$SCRIPTPATH/common.include.sh"
source "$SCRIPTPATH/metadata"

release_cleanup() {
  cleanup_signing_full || true
}
trap release_cleanup EXIT

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
  EXTRA_RELEASETOOLS_ARGS+=(-p "$RELEASETOOLS_PATH")
fi

prepare_for_signing_full "$0" "$@" || exit $?

if [ "${DRY_RUN:-}" != "y" ]; then

VERSION=$(unzip -c "$TARGET_FILES" SYSTEM/build.prop | grep "ro.build.id=" | cut -d = -f 2 | tr '[:upper:]' '[:lower:]')

if [[
    $DEVICE == redfin || $DEVICE == bramble || $DEVICE == barbet ||
    $DEVICE == oriole || $DEVICE == raven || $DEVICE == bluejay ||
    $DEVICE == panther || $DEVICE == cheetah || $DEVICE == lynx || $DEVICE == felix ||
    $DEVICE == shiba || $DEVICE == husky || $DEVICE == akita ||
    $DEVICE == tokay || $DEVICE == caiman || $DEVICE == komodo || $DEVICE == comet || $DEVICE == tegu
]]; then
  BOOTLOADER=$(unzip -c "$TARGET_FILES" OTA/android-info.txt | grep version-bootloader | cut -d = -f 2)
  RADIO=$(unzip -c "$TARGET_FILES" OTA/android-info.txt | grep version-baseband | cut -d = -f 2)
elif [[ $DEVICE == tangorpro ]]; then
  BOOTLOADER=$(unzip -c "$TARGET_FILES" OTA/android-info.txt | grep version-bootloader | cut -d = -f 2)
elif [[ $DEVICE == FP4 ]]; then
  FP4="true"
  QCOM_FIRMWARE="true"
elif [[ $DEVICE == FP5 ]]; then
  FP5="true"
  QCOM_FIRMWARE="true"
elif [[ $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ]]; then
  MOTO_BENGAL="true"
  QCOM_FIRMWARE="true"
elif [[ $DEVICE == fogos || $DEVICE == bangkk || $DEVICE == fogo ]]; then
  MOTO_BLAIR="true"
  QCOM_FIRMWARE="true"
elif [[ $DEVICE == otter ]]; then
  OTTER="true"
  QCOM_FIRMWARE="true"
else
  error "Unsupported device $DEVICE"
fi

else  # DRY_RUN

VERSION=version_placeholder

fi  # not DRY_RUN

$maybe_dry_run mkdir -p "$OUT" || exit 1

# Get AVB arguments from keymapper.
avb_arguments=()
fill_avb_arguments

# Populate key mappings for APEXes.
for key in "${keys_apex[@]}"; do
  EXTRA_SIGNING_ARGS+=(--extra_apks "$key.apex=$(get_key apex_container "$key")")
  EXTRA_SIGNING_ARGS+=(--extra_apex_payload_key "$key.apex=$(get_key apex_payload "$key" .pem)")
done

# Populate key mappings for everything else.
declare -A already_remapped
for key in build/make/target/product/security/devkey "${keys_core[@]}"; do
  [ -z "${already_remapped[$key]:-}" ] || continue
  value=$(get_key core "$key")
  [ -n "$value" ] || continue
  EXTRA_SIGNING_ARGS+=(-k "$key=$value")
  already_remapped[$key]=1
done
for key in "${keys_apex_apk[@]}"; do
  [ -z "${already_remapped[$key]:-}" ] || continue
  value=$(get_key apex_apk "$key")
  [ -n "$value" ] || continue
  EXTRA_SIGNING_ARGS+=(-k "$key=$value")
  already_remapped[$key]=1
done
for key in "${keys_app[@]}"; do
  [ -z "${already_remapped[$key]:-}" ] || continue
  value=$(get_key app "$key")
  [ -n "$value" ] || continue
  EXTRA_SIGNING_ARGS+=(-k "$key=$value")
  already_remapped[$key]=1
done

if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
  if [[
    $DEVICE == FP4 ||
    $DEVICE == FP5 ||
    $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ||
    $DEVICE == fogos || $DEVICE == bangkk || $DEVICE == fogo ||
    $DEVICE == otter
  ]]; then
    EXTRA_SIGNING_ARGS+=(--avb_rollback_index_override "$AVB_ROLLBACK_INDEX_OVERRIDE")
  else
    echo "Unsupported device for AVB Rollback Index override: $DEVICE"
    exit 1
  fi
fi

case "${KEEP_EXISTING:-}" in
  *target*|all)
    KEEP_TARGET_FILES=y
    ;;&
  *otaupdate*|all)
    KEEP_OTA=y
    ;;&
  *factory*|all)
    KEEP_FACTORY=y
    ;;
esac

if [ "${KEEP_TARGET_FILES:-n}" = n ] || [ ! -e "$SIGNED_TARGET_FILES" ]; then
  echo "Creating signed targetfiles zip"
  $maybe_dry_run \
    "$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" -o \
      "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
      "$TARGET_FILES" "$SIGNED_TARGET_FILES" || exit 1
fi

RELEASEKEY=$(get_key core build/make/target/product/security/testkey)

if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
echo "Skipping OTA update zip for AVB Rollback Index override build"
else
if [ "${KEEP_OTA:-n}" = n ] || [ ! -e "$OUT/$DEVICE-ota_update-$BUILD.zip" ]; then
  echo "Create OTA update zip"
  $maybe_dry_run \
  "$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" -k "$RELEASEKEY" "${EXTRA_OTA_ARGS[@]}" "$SIGNED_TARGET_FILES" \
    "$OUT/$DEVICE-ota_update-$BUILD.zip" || exit 1

  $maybe_dry_run \
  sha256sum "$OUT/$DEVICE-ota_update-$BUILD.zip" \
    | $maybe_dry_run_ignore awk '{printf $1}' \
    | $maybe_dry_run_ignore tee "$OUT/$DEVICE-ota_update-$BUILD.zip.sha256sum"
fi

if [ ! -z "${OTA_ONLY:-}" ]; then
  echo "Not creating factory images due to OTA_ONLY=$OTA_ONLY"
  exit 0
fi
fi

if [ "${KEEP_FACTORY:-n}" = n ] || [ ! -e "$OUT/$DEVICE-img-$BUILD.zip" ]; then
  echo "Creating factory images"
  $maybe_dry_run \
  "$RELEASETOOLS_PATH/bin/img_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "$SIGNED_TARGET_FILES" \
    "$OUT/$DEVICE-img-$BUILD.zip" || exit 1
fi

$maybe_dry_run pushd "$OUT" || exit 1

# FIXME: generate-factory-images-common.sh doesn't handle errors gracefully, such as for missing
#        RADIO/bootloader.img on non-Pixel, so we turn off exit-on-error, etc before sourcing it.
set +euo pipefail
if [ ! -z "${ANDROID_BUILD_TOP:-}" ]; then
  $maybe_dry_run \
  source "$ANDROID_BUILD_TOP/device/common/generate-factory-images-common.sh"
else
  $maybe_dry_run \
  source "$RELEASETOOLS_PATH/device/common/generate-factory-images-common.sh"
fi
set -euo pipefail

$maybe_dry_run \
mv "$DEVICE-$VERSION-factory-"*.zip "$DEVICE-factory-$BUILD.zip"
$maybe_dry_run \
sha256sum "$DEVICE-factory-$BUILD.zip" \
  | $maybe_dry_run_ignore awk '{printf $1}' \
  | $maybe_dry_run_ignore tee "$DEVICE-factory-$BUILD.zip.sha256sum"

$maybe_dry_run popd

echo "Removing intermediate file after factory image generation: $DEVICE-img-$BUILD.zip"
$maybe_dry_run \
rm "$OUT/$DEVICE-img-$BUILD.zip"

if [[ -n ${OTATEST:-} ]]; then
OTATEST_TARGET_FILES=$OUT/$DEVICE-target_files-$OTATEST.zip
echo "Creating OTA test update zip"
$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" --otatest -o \
 "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
  "$TARGET_FILES" "$OTATEST_TARGET_FILES" || exit 1

$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" -k "$RELEASEKEY" "${EXTRA_OTA_ARGS[@]}" "$OTATEST_TARGET_FILES" \
  "$OUT/$DEVICE-ota_update-$OTATEST.zip" || exit 1
$maybe_dry_run \
sha256sum "$OUT/$DEVICE-ota_update-$OTATEST.zip" \
  | $maybe_dry_run_ignore awk '{printf $1}' \
  | $maybe_dry_run_ignore tee "$OUT/$DEVICE-ota_update-$OTATEST.zip.sha256sum"
fi

release_cleanup || true
trap "" EXIT
