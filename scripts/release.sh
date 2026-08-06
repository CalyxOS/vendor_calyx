#!/bin/bash
#
# SPDX-FileCopyrightText: 2018 Daniel Micay
# SPDX-FileCopyrightText: 2018-2026 The Calyx Institute
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

read -a EXTRA_RELEASETOOLS_ARGS <<< "${EXTRA_RELEASETOOLS_ARGS:-}"
read -a EXTRA_OTA_ARGS <<< "${EXTRA_OTA_ARGS:-}"

source "$SCRIPTPATH/common.include.sh"
source "$SCRIPTPATH/metadata"

release_cleanup() {
  cleanup_signing_full || true
}
trap release_cleanup EXIT

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 device [target-files.zip]"
  exit 1
}

[[ $# -le 2 ]] || error "incorrect number of arguments"
[[ -n $BUILD_NUMBER ]] || error "BUILD_NUMBER not set, did you source envsetup.sh ?"

source device/common/clear-factory-images-variables.sh

DEVICE=$1
PRODUCT=$1
BUILD=$BUILD_NUMBER

if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
  BUILD=$((BUILD + 1))
fi

OUT=out/release-$DEVICE-$BUILD
SIGNED_TARGET_FILES=$OUT/$DEVICE-target_files-$BUILD.zip

if [[ -z ${2:-} ]] ; then
  TARGET_FILES=out/target/product/$DEVICE/obj/PACKAGING/target_files_intermediates/calyx_$DEVICE-target_files-$BUILD.zip
  RELEASETOOLS_PATH=build/tools
else
  TARGET_FILES=$2
  # For usage with otatools.zip
  RELEASETOOLS_PATH="$(pwd -P)"
  EXTRA_RELEASETOOLS_ARGS+=(-p "$RELEASETOOLS_PATH")
fi

if [ "${SKIP_SIGNING:-}" != y ]; then
  prepare_for_signing_full "$0" "$@" || exit $?
fi

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
elif [[ $DEVICE == FP6 ]]; then
  FP6="true"
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
  SKIP_AVB_CUSTOM_KEY="true"
else
  error "Unsupported device $DEVICE"
fi

else  # DRY_RUN

VERSION=version_placeholder

fi  # not DRY_RUN

$maybe_dry_run mkdir -p "$OUT" || exit 1

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

if [ "${SKIP_SIGNING:-}" = y ]; then
  if [ ! -z "${OTA_ONLY:-}" ]; then
    echo "Not creating factory image due to OTA_ONLY=$OTA_ONLY"
    exit 0
  fi
  echo "Skipping signing and OTA generation, creating factory image from unsigned target files"
  FACTORY_TARGET_FILES=$TARGET_FILES
else
  FACTORY_TARGET_FILES=$SIGNED_TARGET_FILES

  # Get AVB arguments from keymapper.
  avb_arguments=()
  fill_avb_arguments

  # Populate key mappings for APEXes.
  for key in "${keys_apex[@]}"; do
    EXTRA_SIGNING_ARGS+=(--extra_apks "$key.apex=$(get_key apex_container "$key" || exit $?)")
    EXTRA_SIGNING_ARGS+=(--extra_apex_payload_key "$key.apex=$(get_key apex_payload "$key" .pem || exit $?)")
  done

  # Populate key mappings for everything else.
  declare -A already_remapped
  for key in build/make/target/product/security/devkey "${keys_core[@]}"; do
    [ -z "${already_remapped[$key]:-}" ] || continue
    value=$(get_key core "$key" || exit $?)
    [ -n "$value" ] || continue
    EXTRA_SIGNING_ARGS+=(-k "$key=$value")
    already_remapped[$key]=1
  done
  for key in "${keys_apex_apk[@]}"; do
    [ -z "${already_remapped[$key]:-}" ] || continue
    value=$(get_key apex_apk "$key" || exit $?)
    [ -n "$value" ] || continue
    EXTRA_SIGNING_ARGS+=(-k "$key=$value")
    already_remapped[$key]=1
  done
  for key in "${keys_app[@]}"; do
    [ -z "${already_remapped[$key]:-}" ] || continue
    value=$(get_key app "$key" || exit $?)
    [ -n "$value" ] || continue
    EXTRA_SIGNING_ARGS+=(-k "$key=$value")
    already_remapped[$key]=1
  done

  if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
    if [[
      $DEVICE == FP5 ||
      $DEVICE == devon || $DEVICE == hawao || $DEVICE == rhode ||
      $DEVICE == fogos || $DEVICE == bangkk || $DEVICE == fogo
    ]]; then
      EXTRA_SIGNING_ARGS+=(--avb_rollback_index_override "$AVB_ROLLBACK_INDEX_OVERRIDE")
      EXTRA_SIGNING_ARGS+=(--bump_date_and_version "1")
    else
      echo "Unsupported device for AVB Rollback Index override: $DEVICE"
      exit 1
    fi
  fi

  OTAKEY=$(get_key other ota || exit $?)
  EXTRA_SIGNING_ARGS+=(--package_key "$OTAKEY")
  EXTRA_OTA_ARGS+=(--package_key "$OTAKEY")

  if [ "${KEEP_TARGET_FILES:-n}" = n ] || [ ! -e "$SIGNED_TARGET_FILES" ]; then
    echo "Creating signed targetfiles zip"
    $maybe_dry_run \
      "$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" -o \
        "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
        "$TARGET_FILES" "$SIGNED_TARGET_FILES" || exit 1
  fi

  if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
    echo "Skipping OTA update zip for AVB Rollback Index override build"
  else
    if [ "${KEEP_OTA:-n}" = n ] || [ ! -e "$OUT/$DEVICE-ota_update-$BUILD.zip" ]; then
      echo "Creating OTA update zip"
      $maybe_dry_run \
      "$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_OTA_ARGS[@]}" "$SIGNED_TARGET_FILES" \
        "$OUT/$DEVICE-ota_update-$BUILD.zip" || exit 1

      $maybe_dry_run pushd "$OUT" || exit 1

      echo "Calculating sha256sum for OTA update zip"
      $maybe_dry_run \
      sha256sum "$DEVICE-ota_update-$BUILD.zip" > "$DEVICE-ota_update-$BUILD.zip.sha256sum"

      $maybe_dry_run popd
    fi

    if [ ! -z "${OTA_ONLY:-}" ]; then
      echo "Not creating factory image due to OTA_ONLY=$OTA_ONLY"
      exit 0
    fi
  fi

fi  # ! SKIP_SIGNING

if [ "${KEEP_FACTORY:-n}" = n ] || [ ! -e "$OUT/$DEVICE-img-$BUILD.zip" ]; then
  echo "Creating factory image"
  $maybe_dry_run \
  "$RELEASETOOLS_PATH/bin/img_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "$FACTORY_TARGET_FILES" \
    "$OUT/$DEVICE-img-$BUILD.zip" || exit 1
fi

$maybe_dry_run pushd "$OUT" || exit 1

if [ ! -z "${ANDROID_BUILD_TOP:-}" ]; then
  $maybe_dry_run \
  source "$ANDROID_BUILD_TOP/device/common/generate-factory-images-common.sh"
else
  $maybe_dry_run \
  source "$RELEASETOOLS_PATH/device/common/generate-factory-images-common.sh"
fi

$maybe_dry_run \
mv "$DEVICE-$VERSION-factory-"*.zip "$DEVICE-factory-$BUILD.zip"

echo "Calculating sha256sum for factory image"
$maybe_dry_run \
sha256sum "$DEVICE-factory-$BUILD.zip" > "$DEVICE-factory-$BUILD.zip.sha256sum"

$maybe_dry_run popd

echo "Removing intermediate file after factory image generation: $DEVICE-img-$BUILD.zip"
$maybe_dry_run \
rm "$OUT/$DEVICE-img-$BUILD.zip"

if [[ -n ${OTATEST:-} && "${SKIP_SIGNING:-}" != y ]]; then
OTATEST_TARGET_FILES=$OUT/$DEVICE-target_files-$OTATEST.zip
echo "Creating OTA test update zip"
$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" --otatest -o \
 "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
  "$TARGET_FILES" "$OTATEST_TARGET_FILES" || exit 1

$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_OTA_ARGS[@]}" "$OTATEST_TARGET_FILES" \
  "$OUT/$DEVICE-ota_update-$OTATEST.zip" || exit 1

$maybe_dry_run pushd "$OUT" || exit 1

echo "Calculating sha256sum for OTA test update zip"
$maybe_dry_run \
sha256sum "$DEVICE-ota_update-$OTATEST.zip" > "$DEVICE-ota_update-$OTATEST.zip.sha256sum"

$maybe_dry_run popd
fi

release_cleanup || true
trap "" EXIT
