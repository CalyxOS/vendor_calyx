#!/bin/bash
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

set -euo pipefail
SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source "$SCRIPTPATH/metadata"

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 device [target-files.zip]"
  exit 1
}

[[ $# -le 2 ]] || error "incorrect number of arguments"
[[ -n $BUILD_NUMBER ]] || error "BUILD_NUMBER not set, did you source envsetup.sh ?"

source device/common/clear-factory-images-variables.sh

dry_run() {
  printf "%q " "$@"
  echo
}
if [ "${DRY_RUN:-}" = "y" ]; then
  maybe_dry_run=dry_run
else
  maybe_dry_run=
fi

DEVICE=$1
PRODUCT=$1
OUT=out/release-$DEVICE-$BUILD_NUMBER
BUILD=$BUILD_NUMBER
SIGNED_TARGET_FILES=$OUT/$DEVICE-target_files-$BUILD.zip

if [[ -z $2 ]] ; then
  TARGET_FILES=out/target/product/$DEVICE/obj/PACKAGING/target_files_intermediates/calyx_$DEVICE-target_files-$BUILD.zip
  RELEASETOOLS_PATH=build/tools
  EXTRA_RELEASETOOLS_ARGS=()
else
  TARGET_FILES=$2
  # For usage with otatools.zip
  RELEASETOOLS_PATH="$(pwd -P)"
  EXTRA_RELEASETOOLS_ARGS=(-p "$RELEASETOOLS_PATH")
fi

load_keymapper() {
  if [ -n "${KEYMAPPER_FILE:-}" ]; then
    source "$KEYMAPPER_FILE" || exit 1
  elif [ -n "${KEYMAPPER:-}" ]; then
    keymapper_path=$(cd "$SCRIPTPATH"; realpath -e "keymapper_$KEYMAPPER.sh" || true)
    if [ -z "$keymapper_path" ]; then
      echo "Could not find keymapper '$KEYMAPPER'." >&2
      exit 1
    fi
    source "$keymapper_path" || exit 1
  else
    source "$SCRIPTPATH/keymapper_legacy.sh" || exit 1
  fi
}

if [ -n "${PKCS11_MODULE:-}" ] || [ -n "${PKCS11_VENDOR:-}" ] || [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
  source "$SCRIPTPATH/pkcs11/include.sh"
  if [ -n "${PKCS11_VENDOR_FILE:-}" ]; then
    source "$PKCS11_VENDOR_FILE" || exit 1
  elif [ -n "${PKCS11_VENDOR:-}" ]; then
    pkcs11_vendor_path=$(cd "$SCRIPTPATH"; realpath -e "pkcs11/vendor.${PKCS11_VENDOR}.include.sh" || true)
    if [ -z "$pkcs11_vendor_path" ]; then
      echo "Could not find PKCS#11 vendor include script for '$PKCS11_VENDOR'." >&2
      exit 1
    fi
    source "$pkcs11_vendor_path" || exit 1
  fi
  load_keymapper
  tmpdir=$(mktemp -d)
  cleanup() {
    rm -f "$tmpdir/sunpkcs11.cfg"
    rmdir "$tmpdir"
  }
  trap cleanup EXIT
  _generate_sunpkcs11_config > "$tmpdir/sunpkcs11.cfg"
  tool=pkcs11-tool
  if [ "${PREFER_OPENSSL:-n}" = "y" ]; then
    tool=openssl
  fi
  EXTRA_RELEASETOOLS_ARGS+=(
    --verbose
    --pkcs11_config "$tmpdir/sunpkcs11.cfg"
    --extra_avbtool_signing_args "--signing_helper vendor/calyx/scripts/pkcs11/signing_helper_${tool}.sh"
  )
  EXTRA_COMMON_ARGS+=(
    --payload_signer "vendor/calyx/scripts/pkcs11/payload_signer_${tool}.sh"
    --extra_apksigner_args '--v1-signing-enabled=false --v4-signing-enabled=false'
  )
else
  load_keymapper
fi
if [ -n "${SIGNING_COMMAND_INTERMEDIARY:-}" ]; then
  EXTRA_COMMON_ARGS+=(
    --signing_command_intermediary "$SIGNING_COMMAND_INTERMEDIARY"
  )
fi

# Payload signer maximum signature size is set to 512 in the metadata file by default
# to accommodate RSA4096 keys.
[ -z "${PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE:-}" ] || EXTRA_COMMON_ARGS+=(
  --payload_signer_maximum_signature_size "$PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE"
)

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

mkdir -p "$OUT" || exit 1

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
for key in "${keys_avb[@]}"; do
  [ -z "${already_remapped[$key]:-}" ] || continue
  value=$(get_key avb "$key")
  [ -n "$value" ] || continue
  EXTRA_SIGNING_ARGS+=(-k "$key=$value")
  already_remapped[$key]=1
done
for key in "${keys_core[@]}"; do
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
    "$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_COMMON_ARGS[@]}" -o -d "${KEY_DIR%/}" \
      "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
      "$TARGET_FILES" "$SIGNED_TARGET_FILES" || exit 1
fi

RELEASEKEY="$(get_key core build/make/target/product/security/testkey)"

if [[ -n ${AVB_ROLLBACK_INDEX_OVERRIDE:-} ]]; then
echo "Skipping OTA update zip for AVB Rollback Index override build"
else
if [ "${KEEP_OTA:-n}" = n ] || [ ! -e "$OUT/$DEVICE-ota_update-$BUILD.zip" ]; then
  echo "Create OTA update zip"
  $maybe_dry_run \
  "$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_COMMON_ARGS[@]}" -k "$RELEASEKEY" ${EXTRA_OTA_ARGS:-} "$SIGNED_TARGET_FILES" \
    "$OUT/$DEVICE-ota_update-$BUILD.zip" || exit 1

  $maybe_dry_run \
  sha256sum "$OUT/$DEVICE-ota_update-$BUILD.zip" | awk '{printf $1}' > "$OUT/$DEVICE-ota_update-$BUILD.zip.sha256sum"
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

pushd "$OUT" || exit 1

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
sha256sum "$DEVICE-factory-$BUILD.zip" | awk '{printf $1}' > "$DEVICE-factory-$BUILD.zip.sha256sum"

popd

echo "Removing intermediate file after factory image generation: $DEVICE-img-$BUILD.zip"
$maybe_dry_run \
rm "$OUT/$DEVICE-img-$BUILD.zip"

if [[ -n ${OTATEST:-} ]]; then
OTATEST_TARGET_FILES=$OUT/$DEVICE-target_files-$OTATEST.zip
echo "Creating OTA test update zip"
$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/sign_target_files_apks" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_COMMON_ARGS[@]}" --otatest -o -d "${KEY_DIR%/}" \
 "${EXTRA_SIGNING_ARGS[@]}" "${avb_arguments[@]}" \
  "$TARGET_FILES" "$OTATEST_TARGET_FILES" || exit 1

$maybe_dry_run \
"$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_COMMON_ARGS[@]}" -k "$RELEASEKEY" ${EXTRA_OTA_ARGS:-} "$OTATEST_TARGET_FILES" \
  "$OUT/$DEVICE-ota_update-$OTATEST.zip" || exit 1
$maybe_dry_run \
sha256sum "$OUT/$DEVICE-ota_update-$OTATEST.zip" | awk '{printf $1}' > "$OUT/$DEVICE-ota_update-$OTATEST.zip.sha256sum"
fi
