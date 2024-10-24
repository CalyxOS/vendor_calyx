#!/bin/bash

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 key_dir subject"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

[[ $# -eq 2 ]] ||  error "incorrect number of arguments"

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP="$SCRIPTPATH/../../.."

source $SCRIPTPATH/metadata

KEY_DIR=$1
SUBJECT="$2"
GENVERITYKEY=$TOP/bin/generate_verity_key
AVBTOOL=$TOP/bin/avbtool

[[ ! -e ${GENVERITYKEY} ]] && error "${GENVERITYKEY} not found."
[[ ! -e ${AVBTOOL} ]] && error "${AVBTOOL} not found."
[[ ! -e $(which openssl) ]] && error "openssl not found in PATH."

[[ -d $KEY_DIR ]] && error "key directory already exists"
mkdir -p $KEY_DIR

pushd $KEY_DIR

for k in releasekey platform shared media networkstack sdk_sandbox \
		com.android.connectivity.resources \
		com.android.hotspot2.osulogin com.android.wifi.resources com.android.adservices.api \
		com.android.bluetooth com.android.safetycenter.resources com.android.wifi.dialog \
		com.android.uwb.resources com.android.nearby.halfsheet com.android.graphics.pdf \
		com.android.appsearch.apk com.android.healthconnect.controller \
		com.android.health.connect.backuprestore com.android.nfcservices \
		com.android.federatedcompute; do
	$SCRIPTPATH/mkkey.sh "$k" "$SUBJECT"
done

if [[ $KEY_DIR =~ raven || $KEY_DIR =~ cheetah || $KEY_DIR =~ tangorpro || $KEY_DIR =~ felix ]]; then
	$SCRIPTPATH/mkkey.sh "com.qorvo.uwb" "$SUBJECT"
fi

# Verified Boot (Pixel, Mi A2)
$SCRIPTPATH/mkkey.sh verity "$SUBJECT"
$GENVERITYKEY -convert verity.x509.pem verity_key
openssl x509 -outform der -in verity.x509.pem -out verity_user.der.x509

if [[ $KEY_DIR =~ akita || $KEY_DIR =~ husky || $KEY_DIR =~ shiba ||
	$KEY_DIR =~ felix || $KEY_DIR =~ tangorpro || $KEY_DIR =~ lynx || $KEY_DIR =~ cheetah || $KEY_DIR =~ panther ||
	$KEY_DIR =~ barbet || $KEY_DIR =~ oriole || $KEY_DIR =~ raven || $KEY_DIR =~ bluejay ||
	$KEY_DIR =~ FP4 || $KEY_DIR =~ FP5 || $KEY_DIR =~ kebab || $KEY_DIR =~ lemonade || $KEY_DIR =~ lemonadep ||
	$KEY_DIR =~ axolotl || $KEY_DIR =~ devon || $KEY_DIR =~ hawao || $KEY_DIR =~ rhode ]]; then
# AVB 2.0 (Pixel 8a, 8, 8 Pro, Fold, Tablet, 7a, 7, 7 pro, 5a, 6, 6 pro, 6a, Fairphone 4, 5, OnePlus 8T, 9, 9 Pro, SHIFT6mq, moto g32, g42, g52)
openssl genrsa -out avb.pem 4096
$AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
else
# AVB 2.0 (Pixel 2, 2 xl, 3, 3 xl, 3a, 3a xl, 4, 4 xl, 4a, 5, 4a 5g)
openssl genrsa -out avb.pem 2048
$AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
fi

# Pixel 8a, 8, 8 Pro, Fold, Tablet, 7a, 7, 7 pro
if [[ $KEY_DIR =~ akita || $KEY_DIR =~ husky || $KEY_DIR =~ shiba ||
      $KEY_DIR =~ felix || $KEY_DIR =~ tangorpro || $KEY_DIR =~ lynx || $KEY_DIR =~ cheetah || $KEY_DIR =~ panther ]]; then
	openssl genrsa -out avb_vbmeta_system.pem 4096
fi

for apex in "${apexes[@]}"; do
	$SCRIPTPATH/mkkey.sh "${apex_container_key[$apex]}" "$SUBJECT"
done

for apex in "${apexes[@]}"; do
	openssl genrsa -out ${apex_payload_key[$apex]}.pem 4096
	$AVBTOOL extract_public_key --key ${apex_payload_key[$apex]}.pem --output ${apex_payload_key[$apex]}.avbpubkey
done

popd
