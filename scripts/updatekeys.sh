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

[[ ! -d $KEY_DIR ]] && error "key directory does not exist"

pushd $KEY_DIR

for k in releasekey platform shared media networkstack sdk_sandbox \
		com.android.connectivity.resources \
		com.android.hotspot2.osulogin com.android.wifi.resources com.android.adservices.api \
		com.android.bluetooth com.android.safetycenter.resources com.android.wifi.dialog \
		com.android.uwb.resources com.android.nearby.halfsheet; do
	if [[ ! -e ${k}.pk8 ]]; then
		$SCRIPTPATH/mkkey.sh "$k" "$SUBJECT"
	fi
done

if [[ $KEY_DIR =~ raven || $KEY_DIR =~ cheetah ]]; then
	if [[ ! -e com.qorvo.uwb.pk8 ]]; then
		$SCRIPTPATH/mkkey.sh "com.qorvo.uwb" "$SUBJECT"
	fi
fi

# Verified Boot (Pixel, Mi A2)
if [[ ! -e verity.pk8 ]]; then
	$SCRIPTPATH/mkkey.sh verity "$SUBJECT"
	$GENVERITYKEY -convert verity.x509.pem verity_key
	openssl x509 -outform der -in verity.x509.pem -out verity_user.der.x509
fi

if [[ ! -e avb.pem ]]; then
	if [[ $KEY_DIR =~ felix || $KEY_DIR =~ tangorpro || $KEY_DIR =~ lynx || $KEY_DIR =~ cheetah || $KEY_DIR =~ panther ||
		$KEY_DIR =~ barbet || $KEY_DIR =~ oriole || $KEY_DIR =~ raven || $KEY_DIR =~ bluejay ||
		$KEY_DIR =~ FP4 || $KEY_DIR =~ kebab || $KEY_DIR =~ lemonade || $KEY_DIR =~ lemonadep ||
		$KEY_DIR =~ axolotl || $KEY_DIR =~ devon || $KEY_DIR =~ hawao || $KEY_DIR =~ rhode ]]; then
	# AVB 2.0 (Pixel Fold, Tablet, 7a, 7, 7 pro, 5a, 6, 6 pro, 6a, Fairphone 4, OnePlus 8T, 9, 9 Pro, SHIFT6mq, moto g32, g42, g52)
	openssl genrsa -out avb.pem 4096
	$AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
	else
	# AVB 2.0 (Pixel 2, 2 xl, 3, 3 xl, 3a, 3a xl, 4, 4 xl, 4a, 5, 4a 5g)
	openssl genrsa -out avb.pem 2048
	$AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
	fi
fi

# Pixel Fold, Tablet, 7a, 7, 7 pro
if [[ $KEY_DIR =~ felix || $KEY_DIR =~ tangorpro || $KEY_DIR =~ lynx || $KEY_DIR =~ cheetah || $KEY_DIR =~ panther ]]; then
	if [[ ! -e avb_vbmeta_system.pem ]]; then
	openssl genrsa -out avb_vbmeta_system.pem 4096
	fi
fi

if [[ -e avb_pkmd.bin ]]; then
	mv avb_pkmd.bin avb_custom_key.img
fi

# Migration from 10 to 11
# ART apex was renamed, and bionic runtime was split out into a new apex
[[ -e com.android.runtime.release.pk8 ]] && mv com.android.runtime.release.pk8 com.android.runtime.pk8
[[ -e com.android.runtime.release.x509.pem ]] && mv com.android.runtime.release.x509.pem com.android.runtime.x509.pem

for apex in "${apexes[@]}"; do
	if [[ ! -e ${apex_container_key[$apex]}.pk8 ]]; then
		$SCRIPTPATH/mkkey.sh "${apex_container_key[$apex]}" "$SUBJECT"
	fi
done

for apex in "${apexes[@]}"; do
	if [[ ! -e ${apex_payload_key[$apex]}.pem ]]; then
		openssl genrsa -out ${apex_payload_key[$apex]}.pem 4096
		$AVBTOOL extract_public_key --key ${apex_payload_key[$apex]}.pem --output ${apex_payload_key[$apex]}.avbpubkey
	fi
done

popd
