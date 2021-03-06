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
GENVERITYKEY=generate_verity_key
AVBTOOL=avbtool

[[ -d $KEY_DIR ]] && error "key directory already exists"
mkdir -p $KEY_DIR

pushd $KEY_DIR

for k in releasekey platform shared media networkstack; do
	$SCRIPTPATH/mkkey.sh "$k" "$SUBJECT"
done

# Verified Boot (Pixel, Mi A2)
$SCRIPTPATH/mkkey.sh verity "$SUBJECT"
$GENVERITYKEY -convert verity.x509.pem verity_key
openssl x509 -outform der -in verity.x509.pem -out verity_user.der.x509

# AVB 2.0 (Pixel 2)
openssl genrsa -out avb.pem 2048
$AVBTOOL extract_public_key --key avb.pem --output avb_pkmd.bin

for apex in "${apexes[@]}"; do
	$SCRIPTPATH/mkkey.sh "${apex_container_key[$apex]}" "$SUBJECT"
done

for apex in "${apexes[@]}"; do
	openssl genrsa -out ${apex_payload_key[$apex]}.pem 4096
	$AVBTOOL extract_public_key --key ${apex_payload_key[$apex]}.pem --output ${apex_payload_key[$apex]}.avbpubkey
done

$SCRIPTPATH/mkkeystore.sh "calyxos" "$SUBJECT"

popd

echo "========================================================"
echo "Copy $KEY_DIR/verity_user.der.x509 to the kernel source."
echo "========================================================"
