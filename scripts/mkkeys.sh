#!/bin/bash

set -o nounset

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 key_dir subject"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

[[ $# -eq 2 ]] ||  error "incorrect number of arguments"

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP="$SCRIPTPATH/../../.."

KEY_DIR=$1
SUBJECT="$2"
MKKEY=$TOP/development/tools/make_key
GENVERITYKEY=generate_verity_key
AVBTOOL=avbtool

[[ -d $KEY_DIR ]] && error "key directory already exists"
mkdir -p $KEY_DIR

pushd $KEY_DIR

for k in releasekey platform shared media; do
	$MKKEY $k "$SUBJECT"
done

# Verified Boot (Pixel, Mi A2)
$MKKEY verity "$SUBJECT"
$GENVERITYKEY -convert verity.x509.pem verity_key
openssl x509 -outform der -in verity.x509.pem -out verity_user.der.x509

# AVB 2.0 (Pixel 2)
openssl genrsa -out avb.pem 2048
$AVBTOOL extract_public_key --key avb.pem --output avb_pkmd.bin

popd

echo "========================================================"
echo "Copy $KEY_DIR/verity_user.der.x509 to the kernel source."
echo "========================================================"