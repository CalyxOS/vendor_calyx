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

if [[
  $KEY_DIR =~ raven ||
  $KEY_DIR =~ cheetah ||
  $KEY_DIR =~ tangorpro || $KEY_DIR =~ felix
]]; then
  $SCRIPTPATH/mkkey.sh "com.qorvo.uwb" "$SUBJECT"
fi

# AVB 2.0
if [[
  $KEY_DIR =~ redfin || $KEY_DIR =~ bramble
]]; then
  openssl genrsa -out avb.pem 2048
  $AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
else
  openssl genrsa -out avb.pem 4096
  $AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
fi

if [[
  $KEY_DIR =~ panther || $KEY_DIR =~ cheetah || $KEY_DIR =~ lynx || $KEY_DIR =~ tangorpro || $KEY_DIR =~ felix ||
  $KEY_DIR =~ shiba || $KEY_DIR =~ husky || $KEY_DIR =~ akita ||
  $KEY_DIR =~ tokay || $KEY_DIR =~ caiman || $KEY_DIR =~ komodo || $KEY_DIR =~ comet
]]; then
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
