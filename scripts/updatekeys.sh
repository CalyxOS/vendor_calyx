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
source $SCRIPTPATH/keymapper_legacy.sh

KEY_DIR=${1%/}
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
    com.android.uwb.resources com.android.nearby.halfsheet com.android.graphics.pdf \
    com.android.appsearch.apk com.android.healthconnect.controller \
    com.android.health.connect.backuprestore com.android.nfcservices \
    com.android.federatedcompute; do
  if [[ ! -e ${k}.pk8 ]]; then
    $SCRIPTPATH/mkkey.sh "$k" "$SUBJECT"
  fi
done

if [[
  $KEY_DIR =~ raven ||
  $KEY_DIR =~ cheetah ||
  $KEY_DIR =~ tangorpro || $KEY_DIR =~ felix
]]; then
  if [[ ! -e com.qorvo.uwb.pk8 ]]; then
    $SCRIPTPATH/mkkey.sh "com.qorvo.uwb" "$SUBJECT"
  fi
fi

# AVB 2.0
if [[ ! -e avb.pem ]]; then
  if [[
    $KEY_DIR =~ redfin || $KEY_DIR =~ bramble
  ]]; then
    openssl genrsa -out avb.pem 2048
    $AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
  else
    openssl genrsa -out avb.pem 4096
    $AVBTOOL extract_public_key --key avb.pem --output avb_custom_key.img
  fi
fi

if [[
  $KEY_DIR =~ panther || $KEY_DIR =~ cheetah || $KEY_DIR =~ lynx || $KEY_DIR =~ tangorpro || $KEY_DIR =~ felix ||
  $KEY_DIR =~ shiba || $KEY_DIR =~ husky || $KEY_DIR =~ akita ||
  $KEY_DIR =~ tokay || $KEY_DIR =~ caiman || $KEY_DIR =~ komodo || $KEY_DIR =~ comet || $KEY_DIR =~ tegu
]]; then
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

for apex in "${keys_apex[@]}"; do
  $SCRIPTPATH/mkkey.sh "$(KEY_DIR= get_key apex_container "$apex")" "$SUBJECT"
done

for apex in "${keys_apex[@]}"; do
  keyval="$(KEY_DIR= KEY_SUFFIX= get_key apex_payload "$apex")"
  openssl genrsa -out "$keyval.pem" 4096
  $AVBTOOL extract_public_key --key "$keyval.pem" --output "$keyval.avbpubkey"
done

popd
