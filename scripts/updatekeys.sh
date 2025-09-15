#!/bin/bash

set -euo pipefail

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 key_dir subject"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

[[ $# -eq 2 ]] ||  error "incorrect number of arguments"

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP="$SCRIPTPATH/../../.."

source "$SCRIPTPATH/metadata"
source "$SCRIPTPATH/common.include.sh"

# For legacy reasons, the DEVICE is taken from the path, i.e. keys/DEVICE.
# The legacy keymapper generates a $KEY_DIR/$DEVICE path which should result in the same path.
DEVICE=$(basename "$1")
KEY_DIR=$(dirname "${1%/}")/
SUBJECT="$2"
GENVERITYKEY=$TOP/bin/generate_verity_key
AVBTOOL=$TOP/bin/avbtool

load_keymapper

[[ -e ${GENVERITYKEY} ]] || error "${GENVERITYKEY} not found."
[[ -e ${AVBTOOL} ]] || error "${AVBTOOL} not found."
[[ -e $(which openssl) ]] || error "openssl not found in PATH."

[[ -d $1 ]] || error "key directory does not exist"

for k in "${keys_core[@]}"; do
  keyval=$(get_key core "$k" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e ${keyval}.pk8 ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
  fi
done

for k in "${keys_apex_apk[@]}"; do
  keyval=$(get_key apex_apk "$k" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e ${keyval}.pk8 ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
  fi
done

# AVB 2.0
keyval_vbmeta=$(get_key avb vbmeta || exit $?)
if [[ ! -e "$keyval_vbmeta" ]]; then
  if [[
    $KEY_DIR =~ redfin || $KEY_DIR =~ bramble
  ]]; then
    openssl genrsa -out "$keyval_vbmeta" 2048
  else
    openssl genrsa -out "$keyval_vbmeta" 4096
  fi
fi
"$AVBTOOL" extract_public_key --key "$keyval_vbmeta" --output "$AVB_CUSTOM_KEY"

keyval_vbmeta_system=$(get_key avb vbmeta_system || exit $?)
if [ "$keyval_vbmeta_system" != "$keyval" ]; then
  openssl genrsa -out "$keyval_vbmeta_system" 4096
fi

if [[ -e "${KEY_DIR%/}/avb_pkmd.bin" ]]; then
  mv "${KEY_DIR%/}/avb_pkmd.bin" "$AVB_CUSTOM_KEY"
fi

# Migration from 10 to 11
# ART apex was renamed, and bionic runtime was split out into a new apex
if [[ -e ${KEY_DIR%/}/com.android.runtime.release.pk8 ]]; then
  mv "${KEY_DIR%/}/com.android.runtime.release.pk8" "${KEY_DIR%/}/com.android.runtime.pk8"
fi
if [[ -e ${KEY_DIR%/}/com.android.runtime.release.x509.pem ]]; then
  mv "${KEY_DIR%/}/com.android.runtime.release.x509.pem" "${KEY_DIR%/}/com.android.runtime.x509.pem"
fi

for apex in "${keys_apex[@]}"; do
  keyval=$(get_key apex_container "$apex" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e $keyval.pk8 ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
  fi
done

for apex in "${keys_apex[@]}"; do
  keyval=$(KEY_SUFFIX= get_key apex_payload "$apex" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e $keyval.pem ]]; then
    openssl genrsa -out "$keyval.pem" 4096
    "$AVBTOOL" extract_public_key --key "$keyval.pem" --output "$keyval.avbpubkey"
  fi
done
