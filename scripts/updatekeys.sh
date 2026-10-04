#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

if [ "${USE_PYTHON_UPDATEKEYS:-}" = y ]; then
  PYTHONPATH="$(cd "$(dirname "$0")";pwd -P)${PYTHONPATH:+:$PYTHONPATH}" \
    exec python3 -P -m signing updatekeys "$0" "$@"
fi

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 key_dir subject"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

extract_avb_public_key() {
  local private_key=$1 public_key=$2
  local derived="$public_key.tmp"
  "$AVBTOOL" extract_public_key --key "$private_key" --output "$derived" \
    || { rm -f "$derived"; return 1; }
  if cmp -s "$derived" "$public_key"; then
    rm -f "$derived"
  else
    mv "$derived" "$public_key"
  fi
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
GENVERITYKEY=${GENERATE_VERITY_KEY_BIN:-$TOP/bin/generate_verity_key}
AVBTOOL=${AVBTOOL_BIN:-$TOP/bin/avbtool}

load_keymapper

[[ -e ${GENVERITYKEY} ]] || error "${GENVERITYKEY} not found."
[[ -e ${AVBTOOL} ]] || error "${AVBTOOL} not found."
[[ -e $(which openssl) ]] || error "openssl not found in PATH."

[[ -d $1 ]] || error "key directory does not exist"

for k in "${keys_core[@]}"; do
  [ -n "$k" ] || continue
  keyval=$(get_key core "$k" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e ${keyval}.pk8 || ! -e ${keyval}.x509.pem ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
    [[ -e $keyval.x509.pem ]] || exit $?
  fi
done

for k in "${keys_apex_apk[@]}"; do
  [ -n "$k" ] || continue
  keyval=$(get_key apex_apk "$k" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e ${keyval}.pk8 || ! -e ${keyval}.x509.pem ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
    [[ -e $keyval.x509.pem ]] || exit $?
  fi
done

# AVB 2.0
keyval_vbmeta=$(get_key avb vbmeta "${KEY_SUFFIX:-}" || exit $?)
if [ "${USE_PYTHON_AVB:-}" = y ]; then
  PYTHONPATH="$SCRIPTPATH${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -P -m signing provision-avb-key \
      --private-key "$keyval_vbmeta" \
      --public-key "$AVB_CUSTOM_KEY" \
      --avbtool "$AVBTOOL"
else
  if [[ ! -e "$keyval_vbmeta" ]]; then
    openssl genrsa -out "$keyval_vbmeta" 4096
  fi
  extract_avb_public_key "$keyval_vbmeta" "$AVB_CUSTOM_KEY"
fi

keyval_vbmeta_system=$(get_key avb vbmeta_system "${KEY_SUFFIX:-}" || exit $?)
if [[ ! -e "$keyval_vbmeta_system" ]]; then
  if [ "${USE_PYTHON_AVB:-}" = y ]; then
    PYTHONPATH="$SCRIPTPATH${PYTHONPATH:+:$PYTHONPATH}" \
      python3 -P -m signing provision-rsa-key \
        --private-key "$keyval_vbmeta_system"
  else
    openssl genrsa -out "$keyval_vbmeta_system" 4096
  fi
fi

if [[ -e "${KEY_DIR%/}/avb_pkmd.bin" ]]; then
  mv "${KEY_DIR%/}/avb_pkmd.bin" "$AVB_CUSTOM_KEY"
fi

# Migration from 10 to 11
# ART apex was renamed, and bionic runtime was split out into a new apex
if [ "${USE_PYTHON_KEY_MIGRATION:-}" = y ]; then
  PYTHONPATH="$SCRIPTPATH${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -P -m signing migrate-runtime-key \
      --key-directory "${KEY_DIR%/}"
else
  if [[ -e ${KEY_DIR%/}/com.android.runtime.release.pk8 ]]; then
    mv "${KEY_DIR%/}/com.android.runtime.release.pk8" "${KEY_DIR%/}/com.android.runtime.pk8"
  fi
  if [[ -e ${KEY_DIR%/}/com.android.runtime.release.x509.pem ]]; then
    mv "${KEY_DIR%/}/com.android.runtime.release.x509.pem" "${KEY_DIR%/}/com.android.runtime.x509.pem"
  fi
fi

for apex in "${keys_apex[@]}"; do
  [ -n "$apex" ] || continue
  keyval=$(get_key apex_container "$apex" || exit $?)
  [ -n "$keyval" ] || continue
  if [[ ! -e $keyval.pk8 || ! -e $keyval.x509.pem ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
    [[ -e $keyval.x509.pem ]] || exit $?
  fi
done

for apex in "${keys_apex[@]}"; do
  [ -n "$apex" ] || continue
  keyval=$(KEY_SUFFIX= get_key apex_payload "$apex" || exit $?)
  [ -n "$keyval" ] || continue
  if [ "${USE_PYTHON_AVB:-}" = y ]; then
    PYTHONPATH="$SCRIPTPATH${PYTHONPATH:+:$PYTHONPATH}" \
      python3 -P -m signing provision-avb-key \
        --private-key "$keyval.pem" \
        --public-key "$keyval.avbpubkey" \
        --avbtool "$AVBTOOL"
  else
    if [[ ! -e $keyval.pem ]]; then
      openssl genrsa -out "$keyval.pem" 4096
    fi
    extract_avb_public_key "$keyval.pem" "$keyval.avbpubkey"
  fi
done
