#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

if [ "${USE_PYTHON_UPDATECOMMONKEYS:-}" = y ]; then
  PYTHONPATH="$(cd "$(dirname "$0")";pwd -P)${PYTHONPATH:+:$PYTHONPATH}" \
    exec python3 -P -m signing updatecommonkeys "$0" "$@"
fi

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

load_keymapper

KEY_DIR=$1
SUBJECT="$2"

[[ -e $(which openssl) ]] || error "openssl not found in PATH."
[[ -e $(which keytool) ]] || error "keytool not found in PATH."

[[ -d $KEY_DIR ]] || error "key directory does not exist"

pushd "$KEY_DIR"

# Convert chromium keystore
if [[ -e calyxos.keystore ]]; then
  keytool -importkeystore -srckeystore calyxos.keystore -destkeystore calyxos.p12 -srcstoretype jks -deststoretype pkcs12
  openssl pkcs12 -in calyxos.p12 -out calyxos.pem -nodes && rm calyxos.p12
  openssl x509 -in calyxos.pem -out chromium.x509.pem
  openssl pkcs8 -in calyxos.pem -out chromium.pk8 -outform DER -topk8 -nocrypt && rm calyxos.pem
fi

for k in "${keys_app[@]}"; do
  [ -n "$k" ] || continue
  keyval=$(KEY_DIR= get_key app "$k" || exit $?)
  keyval=$(basename "$keyval")
  if [[ ! -e ${keyval}.pk8 || ! -e ${keyval}.x509.pem ]]; then
    "$SCRIPTPATH/mkkey.sh" "$keyval" "$SUBJECT" \
      || true  # Broken script. Always returns failure.
    [[ -e $keyval.pk8 ]] || exit $?  # Exit if the private key does not exist after the above.
    [[ -e $keyval.x509.pem ]] || exit $?
  fi
done

popd
