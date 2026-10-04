#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

PYTHONPATH="$(cd "$(dirname "$0")";pwd -P)${PYTHONPATH:+:$PYTHONPATH}" \
  exec python3 -P -m signing mkkey "$0" "$@"

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 key_name subject"
  echo "Example key_name: networkstack"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

[[ $# -eq 2 ]] ||  error "incorrect number of arguments"

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP="$SCRIPTPATH/../../.."

KEY_NAME=$1
SUBJECT="$2"
MKKEY=${MAKE_KEY_BIN:-$TOP/development/tools/make_key}

[[ -e ${MKKEY} ]] || error "${MKKEY} not found"
[[ -e $(which openssl) ]] || error "openssl not found in PATH."

if [[ -e ${KEY_NAME}.pk8 && ! -e ${KEY_NAME}.x509.pem ]]; then
  echo "error: key $KEY_NAME exists without ${KEY_NAME}.x509.pem." >&2
  echo "Restore the certificate from a backup, or delete ${KEY_NAME}.pk8 if the key was never used." >&2
  exit 1
fi

[[ ! -e ${KEY_NAME}.pk8 ]] || error "key $KEY_NAME already exists"
[[ ! -e ${KEY_NAME}.pem ]] || error "key $KEY_NAME already exists"
[[ ! -e ${KEY_NAME}.x509.pem ]] || error "key $KEY_NAME already exists"

"$MKKEY" "$KEY_NAME" "$SUBJECT"
