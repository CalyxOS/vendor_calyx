#!/bin/bash

error() {
  echo error: $1, please try again >&2
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
MKKEY=$TOP/development/tools/make_key

[[ ! -e ${MKKEY} ]] && error "${MKKEY} not found"
[[ ! -e $(which openssl) ]] && error "openssl not found in PATH."

[[ -e ${KEY_NAME}.pk8 ]] && error "key $KEY_NAME already exists"
[[ -e ${KEY_NAME}.pem ]] && error "key $KEY_NAME already exists"
[[ -e ${KEY_NAME}.x509.pem ]] && error "key $KEY_NAME already exists"

$MKKEY "$KEY_NAME" "$SUBJECT"