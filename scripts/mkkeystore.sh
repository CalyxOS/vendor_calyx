#!/bin/bash

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 key_name subject"
  echo "Example key_name: calyxos"
  echo "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'"
  exit 1
}

[[ $# -eq 2 ]] ||  error "incorrect number of arguments"

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

KEY_NAME=$1
SUBJECT="$2"
KEYTOOL=keytool

[[ ! -e $(which ${KEYTOOL}) ]] && error "${KEYTOOL} not found in PATH."

[[ -e ${KEY_NAME}.keystore ]] && error "key $KEY_NAME already exists"

DNAME="$(echo $SUBJECT | tr -d "'" | sed "s#/#,#g")"
DNAME=${DNAME:1}

$KEYTOOL -genkey -v -keystore ${KEY_NAME}.keystore -alias ${KEY_NAME} -dname "$DNAME" -keyalg RSA -keysize 2048 -validity 10000