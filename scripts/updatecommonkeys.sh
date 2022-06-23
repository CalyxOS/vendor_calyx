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

[[ ! -e $(which openssl) ]] && error "openssl not found in PATH."

[[ ! -d $KEY_DIR ]] && error "key directory does not exist"

pushd $KEY_DIR

for k in "${common_app_keys[@]}"; do
  if [[ ! -e ${k}.pk8 ]]; then
    $SCRIPTPATH/mkkey.sh "$k" "$SUBJECT"
  fi
done

popd
