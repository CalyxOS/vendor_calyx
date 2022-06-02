#!/bin/bash
# Signs the Trichrome apks

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP=$SCRIPTPATH/../../../

source $SCRIPTPATH/metadata

KEY_DIR=$TOP/keys/common
APKSIGNER=$TOP/bin/apksigner
KEY=${KEY_DIR}/calyxos.keystore

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0"
  echo "Supported files: (TrichromeChrome6432) universal.apk TrichromeLibrary6432.apk TrichromeWebView6432.apk"
  exit 1
}

[[ $# -eq 0 ]] || error "incorrect number of arguments"

[[ ! -e ${KEY} ]] && error "$KEY not found"
[[ ! -e universal.apk ]] && error "(TrichromeChrome6432) universal.apk not found"
[[ ! -e TrichromeLibrary6432.apk ]] && error "TrichromeLibrary6432.apk not found"
[[ ! -e TrichromeWebView6432.apk ]] && error "TrichromeWebView6432.apk not found"

for APP in universal TrichromeLibrary6432 TrichromeWebView6432; do
	$APKSIGNER sign --ks ${KEY} --ks-key-alias calyxos --in ${APP}.apk --out ${APP}-signed.apk
done
