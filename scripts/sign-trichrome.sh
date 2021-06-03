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
  echo "Supported files: TrichromeChrome.apk TrichromeLibrary.apk TrichromeWebView.apk"
  exit 1
}

[[ $# -eq 0 ]] || error "incorrect number of arguments"

[[ ! -e ${KEY} ]] && error "$KEY not found"
[[ ! -e TrichromeChrome.apk ]] && error "TrichromeChrome.aab not found"
[[ ! -e TrichromeLibrary.apk ]] && error "TrichromeLibrary.apk not found"
[[ ! -e TrichromeWebView.apk ]] && error "TrichromeWebView.apk not found"

for APP in TrichromeChrome TrichromeLibrary TrichromeWebView; do
	$APKSIGNER sign --ks ${KEY} --ks-key-alias calyxos --in ${APP}.apk --out ${APP}-signed.apk
done
