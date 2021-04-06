#!/bin/bash
# Signs the Trichrome apks

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TOP=$SCRIPTPATH/../../../

source $SCRIPTPATH/metadata

KEY_DIR=$TOP/keys/common
APKSIGNER=$TOP/bin/apksigner
KEY=${KEY_DIR}/calyxos.keystore
BUNDLETOOL=$TOP/"bundletool-all-1.4.0.jar"
AAPT2=$TOP/aapt2

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0"
  echo "Supported files: TrichromeChrome.aab TrichromeLibrary.apk TrichromeWebView.apk"
  exit 1
}

[[ $# -eq 0 ]] || error "incorrect number of arguments"

[[ ! -e ${KEY} ]] && error "$KEY not found"
[[ ! -e TrichromeChrome.aab ]] && error "TrichromeChrome.aab not found"
[[ ! -e TrichromeLibrary.apk ]] && error "TrichromeLibrary.apk not found"
[[ ! -e TrichromeWebView.apk ]] && error "TrichromeWebView.apk not found"
[[ ! -e ${BUNDLETOOL} ]] && error "${BUNDLETOOL} not found."
[[ ! -e ${AAPT2} ]] && error "${AAPT2} not found."

[[ -e TrichromeChrome.apks ]] && error "TrichromeChrome.apks already exists"
[[ -e TrichromeChrome.apk ]] && error "TrichromeChrome.apk already exists"

java -jar ${BUNDLETOOL} build-apks --bundle TrichromeChrome.aab --output TrichromeChrome.apks --mode=universal --aapt2 $AAPT2 --ks ${KEY} --ks-key-alias calyxos
unzip TrichromeChrome.apks universal.apk && mv universal.apk TrichromeChrome-signed.apk

for APP in TrichromeLibrary TrichromeWebView; do
	$APKSIGNER sign --ks ${KEY} --ks-key-alias calyxos --in ${APP}.apk --out ${APP}-signed.apk
done
