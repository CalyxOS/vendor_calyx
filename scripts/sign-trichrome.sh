#!/bin/bash
# Signs the Trichrome apks

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

KEY_DIR=keys
APKSIGNER=bin/apksigner
KEY=${KEY_DIR}/calyxos.keystore
BUNDLETOOL="bundletool-all-0.12.0.jar"
BUNDLETOOL_URL="https://github.com/google/bundletool/releases"

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
[[ ! -e ${BUNDLETOOL} ]] && error "${BUNDLETOOL} not found. Get it from ${BUNDLETOOL_URL}"

[[ -e TrichromeChrome.apks ]] && error "TrichromeChrome.apks already exists"
[[ -e TrichromeChrome.apk ]] && error "TrichromeChrome.apk already exists"

java -jar ${BUNDLETOOL} build-apks --bundle TrichromeChrome.aab --output TrichromeChrome.apks --mode=universal --ks ${KEY} --ks-key-alias calyxos
unzip TrichromeChrome.apks universal.apk && mv universal.apk TrichromeChrome-signed.apk

for APP in TrichromeLibrary TrichromeWebView; do
	cp ${APP}.apk ${APP}-signed.apk
	$APKSIGNER sign --ks ${KEY} --ks-key-alias calyxos ${APP}-signed.apk
done