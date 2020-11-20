#!/bin/bash
# Signs given app with the appropriate key

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

DEVICE=$1
KEY_DIR=keys/$DEVICE
APKSIGNER=bin/apksigner

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 <device> <app> file.apk"
  echo "Supported apps: ${apps[@]}"
  exit 1
}

[[ $# -eq 3 ]] || error "incorrect number of arguments"

APP=${2}
APK=${3}
if [[ ! " ${apps[@]} " =~ " ${APP} " ]]; then
	error "Unsupported app ${APP}"
fi

APPKEY=${appkey[$APP]}
KEY=$KEY_DIR/${keymap[$APPKEY]}

$APKSIGNER sign --key ${KEY}.pk8 --cert ${KEY}.x509.pem --in ${APK} --out ${APP}-signed-${DEVICE}.apk
