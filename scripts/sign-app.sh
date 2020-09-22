#!/bin/bash
# Signs given app with the appropriate key

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

DEVICE=$1
KEY_DIR=keys/$DEVICE
AAPT=bin/aapt
SIGNAPK=framework/signapk.jar
LIB=lib64

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 <device> <app> file.apk"
  echo "Supported apps: ${apps[@]}"
  exit 1
}

[[ $# -eq 2 ]] || error "incorrect number of arguments"

APP=${1}
APK=${2}
if [[ ! " ${apps[@]} " =~ " ${APP} " ]]; then
	error "Unsupported app ${APP}"
fi

APPKEY=${appkey[$APP]}
KEY=$KEY_DIR/${keymap[$APPKEY]}
SDK=$($AAPT dump badging $APK | grep sdkVersion | cut -d \' -f 2)

java -Djava.library.path=${LIB} -jar $SIGNAPK --min-sdk-version ${SDK} ${KEY}.x509.pem ${KEY}.pk8 ${APK} ${APP}-signed.apk
