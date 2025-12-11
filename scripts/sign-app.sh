#!/usr/bin/env bash
# Signs given app with the appropriate key

set -euo pipefail

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
MAIN_PATH="$(realpath "$SCRIPTPATH/../../../")"
KEY_DIR="$MAIN_PATH/keys"

source "$SCRIPTPATH/metadata"
source "$SCRIPTPATH/common.include.sh"

# ask for username and password
ask_variable YUBIHSM_AUTHKEY "0x0001" n y || return $?
ask_variable YUBIHSM_PASSWORD "" y y || return $?
export YUBIHSM_AUTHKEY YUBIHSM_PASSWORD

source "$SCRIPTPATH/metadata"
source "$SCRIPTPATH/keymapper.static.include.sh"
source "$SCRIPTPATH/pkcs11/include.sh"
source "$SCRIPTPATH/pkcs11/vendor.yubihsm.include.sh"

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 <app> file.apk"
  echo "Supported apps: ${keys_app[@]}"
  exit 1
}

[[ $# -eq 2 ]] || error "incorrect number of arguments"

APP=${1}
APK=${2}
if [ ! -f "$APK" ]; then
    error "$APK is not an existing regular file or does not exist." >&2
fi
if [[ ! " ${keys_app[@]} " =~ " ${APP} " ]]; then
  error "Unsupported app ${APP}"
fi

main() {
  # get key ID for app
  KEY_ID=$(get_key_id "app" "$APP")

  # generate PKCS#11 config for Java
  SUN_CONFIG_PATH="${TMPDIR:-"/tmp"}/sunpkcs11.cfg"
  generate_sunpkcs11_config > "$SUN_CONFIG_PATH"

  # disable batch signing, this is just for one app
  export NEVER_START_APKSIGNER_BATCH="y"

  # this is needed so HSM access will actually work
  initialize_vendor

  # set file name for audit logging
  read_yubihsm_deviceinfo || return $?
  name=$(get_name_for_hsm) || return $?
  AUDIT_LOG_PATH="$YUBIHSM_LOGS_DIR/$name/$(get_formatted_date)-$APP.log"
  export AUDIT_LOG_PATH

  # run the actual signing command via the interceptor that also gets used for build signing
  INTERCEPTOR="$SCRIPTPATH/pkcs11/vendor.yubihsm.interceptor.sh"
  export SIGNING_COMMAND=java # having to pass the actual command via this variable is an interceptor thing
  print_and_run "$INTERCEPTOR" \
    -Xmx4096m \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
    -Djava.library.path="$MAIN_PATH/lib64" \
    -jar "$MAIN_PATH/framework/apksigner.jar" \
    sign \
    --v4-signing-enabled=false --min-sdk-version 30 \
    --ks NONE --ks-type PKCS11 --ks-pass env:PKCS11_PIN \
    --provider-class sun.security.pkcs11.SunPKCS11 \
    --provider-arg "$SUN_CONFIG_PATH" \
    --ks-key-alias "${KEY_ID}" \
    --out "${APK%.*}-signed.apk" "${APK}" && echo "Signed $APK successfully"
}

main "$@"
