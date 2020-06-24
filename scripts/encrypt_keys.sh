#!/bin/bash

set -o errexit -o nounset -o pipefail

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

error() {
    echo error: $1 >&2
    echo "Usage: $0 key_dir"
    exit 1
}

[[ $# -ne 1 ]] && error "expected 1 argument (key directory)"

cd $1

read -p "Enter old key passphrase (empty if none): " -s password
echo

read -p "Enter new key passphrase: " -s new_password
echo
read -p "Confirm new key passphrase: " -s confirm_new_password
echo

if [[ $new_password != $confirm_new_password ]]; then
    echo new password does not match
    exit 1
fi

tmp="$(mktemp -d /dev/shm/encrypt_keys.XXXXXXXXXX)"
trap "rm -rf \"$tmp\"" EXIT

export password
export new_password

function encrypt_pk8() {
    key="$1"
    if [[ -n $password ]]; then
        openssl pkcs8 -inform DER -in $key.pk8 -passin env:password | openssl pkcs8 -topk8 -outform DER -out "$tmp/$key.pk8" -passout env:new_password -scrypt
    else
        openssl pkcs8 -topk8 -inform DER -in $key.pk8 -outform DER -out "$tmp/$key.pk8" -passout env:new_password -scrypt
    fi
}

function encrypt_pem() {
    key="$1"
    if [[ -n $password ]]; then
        openssl pkcs8 -topk8 -in $key.pem -passin env:password -out "$tmp/$key.pem" -passout env:new_password -scrypt
    else
        openssl pkcs8 -topk8 -in $key.pem -out "$tmp/$key.pem" -passout env:new_password -scrypt
    fi
}

for key in releasekey platform shared media networkstack; do
    encrypt_pk8 "$key"
done

encrypt_pk8 "verity"
encrypt_pem "avb"

for apex in "${apexes[@]}"; do
    encrypt_pk8 "${apex_container_key[$apex]}"
    encrypt_pem "${apex_payload_key[$apex]}"
done

unset password
unset new_password

mv "$tmp"/* .
