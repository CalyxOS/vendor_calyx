#!/bin/bash

set -o errexit -o nounset -o pipefail

error() {
    echo error: $1 >&2
    echo "Usage: $0 key_dir"
    exit 1
}

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

[[ $# -ne 1 ]] && error "expected 1 argument (key directory)"

cd $1

read -p "Enter key passphrase (empty if none): " -s password
echo

tmp="$(mktemp -d /dev/shm/decrypt_keys.XXXXXXXXXX)"
trap "rm -rf \"$tmp\"" EXIT

export password

function decrypt_pk8() {
    key="$1"
    if [[ -n $password ]]; then
        openssl pkcs8 -inform DER -in $key.pk8 -passin env:password | openssl pkcs8 -topk8 -outform DER -out "$tmp/$key.pk8" -nocrypt
    else
        openssl pkcs8 -topk8 -inform DER -in $key.pk8 -outform DER -out "$tmp/$key.pk8" -nocrypt
    fi
}

function decrypt_pem() {
    key="$1"
    if [[ -n $password ]]; then
        openssl pkcs8 -topk8 -in $key.pem -passin env:password -out "$tmp/$key.pem" -nocrypt
    else
        openssl pkcs8 -topk8 -in $key.pem -out "$tmp/$key.pem" -nocrypt
    fi
}

for key in releasekey platform shared media networkstack; do
    decrypt_pk8 "$key"
done

decrypt_pk8 "verity"
decrypt_pem "avb"

for apex in "${apexes[@]}"; do
    decrypt_pk8 "${apex_container_key[$apex]}"
    decrypt_pem "${apex_payload_key[$apex]}"
done

unset password

mv "$tmp"/* .
