#!/bin/bash

set -o errexit -o nounset -o pipefail

source "$(dirname ${BASH_SOURCE[0]})/common.sh"

[[ $# -ne 1 ]] && user_error "expected 1 argument (key directory)"

cd $1

read -p "Enter key passphrase (empty if none): " -s password
echo

tmp="$(mktemp -d /dev/shm/decrypt_keys.XXXXXXXXXX)"
trap "rm -rf \"$tmp\"" EXIT

export password

for key in releasekey platform shared media networkstack; do
    if [[ -n $password ]]; then
        openssl pkcs8 -inform DER -in $key.pk8 -passin env:password | openssl pkcs8 -topk8 -outform DER -out "$tmp/$key.pk8" -nocrypt
    else
        openssl pkcs8 -topk8 -inform DER -in $key.pk8 -outform DER -out "$tmp/$key.pk8" -nocrypt
    fi
done

if [[ -f avb.pem ]]; then
    if [[ -n $password ]]; then
        openssl pkcs8 -topk8 -in avb.pem -passin env:password -out "$tmp/avb.pem" -nocrypt
    else
        openssl pkcs8 -topk8 -in avb.pem -out "$tmp/avb.pem" -nocrypt
    fi
fi

unset password

mv "$tmp"/* .
