#!/bin/bash
# Setup android-prepare-vendor for all supported devices

set -o nounset

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

APV=vendor/android-prepare-vendor

for device in ${devices[@]}; do 
	echo "Setting up vendor for $device ${buildid[$device]}"
	$APV/execute-all.sh -y --debugfs -d $device -b ${buildid[$device]} -o $APV || exit 1
done

rm -rf vendor/google_devices && mkdir vendor/google_devices

for device in ${devices[@]}; do
	cp -a $APV/$device/${buildid[$device]}/vendor/google_devices vendor/
	rm -rf $APV/$device/${buildid[$device]}/vendor*
done

# git -C $APV clean -fdx