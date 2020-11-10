#!/bin/bash
# Setup android-prepare-vendor for all supported devices

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

APV=vendor/android-prepare-vendor

for device in ${devices[@]}; do
	echo "Setting up vendor for $device ${buildid[$device]}"
	$APV/execute-all.sh -y --debugfs -d $device -b ${buildid[$device]} -o $APV || exit 1
done

for device in ${devices[@]}; do
	rm -rf vendor/google_devices/$device/*
	cp -a $APV/$device/${buildid[$device]}/vendor/google_devices vendor/
	rm -rf $APV/$device/${buildid[$device]}/vendor*
done

# git -C $APV clean -fdx
