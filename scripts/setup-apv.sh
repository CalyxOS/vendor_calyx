#!/bin/bash
# Setup android-prepare-vendor for all supported devices

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

APV=vendor/android-prepare-vendor
OUTPUT=${APV_OUT:-APV}
ALL_DEVICES=${devices[@]}

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 device"
  echo "       Supported devices: ${ALL_DEVICES}"
  echo "       Pass 'all' for all supported devices"
  exit 1
}

[[ $# -ne 1 ]] && error "incorrect number of arguments"

APV_DEVICE=$1

if [[ ${APV_DEVICE} == "all" ]]; then
	apv_devices=${ALL_DEVICES}
else
	apv_devices=${APV_DEVICE}
fi

for device in ${apv_devices}; do
	echo "Setting up vendor for $device ${buildid[$device]}"
	echo "Running $APV/execute-all.sh -y --debugfs -d $device -b ${buildid[$device]} -o $OUTPUT"
	$APV/execute-all.sh -y --debugfs -d $device -b ${buildid[$device]} -o $OUTPUT || exit 1
done

for device in ${apv_devices}; do
	rm -rf vendor/google_devices/$device/*
	cp -a $OUTPUT/$device/${buildid[$device]}/vendor/google_devices vendor/
	rm -rf $APV/$device/${buildid[$device]}/vendor*
done

# git -C $APV clean -fdx
