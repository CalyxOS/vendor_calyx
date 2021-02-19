#!/bin/bash

KERNEL=$1
shift

# TODO basename $TOP
if [ -z $OUT_DIR_COMMON_BASE ]; then
	OUT_DIR=out/kernel/$KERNEL
else
	OUT_DIR=$OUT_DIR_COMMON_BASE/android11-qpr1/kernel/$KERNEL
fi

export KERNEL_OUT_DIR=$OUT_DIR
export OUT_DIR

if [[ $KERNEL == wahoo ]]; then
	BUILD_CONFIG=google/wahoo/build.config.calyx
elif [[ $KERNEL == crosshatch ]]; then
	BUILD_CONFIG=google/msm-4.9/build.config.bluecross_calyx
elif [[ $KERNEL == bonito ]]; then
	BUILD_CONFIG=google/msm-4.9/build.config.bonito_calyx
elif [[ $KERNEL == coral ]]; then
	BUILD_CONFIG=google/coral/build.config.floral_calyx
elif [[ $KERNEL == sunfish ]]; then
	BUILD_CONFIG=google/sunfish/build.config.sunfish_calyx
elif [[ $KERNEL == redbull ]]; then
	#BUILD_BOOT_IMG=true
	BUILD_CONFIG=google/redbull/build.config.redbull.calyx
else
	echo "Unsupported kernel $KERNEL"
	exit
fi

export BUILD_BOOT_IMG
export BUILD_CONFIG

build/build.sh "$@"

cp -a $OUT_DIR/dist/* ../device/google/${KERNEL}-kernel/

unset OUT_DIR