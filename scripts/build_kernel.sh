#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
# kernel/
TOP=$(cd "$SCRIPTPATH/.."; pwd -P)
# vendor/calyx/scripts/
if [[ ! -e "$TOP/bootstrap.bash" ]]; then
	TOP=$(cd "$SCRIPTPATH/../../.."; pwd -P)
fi

KERNEL=$1
shift

if [ -z $OUT_DIR_COMMON_BASE ]; then
	OUT_DIR=$TOP/out/kernel/$KERNEL
else
	OUT_DIR=$OUT_DIR_COMMON_BASE/$(basename $TOP)/kernel/$KERNEL
fi

export KERNEL_OUT_DIR=$OUT_DIR
export OUT_DIR

case ${KERNEL} in
	wahoo)
		BUILD_CONFIG=google/wahoo/build.config.calyx
		;;
	crosshatch)
		BUILD_CONFIG=google/msm-4.9/build.config.bluecross_calyx
		;;
	bonito)
		BUILD_CONFIG=google/msm-4.9/build.config.bonito_calyx
		;;
	coral)
		BUILD_CONFIG=google/coral/build.config.floral_calyx
		;;
	sunfish)
		BUILD_CONFIG=google/sunfish/build.config.sunfish_calyx
		;;
	redbull)
		BUILD_CONFIG=google/redbull/build.config.redbull.calyx
		;;
	barbet)
		BUILD_CONFIG=google/barbet/build.config.barbet.calyx
		;;
	*)
		echo "Unsupported kernel $KERNEL"
		echo "Support kernels: wahoo crosshatch bonito coral sunfish redbull barbet"
		exit
		;;
esac

export BUILD_CONFIG

pushd ${TOP}/kernel

build/build.sh "$@"

popd

cp -a ${OUT_DIR}/dist/* ${TOP}/device/google/${KERNEL}-kernel/

unset OUT_DIR
