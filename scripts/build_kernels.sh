#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

for k in wahoo crosshatch bonito coral sunfish redbull; do
	$SCRIPTPATH/build_kernel.sh $k
done