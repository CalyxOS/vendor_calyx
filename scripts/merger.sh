#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
KERNEL_MERGER=$SCRIPTPATH/../../../calyx/scripts/aosp-merger/kernel-merger.sh

source $SCRIPTPATH/metadata

for kernel in "${!kernel_tags[@]}"; do
	prev_kernel_tag=${prev_kernel_tags[$kernel]}
	kernel_tag=${kernel_tags[$kernel]}
	if [[ $kernel_tag == $prev_kernel_tag ]]; then continue; fi
	kernel_path=kernel/$(echo $kernel | sed s/dot/\./ | sed s/dash/\-/ | sed s#_#/#)
	$KERNEL_MERGER $kernel_path merge $prev_kernel_tag $kernel_tag
	if [[ -v ${kernel[@]} ]]; then
		kernel_modules="$kernel[@]"
		for kernel_module in "${!kernel_modules}"; do
			kernel_module_path=$(echo $kernel_module | sed s#_#/#)
			$KERNEL_MERGER $kernel_path/$kernel_module_path merge $prev_kernel_tag $kernel_tag
		done
	fi
done