#!/bin/bash
#
# SPDX-FileCopyrightText: 2018 Daniel Micay
# SPDX-FileCopyrightText: 2018-2026 The Calyx Institute
# SPDX-License-Identifier: MIT OR Apache-2.0
#

set -euo pipefail
scriptpath="$(cd "$(dirname "$0")";pwd -P)"

read -a EXTRA_RELEASETOOLS_ARGS <<< "${EXTRA_RELEASETOOLS_ARGS:-}"
read -a EXTRA_OTA_ARGS <<< "${EXTRA_OTA_ARGS:-}"

source "$scriptpath/common.include.sh"
source "$scriptpath/metadata"

release_cleanup() {
  cleanup_signing_full || true
}
trap release_cleanup EXIT

error() {
  echo "error: $1, please try again" >&2
  echo "Usage: $0 device oldversion newversion"
  exit 1
}

[[ $# -eq 3 ]] ||  error "incorrect number of arguments"

DEVICE=$1
OLD=$2
NEW=$3

if [[ -d build/tools/releasetools ]]; then
  RELEASETOOLS_PATH=build/tools
else
  # For usage with otatools.zip
  RELEASETOOLS_PATH=.
  EXTRA_RELEASETOOLS_ARGS+=(-p .)
fi

prepare_for_signing_full "$0" "$@" || error "failed to prepare for signing"

OTAKEY=$(get_key other ota || exit $?)

$maybe_dry_run "$RELEASETOOLS_PATH/bin/ota_from_target_files" "${EXTRA_RELEASETOOLS_ARGS[@]}" "${EXTRA_OTA_ARGS[@]}" -k "$OTAKEY" \
  -i "archive/release-$DEVICE-$OLD/$DEVICE-target_files-$OLD.zip" \
  "archive/release-$DEVICE-$NEW/$DEVICE-target_files-$NEW.zip" \
  "archive/release-$DEVICE-$NEW/$DEVICE-incremental-$OLD-$NEW.zip"

$maybe_dry_run pushd "archive/release-$DEVICE-$NEW" || exit 1

echo "Calculating sha256sum for incremental"
$maybe_dry_run sha256sum "$DEVICE-incremental-$OLD-$NEW.zip" > "$DEVICE-incremental-$OLD-$NEW.zip.sha256sum"

$maybe_dry_run popd

release_cleanup || true
trap "" EXIT
