#!/bin/bash

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 device oldversion newversion"
  exit 1
}

[[ $# -eq 3 ]] ||  error "incorrect number of arguments"

DEVICE=$1
KEY_DIR=keys/$DEVICE
OLD=$2
NEW=$3

if [[ -d build/tools/releasetools ]]; then
  RELEASETOOLS_PATH=build/tools
else
  # For usage with otatools.zip
  RELEASETOOLS_PATH=.
  EXTRA_RELEASETOOLS_ARGS="-p ."
fi

$RELEASETOOLS_PATH/bin/ota_from_target_files $EXTRA_RELEASETOOLS_ARGS -k "$KEY_DIR/releasekey" \
  -i archive/release-$DEVICE-$OLD/$DEVICE-target_files-$OLD.zip \
  archive/release-$DEVICE-$NEW/$DEVICE-target_files-$NEW.zip \
  archive/release-$DEVICE-$NEW/$DEVICE-incremental-$OLD-$NEW.zip

echo "Calculating sha256sum for incremental"
sha256sum archive/release-$DEVICE-$NEW/$DEVICE-incremental-$OLD-$NEW.zip | awk '{printf $1}' > archive/release-$DEVICE-$NEW/$DEVICE-incremental-$OLD-$NEW.zip.sha256sum
