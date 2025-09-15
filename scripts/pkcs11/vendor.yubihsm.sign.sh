#!/bin/bash

source ./vendor/calyx/scripts/common.include.sh
source ./vendor/calyx/scripts/pkcs11/include.sh
source ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.include.sh

export BUILD_NUMBER="25610200"
export PREV_BUILD_NUMBER_PXL="25608200"
export PREV_BUILD_NUMBER_MOST="25608210"

error() {
	echo $@
	exit 1
}

[ ! -e archive ] && error "archive directory not found. It should contain the previous builds"

echo "Old build(s) needed:"
echo "  $PREV_BUILD_NUMBER_PXL"
echo "  $PREV_BUILD_NUMBER_MOST"
read -p "Kindly ensure their presence in the archive."

df -h .
# TODO: is 500GB enough for all devices? test this
read -p "Make sure there is 500GB free space. Press enter to continue."

# all devices except Pixel 9a
export TMPDIR=$(mktemp -d -p "${SIGN_TMPDIR:-/dev/shm}")
export STATEDIR=$(mktemp -d -p /dev/shm)
cleanup() {
  maybe_stop_yubihsm_connector "$STATEDIR/yubihsm_connector.pid"
  rm -rf "$TMPDIR"
  rm -rf "$STATEDIR"
}
trap cleanup EXIT
maybe_start_yubihsm_connector "$STATEDIR/yubihsm_connector.pid"
if [ -z "${YUBIHSM_CONNECTOR_PIDFILE:-}" ]; then
  echo
  echo "yubihsm-connector is already running."
  echo "This means we will not be able to restart it if it messes up."
  echo "Please stop the existing connector by stopping its service, if any,"
  echo "or by running killall yubihsm-connector"
  read -p "Press Enter to continue anyway, or CTRL-C to exit."
fi
export YUBIHSM_LOCKFILE=$STATEDIR/yubihsm.lock

if [ -z "${YUBIHSM_PKCS11_CONF:-}" ]; then
  export YUBIHSM_PKCS11_CONF=$STATEDIR/yubihsm_pkcs11.conf
  generate_yubihsm_pkcs11_library_config > "$YUBIHSM_PKCS11_CONF"
fi
maybe_start_apksigner_batch "$STATEDIR"

echo "Signing release for all devices except Pixel 9a"
# TODO: Fix all this, it's just temporary.
#parallel -j 7 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.release.sh {} calyx_{}-target_files-${BUILD_NUMBER}.zip ::: akita shiba bluejay FP5 hawao &
BUILD_NUMBER=25608200; parallel -j 3 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.release.sh {} calyx_{}-target_files-${BUILD_NUMBER}.zip ::: akita shiba bluejay &pid1=$!
# Stagger the next ones by at least 10 minutes.
sleep 600 &pidwait=$!
wait -n $pid1 $pidwait
BUILD_NUMBER=25608210; parallel -j 3 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.release.sh {} calyx_{}-target_files-${BUILD_NUMBER}.zip ::: FP5 hawao &pid2=$!
echo "Waiting for signing"
wait $pid1 $pid2

mv out/* archive/

# TODO: Don't exit here, it's just temporary.
maybe_stop_apksigner_batch "$STATEDIR"

exit 0

rm -rf "$TMPDIR"
export TMPDIR=$(mktemp -d -p "${SIGN_TMPDIR:-/dev/shm}")
# Deltas

#echo "Generating delta updates for Pixel 9"
#parallel -j 5 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.generate_delta.sh {} ${PREV_BUILD_NUMBER_PXL} ${BUILD_NUMBER} ::: comet komodo caiman tokay &

echo "Generating delta updates for Pixel 6/7/8"
parallel -j 3 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.generate_delta.sh {} ${PREV_BUILD_NUMBER_PXL} ${BUILD_NUMBER} ::: akita shiba bluejay &

wait

echo "Generating delta updates for remaining devices"
parallel -j 3 --tag --line-buffer ./vendor/calyx/scripts/pkcs11/vendor.yubihsm.generate_delta.sh {} ${PREV_BUILD_NUMBER_MOST} ${BUILD_NUMBER} ::: FP5 hawao &

wait
rm -rf "$TMPDIR"

echo
echo "Done signing and making deltas for all devices except Pixel 9a"
echo

echo "Please minisign -SHm out/release-*-${BUILD_NUMBER}/*-factory-${BUILD_NUMBER}.zip -t 'CalyxOS 6.10.20 - Paused update notice for all current installations'"
