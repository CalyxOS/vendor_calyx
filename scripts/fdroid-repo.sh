#!/bin/bash
# Update the local CalyxOS F-Droid repository

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
DATE=$(date +%F)
FDROIDREPOTMP=$(mktemp -d)
JOBID=$(curl -sI https://gitlab.com/calyxos/calyxos-fdroid-repo/-/jobs/artifacts/master/download?job=fdroid-repo | grep Location | cut -d / -f 8)

pushd $SCRIPTPATH/../../../prebuilts/calyx/
pushd $FDROIDREPOTMP
curl -L https://gitlab.com/calyxos/calyxos-fdroid-repo/-/jobs/${JOBID}/artifacts/download -o artifacts.zip || exit 1
unzip artifacts.zip
popd
rm -rf fdroid/repo
cp -a ${FDROIDREPOTMP}/public/fdroid/repo fdroid/
git add fdroid/repo
git commit -m "Update fdroid repo to ${JOBID}"
rm -rf ${FDROIDREPOTMP}
popd
