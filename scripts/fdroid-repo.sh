#!/bin/bash
# Update the local CalyxOS F-Droid repository

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
DATE=$(date +%F)
FDROIDREPOTMP=$(mktemp -d)
JOBID=$(curl -sI https://gitlab.com/CalyxOS/calyxos-fdroid-repo/-/jobs/artifacts/main/download?job=fdroid-repo | grep -iw Location: | cut -d / -f 8)
ANDROID_BP=Android.bp
FDROID_MK=fdroid-repo.mk

pushd $SCRIPTPATH/../../../prebuilts/calyx/fdroid
pushd $FDROIDREPOTMP
curl -L https://gitlab.com/CalyxOS/calyxos-fdroid-repo/-/jobs/${JOBID}/artifacts/download -o artifacts.zip || exit 1
unzip artifacts.zip
popd
rm -rf repo
rm -rf $ANDROID_BP $FDROID_MK
cp -a ${FDROIDREPOTMP}/public/fdroid/repo .
chmod 755 repo
# Temporary, due to copy-xml-file-checked TODO: Figure out a better solution, if possible
rm -f repo/icons*/*.xml
FILES=$(find repo/ -type f -not -name "*.apk" | sort)
APKS=$(cd repo/ && find . -type f -name "*.apk" -printf "%P\n" | sort)
APPS=$(for apk in $APKS; do echo ${apk%.*}; done)

{
	echo '# Auto generated, do not edit.'
	echo
	echo -e 'prebuilt_etc {'
	echo -e '    name: "fdroid-repo",'
	echo
	echo -e '    product_specific: true,'
	echo -e '    src: "additional_repos.xml",'
	echo -e '    relative_install_path: "org.fdroid.fdroid",'
	echo -e '}'
	echo
	echo -e 'prebuilt_etc {'
	echo -e '    name: "fdroid-debug-repo",'
	echo
	echo -e '    product_specific: true,'
	echo -e '    src: "additional_repos.xml",'
	echo -e '    relative_install_path: "org.fdroid.fdroid.debug",'
	echo -e '}'
	echo
  echo -e 'prebuilt_etc {'
  echo -e '    name: "fdroid-basic-repo",'
  echo
  echo -e '    product_specific: true,'
  echo -e '    src: "additional_repos.xml",'
  echo -e '    relative_install_path: "org.fdroid.basic",'
  echo -e '}'
  echo
  echo -e 'prebuilt_etc {'
  echo -e '    name: "fdroid-basic-debug-repo",'
  echo
  echo -e '    product_specific: true,'
  echo -e '    src: "additional_repos.xml",'
  echo -e '    relative_install_path: "org.fdroid.basic.debug",'
  echo -e '}'
  echo
  echo -e 'prebuilt_etc {'
  echo -e '    name: "aurora-store",'
  echo
  echo -e '    product_specific: true,'
  echo -e '    src: "aurora-store-blacklist.xml",'
  echo -e '    relative_install_path: "com.aurora.store",'
  echo -e '}'
	echo
} > $ANDROID_BP

for app in $APPS; do
	{
	echo -e 'android_app_import {'
	echo -e '    name: "$app",'
	echo
	echo -e '    relative_install_path: "fdroid/repo",'
	echo
	echo -e '    dex_preopt: {'
	echo -e '        enabled: false,'
	echo -e '    },'
	echo
	echo -e '    preprocessed: true,'
	echo -e '    enforce_uses_libs: false,'
	echo -e '    apk: "repo/$app.apk",'
	echo -e '    presigned: true,'
	echo -e '}'
	echo
	} >> $ANDROID_BP
done

{
	echo "# Auto generated, do not edit."
	echo
	echo "PRODUCT_COPY_FILES += \\"
	echo -e "    prebuilts/calyx/fdroid/fallback-icon.png:\$(TARGET_COPY_OUT_PRODUCT)/fdroid/repo/fallback-icon.png \\"
} > $FDROID_MK

for f in $FILES; do
	{
		echo -e "    prebuilts/calyx/fdroid/$f:\$(TARGET_COPY_OUT_PRODUCT)/fdroid/$f \\"
	} >> $FDROID_MK
done

{
	echo
	echo "PRODUCT_PACKAGES += \\"
	echo "    fdroid-repo \\"
	echo "    fdroid-debug-repo \\"
	echo "    fdroid-basic-repo \\"
	echo "    fdroid-basic-debug-repo \\"
	echo "    aurora-store \\"
} >> $FDROID_MK

for app in $APPS; do
	echo "    $app \\" >> $FDROID_MK
done

git add repo $ANDROID_BP $FDROID_MK
git commit -m "Update fdroid repo to ${JOBID}"
rm -rf ${FDROIDREPOTMP}

popd

