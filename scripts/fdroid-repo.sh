#!/bin/bash
# Update the local CalyxOS F-Droid repository

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
DATE=$(date +%F)
FDROIDREPOTMP=$(mktemp -d)
JOBID=$(curl -sI https://gitlab.com/calyxos/calyxos-fdroid-repo/-/jobs/artifacts/master/download?job=fdroid-repo | grep -iw Location: | cut -d / -f 8)

pushd $SCRIPTPATH/../../../prebuilts/calyx/
pushd $FDROIDREPOTMP
curl -L https://gitlab.com/calyxos/calyxos-fdroid-repo/-/jobs/${JOBID}/artifacts/download -o artifacts.zip || exit 1
unzip artifacts.zip
popd
rm -rf fdroid/repo
rm -rf fdroid/*.mk
cp -a ${FDROIDREPOTMP}/public/fdroid/repo fdroid/
# Temporary, due to copy-xml-file-checked TODO: Figure out a better solution, if possible
rm -f fdroid/repo/icons*/*.xml
ANDROID_MK=fdroid/Android.mk
FDROID_MK=fdroid/fdroid-repo.mk
FILES=$(find fdroid/repo/ -type f -not -name "*.apk" | sort)
APKS=$(cd fdroid/repo/ && find . -type f -name "*.apk" -printf "%P\n" | sort)
APPS=$(for apk in $APKS; do echo ${apk%.*}; done)

{
	echo "# Auto generated, do not edit."
	echo
	echo -e 'LOCAL_PATH := $(call my-dir)'
	echo
	echo -e 'include $(CLEAR_VARS)'
	echo -e 'LOCAL_MODULE := F-Droid'
	echo -e 'LOCAL_SRC_FILES := F-Droid.apk'
	echo -e 'LOCAL_CERTIFICATE := PRESIGNED'
	echo -e 'LOCAL_MODULE_CLASS := APPS'
	echo -e 'include $(BUILD_PREBUILT)'
	echo
	echo -e 'include $(CLEAR_VARS)'
	echo -e "LOCAL_MODULE := fdroid-repo"
	echo -e "LOCAL_MODULE_CLASS := ETC"
	echo -e "LOCAL_MODULE_TAGS := optional"
	echo -e 'LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/org.fdroid.fdroid'
	echo -e "LOCAL_MODULE_STEM := additional_repos.xml"
	echo -e "LOCAL_SRC_FILES := additional_repos.xml"
	echo -e 'include $(BUILD_PREBUILT)'
	echo
} > $ANDROID_MK

for app in $APPS; do
	{
	echo -e 'include $(CLEAR_VARS)'
	echo -e "LOCAL_MODULE := $app"
	echo -e 'LOCAL_SRC_FILES := repo/$(LOCAL_MODULE).apk'
	echo -e 'LOCAL_MODULE_PATH := $(PRODUCT_OUT)/$(TARGET_COPY_OUT_PRODUCT)/fdroid/repo'
	echo -e "LOCAL_CERTIFICATE := PRESIGNED"
	echo -e "LOCAL_MODULE_CLASS := APPS"
	echo -e "LOCAL_DEX_PREOPT := false"
	echo -e "LOCAL_NO_STANDARD_LIBRARIES := true"
	echo -e 'LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/repo/$(LOCAL_MODULE).apk'
	echo -e 'include $(BUILD_PREBUILT)'
	echo
	} >> $ANDROID_MK
done

{
	echo "# Auto generated, do not edit."
	echo
	echo "PRODUCT_COPY_FILES += \\"
} > $FDROID_MK

for f in $FILES; do
	{
		echo -e "    prebuilts/calyx/$f:\$(TARGET_COPY_OUT_PRODUCT)/$f \\"
	} >> $FDROID_MK
done

{
	echo
	echo "PRODUCT_PACKAGES += \\"
	echo "    fdroid-repo \\"
} >> $FDROID_MK

for app in $APPS; do
	echo "    $app \\" >> $FDROID_MK
done

git add fdroid/repo fdroid/*.mk
git commit -m "Update fdroid repo to ${JOBID}"
rm -rf ${FDROIDREPOTMP}

popd

