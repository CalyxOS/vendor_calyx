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

cat <<EOL > $ANDROID_BP
// Auto generated, do not edit.

prebuilt_etc_xml {
    name: "fdroid-repo",
    product_specific: true,
    src: "additional_repos.xml",
    filename_from_src: true,
    sub_dir: "org.fdroid.fdroid",
}

prebuilt_etc_xml {
    name: "fdroid-debug-repo",
    product_specific: true,
    src: "additional_repos.xml",
    filename_from_src: true,
    sub_dir: "org.fdroid.fdroid.debug",
}

prebuilt_etc_xml {
    name: "fdroid-basic-repo",
    product_specific: true,
    src: "additional_repos.xml",
    filename_from_src: true,
    sub_dir: "org.fdroid.basic",
}

prebuilt_etc_xml {
    name: "fdroid-basic-debug-repo",
    product_specific: true,
    src: "additional_repos.xml",
    filename_from_src: true,
    sub_dir: "org.fdroid.basic.debug",
}

prebuilt_etc_xml {
    name: "aurora-store",
    product_specific: true,
    src: "aurora-store-blacklist.xml",
    filename_from_src: false,
    filename: "blacklist.xml",
    sub_dir: "com.aurora.store",
}
EOL

for app in $APPS; do
    cat <<EOL >> $ANDROID_BP
android_app_import {
    name: "$app",
    relative_install_path: "fdroid/repo",
    dex_preopt: {
        enabled: false,
    },
    preprocessed: true,
    product_specific: true,
    enforce_uses_libs: false,
    apk: "repo/$app.apk",
    presigned: true,
EOL

    if ! $SCRIPTPATH/../../../build/soong/scripts/check_prebuilt_presigned_apk.py --zipalign $SCRIPTPATH/../../../out/host/linux-x86/bin/zipalign --preprocessed repo/$app.apk /tmp/$app.apk; then
        echo -e "    skip_preprocessed_apk_checks: true," >> $ANDROID_BP
    fi

    cat <<EOL >> $ANDROID_BP
}

EOL
done

cat <<EOL > $FDROID_MK
# Auto generated, do not edit.

PRODUCT_COPY_FILES += \\
    prebuilts/calyx/fdroid/fallback-icon.png:\$(TARGET_COPY_OUT_PRODUCT)/fdroid/repo/fallback-icon.png \\
EOL

for f in $FILES; do
    echo -e "    prebuilts/calyx/fdroid/$f:\$(TARGET_COPY_OUT_PRODUCT)/fdroid/$f \\" >> $FDROID_MK
done

cat <<EOL >> $FDROID_MK

PRODUCT_PACKAGES += \\
    fdroid-repo \\
    fdroid-debug-repo \\
    fdroid-basic-repo \\
    fdroid-basic-debug-repo \\
    aurora-store \\
EOL

for app in $APPS; do
	echo "    $app \\" >> $FDROID_MK
done

git add repo $ANDROID_BP $FDROID_MK
git commit -m "Update fdroid repo to ${JOBID}"
rm -rf ${FDROIDREPOTMP}

popd
