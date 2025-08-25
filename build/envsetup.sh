CLANG_VERSION=$(build/soong/scripts/get_clang_version.py)
export LLVM_AOSP_PREBUILTS_VERSION="${CLANG_VERSION}"

RUST_VERSION=$(grep 'RustDefaultVersion =' build/soong/rust/config/global.go | awk '{print $3}' | awk -F '"' '{print $2}')
export RUST_AOSP_PREBUILTS_VERSION="${RUST_VERSION}"

# Find the top directory
# Slightly modified from build/make/shell_utils.sh
function _gettop
{
    local TOPFILE=vendor/calyx/build/envsetup.sh
    # The ${TOP-} expansion allows this to work even with set -u
    if [ -n "${TOP:-}" -a -f "${TOP:-}/$TOPFILE" ] ; then
        # The following circumlocution ensures we remove symlinks from TOP.
        (cd "$TOP"; PWD= /bin/pwd)
    else
        if [ -f $TOPFILE ] ; then
            # The following circumlocution (repeated below as well) ensures
            # that we record the true directory name and not one that is
            # faked up with symlink names.
            PWD= /bin/pwd
        else
            local HERE=$PWD
            local T=
            while [ \( ! \( -f $TOPFILE \) \) -a \( "$PWD" != "/" \) ]; do
                \cd ..
                T=`PWD= /bin/pwd -P`
            done
            \cd "$HERE"
            if [ -f "$T/$TOPFILE" ]; then
                echo "$T"
            fi
        fi
    fi
}

# Find the output directory
# From build/soong/scripts/microfactory.bash
function _getoutdir
{
    local out_dir="${OUT_DIR-}"
    if [ -z "${out_dir}" ]; then
        if [ "${OUT_DIR_COMMON_BASE-}" ]; then
            out_dir="${OUT_DIR_COMMON_BASE}/$(basename ${ANDROID_BUILD_TOP})"
        else
            out_dir="out"
        fi
    fi
    if [[ "${out_dir}" != /* ]]; then
        out_dir="${ANDROID_BUILD_TOP}/${out_dir}"
    fi
    echo "${out_dir}"
}

if [[ $OFFICIAL_BUILD = "true" ]]; then
export BUILD_NUMBER=$(cat $(_getoutdir)/build_number.txt 2>/dev/null || "${ANDROID_BUILD_TOP}/calyx/scripts/release/version.sh")
echo "BUILD_NUMBER=$BUILD_NUMBER"
export DISPLAY_BUILD_NUMBER=true
else
echo "NOT an official build"
fi
export CALYX_BUILD=true

function breakfast()
{
    target=$1
    local variant=$2
    source ${ANDROID_BUILD_TOP}/calyx/scripts/vars/aosp_target_release

    if [ $# -eq 0 ]; then
        # No arguments, so let's have the full menu
        lunch
    else
        if [[ "$target" =~ -(user|userdebug|eng)$ ]]; then
            # A buildtype was specified, assume a full device name
            lunch $target
        else
            # This is probably just the Calyx model name
            if [ -z "$variant" ]; then
                variant="userdebug"
            fi

            lunch calyx_$target-$aosp_target_release-$variant
        fi
    fi
    return $?
}

function aospremote()
{
    if ! git rev-parse --git-dir &> /dev/null
    then
        echo ".git directory not found. Please run this from the root directory of the Android repository you wish to set up."
        return 1
    fi
    git remote rm aosp 2> /dev/null

    if [ -f ".gitupstream" ]; then
        local REMOTE=$(cat .gitupstream | cut -d ' ' -f 1)
        git remote add aosp ${REMOTE}
    else
        local PROJECT=$(pwd -P | sed -e "s#$ANDROID_BUILD_TOP\/##")
        # Google moved the repo location in Oreo
        if [ $PROJECT = "build/make" ]
        then
            PROJECT="build"
        fi
        if (echo $PROJECT | grep -qv "^device")
        then
            local PFX="platform/"
        fi
        git remote add aosp https://android.googlesource.com/$PFX$PROJECT
    fi
    echo "Remote 'aosp' created"
}

function calyxremote()
{
    if ! git rev-parse --git-dir &> /dev/null
    then
        echo ".git directory not found. Please run this from the root directory of the Android repository you wish to set up."
        return 1
    fi
    git remote rm calyx 2> /dev/null
    local REMOTE=$(git config --get remote.gitlab.projectname)
    local CALYX="true"
    if [ -z "$REMOTE" ]
    then
        REMOTE=$(git config --get remote.gitlab-main.projectname)
    fi
    if [ -z "$REMOTE" ]
    then
        REMOTE=$(git config --get remote.gitlab-priv.projectname)
    fi
    if [ -z "$REMOTE" ]
    then
        REMOTE=$(git config --get remote.aosp.projectname)
        CALYX="false"
    fi

    if [ $CALYX = "false" ]
    then
        local PROJECT=$(echo $REMOTE | sed -e "s#/#_#g")
        local PFX="CalyxOS/"
    else
        local PROJECT=$REMOTE
    fi

    local CALYX_USER=$(git config --get review.review.calyxos.org.username)
    if [ -z "$CALYX_USER" ]
    then
        git remote add calyx ssh://review.calyxos.org:29418/$PFX$PROJECT
    else
        git remote add calyx ssh://$CALYX_USER@review.calyxos.org:29418/$PFX$PROJECT
    fi
    echo "Remote 'calyx' created"
}

function lineageremote()
{
    if ! git rev-parse --git-dir &> /dev/null
    then
        echo ".git directory not found. Please run this from the root directory of the Android repository you wish to set up."
        return 1
    fi
    git remote rm lineage 2> /dev/null

    if [ -f ".gitupstream-lineage" ]; then
        local REMOTE=$(cat .gitupstream-lineage | cut -d ' ' -f 1)
        git remote add lineage ${REMOTE}
    else
        local REMOTE=$(git config --get remote.gitlab.projectname)
        if [ -z "$REMOTE" ]
        then
            REMOTE=$(git config --get remote.gitlab-priv.projectname)
        fi

        local PROJECT=$(echo $REMOTE | sed -e "s#CalyxOS/##g; s#platform_#android_#g; s#vendor_#android_vendor_#g;")

        git remote add lineage https://github.com/LineageOS/$PROJECT
    fi
    echo "Remote 'lineage' created"
}

function repopick() {
    T=$(_gettop)
    $T/vendor/calyx/build/tools/repopick.py $@
}

function fixup_common_out_dir() {
    common_out_dir=$(_get_build_var_cached OUT_DIR)/target/common
    target_device=$(_get_build_var_cached TARGET_DEVICE)
    common_target_out=common-${target_device}
    if [ ! -z $CALYX_FIXUP_COMMON_OUT ]; then
        if [ -d ${common_out_dir} ] && [ ! -L ${common_out_dir} ]; then
            mv ${common_out_dir} ${common_out_dir}-${target_device}
            ln -s ${common_target_out} ${common_out_dir}
        else
            [ -L ${common_out_dir} ] && rm ${common_out_dir}
            mkdir -p ${common_out_dir}-${target_device}
            ln -s ${common_target_out} ${common_out_dir}
        fi
    else
        [ -L ${common_out_dir} ] && rm ${common_out_dir}
        mkdir -p ${common_out_dir}
    fi
}
