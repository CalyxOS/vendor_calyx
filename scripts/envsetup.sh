source build/envsetup.sh

export LANG=en_US.UTF-8
export _JAVA_OPTIONS=-XX:-UsePerfData
if [[ -n $OFFICIAL_BUILD ]]; then
export BUILD_NUMBER=$(cat out/build_number.txt 2>/dev/null || date --utc +%Y.%m.%d.%H)
echo "BUILD_NUMBER=$BUILD_NUMBER"
export DISPLAY_BUILD_NUMBER=true
else
echo "NOT an official build"
fi
export CALYX_BUILD=true
chrt -b -p 0 $$

function aospremote()
{
    if ! git rev-parse --git-dir &> /dev/null
    then
        echo ".git directory not found. Please run this from the root directory of the Android repository you wish to set up."
        return 1
    fi
    git remote rm aosp 2> /dev/null
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
