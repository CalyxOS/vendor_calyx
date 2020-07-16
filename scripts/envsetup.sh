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
