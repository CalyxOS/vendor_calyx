ifeq ($(WITH_DEXPREOPT),true)
# AOSP has no support of loading framework resources from /system_ext
# so the SDK has to stay in /system for now
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/framework/oat/arm64/org.lineageos.platform.odex \
    system/framework/oat/arm64/org.lineageos.platform.vdex

# These apps require access to hidden API so they need to stay in /system
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/app/Firewall/oat/arm64/Firewall.odex \
    system/app/Firewall/oat/arm64/Firewall.vdex \
    system/priv-app/Seedvault/oat/arm64/Seedvault.odex \
    system/priv-app/Seedvault/oat/arm64/Seedvault.vdex
endif
