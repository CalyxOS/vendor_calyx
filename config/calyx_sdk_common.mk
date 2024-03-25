# Permissions for calyx sdk services
PRODUCT_COPY_FILES += \
    vendor/calyx/config/permissions/org.lineageos.globalactions.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.globalactions.xml \
    vendor/calyx/config/permissions/org.lineageos.hardware.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.hardware.xml \
    vendor/calyx/config/permissions/org.lineageos.health.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.health.xml \
    vendor/calyx/config/permissions/org.lineageos.livedisplay.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.livedisplay.xml \
    vendor/calyx/config/permissions/org.lineageos.settings.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.settings.xml \
    vendor/calyx/config/permissions/org.lineageos.trust.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.trust.xml \
    vendor/calyx/config/permissions/unavailable_features.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/unavailable_features.xml \

# Calyx Platform Library
PRODUCT_PACKAGES += \
    org.lineageos.platform-res \
    org.lineageos.platform

# AOSP has no support of loading framework resources from /system_ext
# so the SDK has to stay in /system for now
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/framework/oat/%/org.lineageos.platform.odex \
    system/framework/oat/%/org.lineageos.platform.vdex \
    system/framework/org.lineageos.platform-res.apk \
    system/framework/org.lineageos.platform.jar
