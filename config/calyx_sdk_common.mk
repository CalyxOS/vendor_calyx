# Permissions for calyx sdk services
PRODUCT_COPY_FILES += \
    vendor/calyx/config/permissions/org.lineageos.globalactions.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/org.lineageos.globalactions.xml \
    vendor/calyx/config/permissions/org.lineageos.hardware.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/org.lineageos.hardware.xml \
    vendor/calyx/config/permissions/org.lineageos.livedisplay.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/org.lineageos.livedisplay.xml \
    vendor/calyx/config/permissions/org.lineageos.settings.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/org.lineageos.settings.xml \
    vendor/calyx/config/permissions/org.lineageos.trust.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/org.lineageos.trust.xml

# Calyx Platform Library
PRODUCT_PACKAGES += \
    org.lineageos.platform-res \
    org.lineageos.platform

# AOSP has no support of loading framework resources from /system_ext
# so the SDK has to stay in /system for now
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/etc/permissions/org.lineageos.globalactions.xml \
    system/etc/permissions/org.lineageos.hardware.xml \
    system/etc/permissions/org.lineageos.livedisplay.xml \
    system/etc/permissions/org.lineageos.settings.xml \
    system/etc/permissions/org.lineageos.trust.xml \
    system/framework/oat/%/org.lineageos.platform.odex \
    system/framework/oat/%/org.lineageos.platform.vdex \
    system/framework/org.lineageos.platform-res.apk \
    system/framework/org.lineageos.platform.jar
