# Permissions for calyx sdk services
PRODUCT_COPY_FILES += \
    vendor/calyx/config/permissions/org.lineageos.globalactions.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.globalactions.xml \
    vendor/calyx/config/permissions/org.lineageos.hardware.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.hardware.xml \
    vendor/calyx/config/permissions/org.lineageos.livedisplay.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.livedisplay.xml \
    vendor/calyx/config/permissions/org.lineageos.settings.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.settings.xml \
    vendor/calyx/config/permissions/org.lineageos.trust.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.lineageos.trust.xml

# Calyx Platform Library
PRODUCT_PACKAGES += \
    org.lineageos.platform-res \
    org.lineageos.platform
