$(call inherit-product, $(SRC_TARGET_DIR)/product/large_screen_common.mk)

# Tablet-specific overlay
PRODUCT_PACKAGE_OVERLAYS += vendor/calyx/overlay/tablet

# Freeform window management
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.software.freeform_window_management.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/android.software.freeform_window_management.xml
