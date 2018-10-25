PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation.zip:system/media/bootanimation.zip

# Apps
PRODUCT_PACKAGES += \
	F-Droid \
	F-DroidPrivelegedExtension

# Temporary, for prebuilt apps
$(call inherit-product, vendor/calyx-tmp/common.mk)
