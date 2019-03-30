DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common

PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation.zip:system/media/bootanimation.zip

# OTA Updater
PRODUCT_PACKAGES += \
	Updater

# SetupWizard
PRODUCT_PACKAGES += \
	CalyxSetupWizard

# Apps
PRODUCT_PACKAGES += \
	F-Droid \
	F-DroidPrivilegedExtension \
	Chromium

# Overlays
PRODUCT_PACKAGES += \
	CalyxOSF-DroidOverlay

# Temporary, for prebuilt apps
$(call inherit-product, vendor/calyx-tmp/common.mk)
