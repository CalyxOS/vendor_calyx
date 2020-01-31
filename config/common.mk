include vendor/calyx/config/version.mk

DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common

PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation.zip:system/media/bootanimation.zip

ifeq ($(OFFICIAL_BUILD),true)
# OTA Updater
PRODUCT_PACKAGES += \
	Updater
endif

# For Google Camera
ifeq ($(filter-out taimen walleye crosshatch blueline bonito sargo, $(TARGET_DEVICE)),)
PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/google_experience.xml:system/etc/sysconfig/google_experience.xml
endif

# SetupWizard
PRODUCT_PACKAGES += \
	CalyxSetupWizard

# Homescreen Layout
PRODUCT_PACKAGES += \
	CalyxLayout

# Branding
PRODUCT_PACKAGES += \
	AccentColorCalyxOverlay

PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
	ro.boot.vendor.overlay.theme=org.calyxos.theme.android

# Local F-droid repo
$(call inherit-product, prebuilts/calyx/fdroid/fdroid-repo.mk)

# microG
PRODUCT_PACKAGES += \
	GmsCore \
	FakeStore \
	DejaVuLocationService \
	MozillaNlpBackend \
	NominatimNlpBackend

# Apps
PRODUCT_PACKAGES += \
	F-Droid \
	F-DroidPrivilegedExtension \
	TrichromeChrome \
	TrichromeWebView \
	Eleven \
	Seedvault \
	Ripple
