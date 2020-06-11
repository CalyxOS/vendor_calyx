include vendor/calyx/config/version.mk

DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common
VENDOR_DEVICE := $(TARGET_PRODUCT:calyx_%=%)

ifeq ($(filter-out coral flame, $(VENDOR_DEVICE)),)
PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation-9x19.zip:system/media/bootanimation.zip
else
PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation-9x16.zip:system/media/bootanimation.zip
endif

ifeq ($(OFFICIAL_BUILD),true)
# OTA Updater
PRODUCT_PACKAGES += \
	Updater
endif

# For Google Camera
ifeq ($(filter-out taimen walleye crosshatch blueline bonito sargo coral flame, $(VENDOR_DEVICE)),)
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
