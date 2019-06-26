DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common

PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation.zip:system/media/bootanimation.zip

ifeq ($(OFFICIAL_BUILD),true)
# OTA Updater
PRODUCT_PACKAGES += \
	Updater
endif

# SetupWizard
PRODUCT_PACKAGES += \
	CalyxSetupWizard

# Homescreen Layout
PRODUCT_PACKAGES += \
	CalyxLayout

# Local F-droid repo
PRODUCT_PACKAGES += \
	fdroid-repo \
	AuroraStore \
	Briar \
	CalyxVPN \
	Conversations \
	DAVx5 \
	DejaVuLocationService \
	DuckDuckGoPrivacyBrowser \
	K-9Mail \
	LocationPrivacy \
	Maps \
	MozillaNlpBackend \
	MuPDFviewer \
	NominatimNlpBackend \
	OONIProbe \
	OpenKeychain \
	Orbot \
	RiseupVPN \
	Signal \
	ScrambledExif \
	Tasks \
	TorBrowser \
	Weather \
	YubicoAuthenticator

# microG
PRODUCT_PACKAGES += \
	GmsCore \
	FakeStore

# Apps
PRODUCT_PACKAGES += \
	F-Droid \
	F-DroidPrivilegedExtension \
	Chromium
