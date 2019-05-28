DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common

PRODUCT_COPY_FILES += \
	vendor/calyx/prebuilt/bootanimation.zip:system/media/bootanimation.zip

# OTA Updater
PRODUCT_PACKAGES += \
	Updater

# SetupWizard
PRODUCT_PACKAGES += \
	CalyxSetupWizard

# Homescreen Layout
PRODUCT_PACKAGES += \
	CalyxLayout

# Local F-droid repo
PRODUCT_PACKAGES += \
	fdroid-repo \
	Briar \
	CalyxVPN \
	Conversations \
	DuckDuckGoPrivacyBrowser \
	K-9Mail \
	MozillaNlpBackend \
	MuPDFviewer \
	OONIProbe \
	OpenKeychain \
	Orbot \
	RiseupVPN \
	Signal \
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