include vendor/calyx/config/version.mk

DEVICE_PACKAGE_OVERLAYS += vendor/calyx/overlay/common
VENDOR_DEVICE := $(TARGET_PRODUCT:calyx_%=%)

ifeq ($(filter-out coral flame sunfish redfin bramble, $(VENDOR_DEVICE)),)
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

# SetupWizard
PRODUCT_PACKAGES += \
    CalyxSetupWizard

# Customization
PRODUCT_PACKAGES += \
    IconShapeRoundOverlay \
    IconShapeSquareOverlay \
    NavigationBarMode2ButtonOverlay

# Themes
PRODUCT_PACKAGES += \
    Backgrounds \
    CalyxThemesStub \
    ThemePicker

# Include {Lato,Rubik} fonts
$(call inherit-product-if-exists, external/google-fonts/lato/fonts.mk)
$(call inherit-product-if-exists, external/google-fonts/rubik/fonts.mk)

# Fonts
PRODUCT_PACKAGES += \
    fonts_customization.xml \
    LineageLatoFont \
    LineageRubikFont

# Local F-droid repo
$(call inherit-product, prebuilts/calyx/fdroid/fdroid-repo.mk)

# microG
PRODUCT_PACKAGES += \
    GmsCore \
    GsfProxy \
    FakeStore \
    DejaVuLocationService \
    MozillaNlpBackend \
    NominatimNlpBackend

# Apps
PRODUCT_PACKAGES += \
    Etar \
    ExactCalculator \
    F-Droid \
    F-DroidPrivilegedExtension \
    TrichromeChrome \
    TrichromeWebView \
    Eleven \
    Seedvault \
    Ripple

# Config
PRODUCT_PACKAGES += \
    SimpleDeviceConfig

# Overlays
PRODUCT_PACKAGES += \
    CellBroadcastReceiverOverlay

# Sensitive Phone Numbers list
PRODUCT_PACKAGES += \
    sensitive_pn.xml

# SystemUI plugins
PRODUCT_PACKAGES += \
    QuickAccessWallet

PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    persist.security.deny_new_usb=dynamic

PRODUCT_COPY_FILES += \
    vendor/calyx/prebuilt/deny_new_usb.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/deny_new_usb.rc