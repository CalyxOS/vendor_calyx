include vendor/calyx/config/version.mk

PRODUCT_PACKAGE_OVERLAYS += vendor/calyx/overlay/common
VENDOR_DEVICE := $(TARGET_PRODUCT:calyx_%=%)

ifeq ($(filter-out sdk_phone_x86 sdk_phone_x86_64 coral flame sunfish redfin bramble barbet, $(VENDOR_DEVICE)),)
PRODUCT_COPY_FILES += \
    vendor/calyx/prebuilt/bootanimation-9x19.zip:$(TARGET_COPY_OUT_PRODUCT)/media/bootanimation.zip
else
PRODUCT_COPY_FILES += \
    vendor/calyx/prebuilt/bootanimation-9x16.zip:$(TARGET_COPY_OUT_PRODUCT)/media/bootanimation.zip
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
    NavigationBarMode2ButtonOverlay

# Themes
PRODUCT_PACKAGES += \
    Backgrounds \
    CalyxThemesStub \
    CalyxBlackTheme \
    ThemePicker

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
    AuroraStorePrivilegedExtension \
    Etar \
    ExactCalculator \
    F-Droid \
    F-DroidPrivilegedExtension \
    TrichromeChrome \
    TrichromeWebView \
    Eleven \
    Firewall \
    Recorder \
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

# One-handed mode
PRODUCT_PRODUCT_PROPERTIES += \
    ro.support_one_handed_mode=true

# Calyx-specific broadcast actions whitelist
PRODUCT_COPY_FILES += \
    vendor/calyx/config/permissions/calyx-sysconfig.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/sysconfig/calyx-sysconfig.xml

# Calyx SDK
include vendor/calyx/config/calyx_sdk_common.mk

PRODUCT_PACKAGES += \
    CalyxParts \
    CalyxSettingsProvider
