include vendor/calyx/config/version.mk

# Overlays
PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/calyx/overlay/no-rro
PRODUCT_PACKAGE_OVERLAYS += \
    vendor/calyx/overlay/common \
    vendor/calyx/overlay/no-rro

PRODUCT_PACKAGES += \
    CellBroadcastReceiverOverlay \
    Launcher3Overlay

# Translations
PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/crowdin/overlay
PRODUCT_PACKAGE_OVERLAYS += vendor/crowdin/overlay

VENDOR_DEVICE := $(TARGET_PRODUCT:calyx_%=%)

ifeq ($(OFFICIAL_BUILD),true)
# OTA Updater
PRODUCT_PACKAGES += \
    CalyxSystemUpdater \
    Updater
endif

# SetupWizard
PRODUCT_PACKAGES += \
    CalyxSetupWizard \
    LupinInstaller

# Customization
PRODUCT_PACKAGES += \
    CalyxNavigationBarNoHint \
    IconShapePebbleOverlay \
    IconShapeRoundedRectOverlay \
    IconShapeSquareOverlay \
    IconShapeSquircleOverlay \
    IconShapeTaperedRectOverlay \
    IconShapeTeardropOverlay \
    IconShapeVesselOverlay

# Themes
PRODUCT_PACKAGES += \
    Backgrounds \
    CalyxBlackTheme \
    ThemePicker \
    ThemesStub

# Include {Lato,Rubik} fonts
$(call inherit-product-if-exists, external/google-fonts/lato/fonts.mk)
$(call inherit-product-if-exists, external/google-fonts/rubik/fonts.mk)

# Fonts
PRODUCT_PACKAGES += \
    fonts_customization.xml \
    FontLatoOverlay \
    FontRubikOverlay

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
    Aperture \
    AudioFX \
    AuroraStorePrivilegedExtension \
    BatteryStatsViewer \
    Bellis \
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

# Charger
PRODUCT_PACKAGES += \
    charger_res_images

ifeq ($(WITH_LINEAGE_CHARGER),true)
PRODUCT_PACKAGES += \
    lineage_charger_animation \
    lineage_charger_animation_vendor
endif

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
    vendor/calyx/config/permissions/calyx-sysconfig.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/calyx-sysconfig.xml

# Calyx SDK
include vendor/calyx/config/calyx_sdk_common.mk

PRODUCT_PACKAGES += \
    CalyxParts \
    CalyxSettingsProvider

# Audio
include vendor/calyx/config/audio.mk

# SystemUI
PRODUCT_DEXPREOPT_SPEED_APPS += \
    SystemUI

PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    dalvik.vm.systemuicompilerfilter=speed
