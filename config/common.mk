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

# Helper script for enabling USB data based on the current type-C role
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/vendor_bin/init.enable_usb_data.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.enable_usb_data.sh

# Debuggable builds will have USB activated early, when this property hasn't been set elsewhere.
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
PRODUCT_PRODUCT_PROPERTIES += \
    persist.init.trust_restrict_usb=0
endif

# Temporarily work around dexpreopting error with prebuilt APEX modules
DISABLE_DEXPREOPT_CHECK := true

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/apex/com.android.adbd.apex \
    system/apex/com.android.adservices.apex \
    system/apex/com.android.art.apex \
    system/apex/com.android.cellbroadcast.apex \
    system/apex/com.android.conscrypt.apex \
    system/apex/com.android.extservices.apex \
    system/apex/com.android.ipsec.apex \
    system/apex/com.android.media.swcodec.apex \
    system/apex/com.android.media.apex \
    system/apex/com.android.mediaprovider.apex \
    system/apex/com.android.neuralnetworks.apex \
    system/apex/com.android.permission.apex \
    system/apex/com.android.resolv.apex \
    system/apex/com.android.tethering.apex \
    system/apex/com.android.uwb.apex \
    system/apex/com.android.wifi.apex \

PRODUCT_PACKAGES += \
    com.android.adbd.prebuilt \
    com.android.adservices.prebuilt \
    com.android.appsearch.prebuilt \
    com.android.art.prebuilt \
    com.android.cellbroadcast.prebuilt \
    com.android.conscrypt.prebuilt \
    com.android.extservices.prebuilt \
    com.android.ipsec.prebuilt \
    com.android.media.swcodec.prebuilt \
    com.android.media.prebuilt \
    com.android.mediaprovider.prebuilt \
    com.android.neuralnetworks.prebuilt \
    com.android.os.statsd.prebuilt \
    com.android.permission.prebuilt \
    com.android.resolv.prebuilt \
    com.android.scheduling.prebuilt \
    com.android.sdkext.prebuilt \
    com.android.tethering.prebuilt \
    com.android.tzdata.prebuilt \
    com.android.uwb.prebuilt \
    com.android.wifi.prebuilt \
