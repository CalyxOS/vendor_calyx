include vendor/calyx/config/version.mk

ifneq ($(wildcard vendor/google/gearhead/proprietary/),)
include device/google/gearhead/device.mk
include vendor/google/gearhead/gearhead-vendor.mk
else
$(warning "Building without Android Auto support")
endif

# Overlays
PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/calyx/overlay/no-rro
PRODUCT_PACKAGE_OVERLAYS += \
    vendor/calyx/overlay/common \
    vendor/calyx/overlay/no-rro

PRODUCT_PACKAGES += \
    CarrierConfigStandaloneEntriesOverlay \
    CellBroadcastReceiverOverlay \
    Launcher3Overlay \
    NfcOverlay \
    PermissionControllerOverlay

# Translations
CUSTOM_LOCALES += \
    ast_ES \
    gd_GB \
    cy_GB \
    fur_IT

PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/crowdin/overlay
PRODUCT_PACKAGE_OVERLAYS += vendor/crowdin/overlay

VENDOR_DEVICE := $(TARGET_PRODUCT:calyx_%=%)

ifneq ($(TARGET_DISABLE_EPPE),true)
# Require all requested packages to exist
$(call enforce-product-packages-exist-internal,$(wildcard device/*/$(VENDOR_DEVICE)/$(TARGET_PRODUCT).mk),product_manifest.xml rild Calendar)
endif

ifeq ($(OFFICIAL_BUILD),true)
# OTA Updater
PRODUCT_PACKAGES += \
    Updater
endif

# SetupWizard
PRODUCT_PACKAGES += \
    CalyxSetupWizard \
    LupinInstaller

PRODUCT_PRODUCT_PROPERTIES += \
    setupwizard.theme=glif_v4 \
    setupwizard.feature.day_night_mode_enabled=true

# Customization
PRODUCT_PACKAGES += \
    IconPackCircularAndroidOverlay \
    IconPackCircularLauncherOverlay \
    IconPackCircularSettingsOverlay \
    IconPackCircularSystemUIOverlay \
    IconPackFilledAndroidOverlay \
    IconPackFilledLauncherOverlay \
    IconPackFilledSettingsOverlay \
    IconPackFilledSystemUIOverlay \
    IconPackKaiAndroidOverlay \
    IconPackKaiLauncherOverlay \
    IconPackKaiSettingsOverlay \
    IconPackKaiSystemUIOverlay \
    IconPackRoundedAndroidOverlay \
    IconPackRoundedLauncherOverlay \
    IconPackRoundedSettingsOverlay \
    IconPackRoundedSystemUIOverlay \
    IconPackSamAndroidOverlay \
    IconPackSamLauncherOverlay \
    IconPackSamSettingsOverlay \
    IconPackSamSystemUIOverlay \
    IconPackVictorAndroidOverlay \
    IconPackVictorLauncherOverlay \
    IconPackVictorSettingsOverlay \
    IconPackVictorSystemUIOverlay \
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
    FakeStore

# Apps
PRODUCT_PACKAGES += \
    Aperture \
    AudioFX \
    AuroraStorePrivilegedExtension \
    AvatarPicker \
    BatteryStatsViewer \
    Bellis \
    Camelot \
    Datura \
    ESpeakNG \
    Etar \
    ExactCalculator \
    F-DroidPrivilegedExtension \
    Glimpse \
    Panic \
    Talkback \
    TrichromeChrome \
    TrichromeWebView \
    Twelve \
    Recorder \
    Seedvault \
    Ripple

# Config
PRODUCT_PACKAGES += \
    SimpleDeviceConfig

# Charger
PRODUCT_PACKAGES += \
    charger_res_images

ifneq ($(WITH_LINEAGE_CHARGER),false)
PRODUCT_PACKAGES += \
    lineage_charger_animation \
    lineage_charger_animation_vendor
endif

# Credential storage
PRODUCT_PACKAGES += \
    android.software.credentials.prebuilt.xml

# SystemUI plugins
PRODUCT_PACKAGES += \
    QuickAccessWallet

# TextClassifier
PRODUCT_PACKAGES += \
    libtextclassifier_annotator_en_model \
    libtextclassifier_annotator_universal_model \
    libtextclassifier_actions_suggestions_universal_model \
    libtextclassifier_lang_id_model

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/etc/textclassifier/actions_suggestions.universal.model \
    system/etc/textclassifier/lang_id.model \
    system/etc/textclassifier/textclassifier.en.model \
    system/etc/textclassifier/textclassifier.universal.model

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

# Enforce privapp-permissions allowlist
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    ro.control_privapp_permissions=enforce

# Helper script for enabling USB data based on the current type-C role
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/vendor_bin/init.enable_usb_data.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.enable_usb_data.sh

# Debuggable builds will have USB activated early, when this property hasn't been set elsewhere.
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
PRODUCT_PRODUCT_PROPERTIES += \
    persist.init.trust_restrict_usb=0
endif

# Include AOSP initial package stopped states.
PRODUCT_PACKAGES += \
    initial-package-stopped-states-aosp.xml

# Perform strict signature checking for particular system packages.
PRODUCT_PACKAGES += \
    preinstalled-packages-strict-signature-custom.xml

# Enable debugging for all processes on debuggable builds
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
PRODUCT_PRODUCT_PROPERTIES += \
    persist.debug.dalvik.vm.jdwp.enabled=1
endif
