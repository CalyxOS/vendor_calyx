ifeq ($(filter-out crosshatch blueline bonito sargo coral flame sunfish redfin bramble barbet oriole raven, $(VENDOR_DEVICE)),)
COMPAT_AUDIO := true
endif

# Default to material audio, compat audio is opt in
ifeq ($(COMPAT_AUDIO),true)
$(call inherit-product-if-exists, vendor/calyx/config/AudioPackage14Compat.mk)
else
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
endif

PRODUCT_COPY_FILES += \
    frameworks/base/data/sounds/effects/ogg/ChargingStarted.ogg:$(TARGET_COPY_OUT_PRODUCT)/media/audio/notifications/ChargingStarted.ogg \
    frameworks/base/data/sounds/effects/material/ogg/WirelessChargingStarted.ogg:$(TARGET_COPY_OUT_PRODUCT)/media/audio/notifications/WirelessChargingStarted.ogg

# Default sounds
PRODUCT_PRODUCT_PROPERTIES += \
    ro.config.alarm_alert=Oxygen.ogg \
    ro.config.notification_sound=Iapetus.ogg
