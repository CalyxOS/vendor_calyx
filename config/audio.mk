# Default to old audio, material audio is opt in
OLD_AUDIO ?= true

ifeq ($(OLD_AUDIO),true)
$(call inherit-product-if-exists, frameworks/base/data/sounds/AllAudio.mk)
else
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
endif

# Default sounds
PRODUCT_PRODUCT_PROPERTIES += \
    ro.config.alarm_alert=Oxygen.ogg \
    ro.config.notification_sound=Iapetus.ogg \
    ro.config.ringtone=Umbriel.ogg
