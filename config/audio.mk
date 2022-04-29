# Default to old audio, material audio is opt in
OLD_AUDIO ?= true

ifeq ($(OLD_AUDIO),true)
$(call inherit-product-if-exists, frameworks/base/data/sounds/AllAudio.mk)
else
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
endif
