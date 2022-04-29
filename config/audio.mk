# Default to old audio, new audio is opt in
OLD_AUDIO ?= true
NEW_AUDIO ?= false

ifeq ($(OLD_AUDIO),true)
$(call inherit-product-if-exists, frameworks/base/data/sounds/AllAudio.mk)
else ifeq ($(NEW_AUDIO),true)
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
endif
