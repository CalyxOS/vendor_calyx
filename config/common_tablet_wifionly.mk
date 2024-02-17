$(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)

# Inherit common CalyxOS stuff
$(call inherit-product, vendor/calyx/config/common.mk)

$(call inherit-product, vendor/calyx/config/wifionly.mk)
