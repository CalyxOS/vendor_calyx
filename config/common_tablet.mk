# Inherit common CalyxOS stuff
$(call inherit-product, vendor/calyx/config/common.mk)

# Inherit tablet common CalyxOS stuff
$(call inherit-product, vendor/calyx/config/tablet.mk)

$(call inherit-product, vendor/calyx/config/telephony.mk)
