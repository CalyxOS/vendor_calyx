PRODUCT_VERSION_MAJOR := 6
PRODUCT_VERSION_MINOR := 0
PRODUCT_VERSION_PATCH := 0
PRODUCT_VERSION_EXTRA :=

ifneq ($(OFFICIAL_BUILD),true)
PRODUCT_VERSION_EXTRA += -UNOFFICIAL
endif

CALYXOS_VERSION := $(PRODUCT_VERSION_MAJOR).$(PRODUCT_VERSION_MINOR).$(PRODUCT_VERSION_PATCH)$(strip $(PRODUCT_VERSION_EXTRA))

PRODUCT_PRODUCT_PROPERTIES += \
    ro.calyxos.version=$(CALYXOS_VERSION)

# BUILD_NUMBER
# See $top/calyx/scripts/release/version.sh
# last 2 of year,    yy * 1000000
# PRODUCT_VERSION_MAJOR * 100000
# PRODUCT_VERSION_MINOR * 1000
# PRODUCT_VERSION_PATCH * 10
# Last digit reserved
# Examples:
# 6.0.0 -> 24600000, otatest 24600001
# 6.0.1 -> 24600010
# 6.1.0 -> 24601000
# 6.10.10 -> 24610100
