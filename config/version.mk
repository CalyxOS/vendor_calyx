PRODUCT_VERSION_MAJOR := 5
PRODUCT_VERSION_MINOR := 8
PRODUCT_VERSION_PATCH := 2
PRODUCT_VERSION_EXTRA :=

ifneq ($(OFFICIAL_BUILD),true)
PRODUCT_VERSION_EXTRA += -UNOFFICIAL
endif

CALYXOS_VERSION := $(PRODUCT_VERSION_MAJOR).$(PRODUCT_VERSION_MINOR).$(PRODUCT_VERSION_PATCH)$(strip $(PRODUCT_VERSION_EXTRA))

# BUILD_NUMBER
# See $top/calyx/scripts/release/version.sh
# last 2 of year,    yy * 1000000
# PRODUCT_VERSION_MAJOR * 100000
# PRODUCT_VERSION_MINOR * 1000
# PRODUCT_VERSION_PATCH * 10
# Last digit reserved
# Examples:
# 5.0.0 -> 23500000, otatest 23500001
# 5.0.1 -> 23500010
# 5.1.0 -> 23501000
# 5.10.10 -> 23510100
