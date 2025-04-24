PATH_OVERRIDE_SOONG := $(shell echo $(TOOLS_PATH_OVERRIDE))

# Add variables that we wish to make available to soong here.
EXPORT_TO_SOONG := \
    KERNEL_ARCH \
    KERNEL_BUILD_OUT_PREFIX \
    KERNEL_CROSS_COMPILE \
    KERNEL_MAKE_CMD \
    KERNEL_MAKE_FLAGS \
    PATH_OVERRIDE_SOONG \
    TARGET_KERNEL_CONFIG \
    TARGET_KERNEL_SOURCE

# Setup SOONG_CONFIG_* vars to export the vars listed above.
# Documentation here:
# https://github.com/LineageOS/android_build_soong/commit/8328367c44085b948c003116c0ed74a047237a69

SOONG_CONFIG_NAMESPACES += calyxVarsPlugin

SOONG_CONFIG_calyxVarsPlugin :=

define addVar
  SOONG_CONFIG_calyxVarsPlugin += $(1)
  SOONG_CONFIG_calyxVarsPlugin_$(1) := $($1)
endef

$(foreach v,$(EXPORT_TO_SOONG),$(eval $(call addVar,$(v))))

SOONG_CONFIG_NAMESPACES += calyxGlobalVars
SOONG_CONFIG_calyxGlobalVars += \
    inline_kernel_building

# Soong bool variables
SOONG_CONFIG_calyxGlobalVars_inline_kernel_building := $(INLINE_KERNEL_BUILDING)

# Libui
TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS ?= 0

ifneq ($(TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS),)
    $(call soong_config_set,libui,additional_gralloc_10_usage_bits,$(TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS))
endif
