# Makefile to build the CalyxOS Android SDK System Image and its XML.

ifeq ($(filter $(MAKECMDGOALS), calyx_emu_imgs),)
SDK_SYSIMG_DEPS     := $(INTERNAL_EMULATOR_PACKAGE_TARGET)
SDK_SYSIMG_XML      := $(PRODUCT_OUT)/repo-sys-img.xml
SDK_SYSIMG_XML_ARGS := system-image any $(INTERNAL_EMULATOR_PACKAGE_TARGET)
SDK_SYSIMG_XSD := \
    $(lastword \
      $(wildcard \
        prebuilts/devtools/repository/sdk-sys-img-*.xsd \
    ))

# Defines the rule to build an XML file for a package.
#
# $1=output file
# $2=schema file
# $3=deps
# $4=args
define mk-sdk-repo-xml
$(1): $$(XMLLINT) development/build/tools/mk_sdk_repo_xml.sh $(2) $(3)
	XMLLINT=$$(XMLLINT) OFFICIAL_BUILD=$$(OFFICIAL_BUILD) development/build/tools/mk_sdk_repo_xml.sh $$@ $(2) $(4)
endef

# -----------------------------------------------------------------

$(eval $(call mk-sdk-repo-xml,$(SDK_SYSIMG_XML),$(SDK_SYSIMG_XSD),$(SDK_SYSIMG_DEPS),$(SDK_SYSIMG_XML_ARGS)))

# -----------------------------------------------------------------

.PHONY: calyx_emu_imgs
calyx_emu_imgs: $(INTERNAL_EMULATOR_PACKAGE_TARGET) $(SDK_SYSIMG_XML)
endif
