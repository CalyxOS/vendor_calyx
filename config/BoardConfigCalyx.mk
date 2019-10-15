include vendor/calyx/config/BoardConfigKernel.mk

ifeq ($(BOARD_USES_QCOM_HARDWARE),true)
include vendor/calyx/config/BoardConfigQcom.mk
endif

include vendor/calyx/config/BoardConfigSoong.mk
