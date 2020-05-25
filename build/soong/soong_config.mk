add_json_str_omitempty = $(if $(strip $(2)),$(call add_json_str, $(1), $(2)))
add_json_val_default = $(call add_json_val, $(1), $(if $(strip $(2)), $(2), $(3)))

_json_contents := $(_json_contents)    "Calyx":{$(newline)

# See build/core/soong_config.mk for the add_json_* functions you can use here.
$(call add_json_str_omitempty, Additional_gralloc_10_usage_bits, $(TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS))
$(call add_json_str_omitempty, Qcom_um_soong_namespace, $(if $(filter $(UM_PLATFORMS),$(TARGET_BOARD_PLATFORM)),$(QCOM_SOONG_NAMESPACE),))
$(call add_json_bool, Should_wait_for_qsee, $(filter true,$(TARGET_KEYMASTER_WAIT_FOR_QSEE)))
$(call add_json_bool, Supports_extended_compress_format, $(filter true,$(AUDIO_FEATURE_ENABLED_EXTENDED_COMPRESS_FORMAT)))
$(call add_json_bool, Supports_hw_fde, $(filter true,$(TARGET_HW_DISK_ENCRYPTION)))
$(call add_json_bool, Supports_hw_fde_perf, $(filter true,$(TARGET_HW_DISK_ENCRYPTION_PERF)))
$(call add_json_bool, Uses_qti_camera_device, $(filter true,$(TARGET_USES_QTI_CAMERA_DEVICE)))

# This causes the build system to strip out the last comma in our nested struct, to keep the JSON valid.
_json_contents := $(_json_contents)__SV_END

_json_contents := $(_json_contents)    },$(newline)
