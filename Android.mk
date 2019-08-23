LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := repo-manifest
LOCAL_MODULE_CLASS := FAKE
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/Android.mk
$(LOCAL_BUILT_MODULE):
	$(hide) repo manifest -r -o $(TARGET_OUT_ETC)/repo-manifest.xml
	$(hide) touch $@

include $(call all-makefiles-under,$(LOCAL_PATH))