LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := repo-manifest
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_SRC_FILES := repo-manifest
include $(BUILD_PREBUILT)
$(LOCAL_BUILT_MODULE):
	$(hide) $(shell repo manifest -r -o $(TARGET_OUT_ETC)/repo-manifest.xml)
	$(hide) touch $@

include $(call all-makefiles-under,$(LOCAL_PATH))