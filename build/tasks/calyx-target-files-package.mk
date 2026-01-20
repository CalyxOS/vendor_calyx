# Copyright (C) 2017 Unlegacy-Android
# Copyright (C) 2017,2020 The LineageOS Project
# Copyright (C) 2026 The Calyx Institute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------
# Calyx target_files package

BUILD_NUMBER_FROM_FILE := $(shell cat out/soong/build_number.txt)
CALYX_TARGET_FILES_PACKAGE := $(PRODUCT_OUT)/$(TARGET_PRODUCT)-target_files-$(BUILD_NUMBER_FROM_FILE).zip

SHA256 := prebuilts/build-tools/path/$(HOST_PREBUILT_TAG)/sha256sum

$(CALYX_TARGET_FILES_PACKAGE): $(BUILT_TARGET_FILES_PACKAGE)
	$(hide) ln -f $(BUILT_TARGET_FILES_PACKAGE) $(CALYX_TARGET_FILES_PACKAGE)
	$(hide) $(SHA256) $(CALYX_TARGET_FILES_PACKAGE) | sed "s|$(PRODUCT_OUT)/||" > $(CALYX_TARGET_FILES_PACKAGE).sha256sum
	@echo "Package Complete: $(CALYX_TARGET_FILES_PACKAGE)" >&2

.PHONY: calyx-target-files-package
calyx-target-files-package: $(CALYX_TARGET_FILES_PACKAGE) $(DEFAULT_GOAL)
