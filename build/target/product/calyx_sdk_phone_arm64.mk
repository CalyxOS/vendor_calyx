# Copyright (C) 2021 The Calyx Institute
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

$(call inherit-product, build/target/product/sdk_phone_arm64.mk)

$(call inherit-product, vendor/calyx/config/common.mk)

TARGET_NO_KERNEL_OVERRIDE := true

# Overrides
PRODUCT_NAME := calyx_sdk_phone_arm64
PRODUCT_MODEL := CalyxOS Android SDK built for arm64
