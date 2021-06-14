# Copyright (C) 2018-2020 The LineageOS Project
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

$(call inherit-product, build/target/product/aosp_arm64.mk)
$(call inherit-product, build/target/product/gsi_release.mk)

$(call inherit-product, vendor/calyx/config/common.mk)

TARGET_NO_KERNEL_OVERRIDE := true

# These apps require access to hidden API so they need to stay in /system
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/app/Firewall/oat/arm64/Firewall.odex \
    system/app/Firewall/oat/arm64/Firewall.vdex \
    system/priv-app/Seedvault/oat/arm64/Seedvault.odex \
    system/priv-app/Seedvault/oat/arm64/Seedvault.vdex

PRODUCT_NAME := calyx_arm64
