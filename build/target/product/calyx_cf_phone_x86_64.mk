# SPDX-FileCopyrightText: 2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0

$(call inherit-product, device/google/cuttlefish/vsoc_x86_64/phone/aosp_cf.mk)

$(call inherit-product, vendor/calyx/config/common.mk)

TARGET_NO_KERNEL_OVERRIDE := true

# Overrides
PRODUCT_NAME := calyx_cf_phone_x86_64
PRODUCT_MODEL := CalyxOS Cuttlefish phone built for x86_64
