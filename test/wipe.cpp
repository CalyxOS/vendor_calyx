/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <unordered_map>
#include <vector>
#include <map>
#include <iostream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android-base/endian.h>

// FS headers
#include <ext4_utils/wipe.h>
#include <fs_mgr.h>
#include <fs_mgr/roots.h>

// Nugget headers
#include <app_nugget.h>
#include <nos/NuggetClient.h>
#include <nos/debug.h>

static android::fs_mgr::Fstab fstab;
enum WipeVolumeStatus {
    WIPE_OK = 0,
    VOL_FSTAB,
    VOL_UNKNOWN,
    VOL_MOUNTED,
    VOL_BLK_DEV_OPEN,
    WIPE_ERROR_MAX = 0xffffffff,
};
std::map<enum WipeVolumeStatus, std::string> wipe_vol_ret_msg{
        {WIPE_OK, ""},
        {VOL_FSTAB, "Unknown FS table"},
        {VOL_UNKNOWN, "Unknown volume"},
        {VOL_MOUNTED, "Fail to unmount volume"},
        {VOL_BLK_DEV_OPEN, "Fail to open block device"},
        {WIPE_ERROR_MAX, "Unknown wipe error"}};

enum WipeVolumeStatus wipe_volume(const std::string &volume) {
    if (!android::fs_mgr::ReadDefaultFstab(&fstab)) {
        return VOL_FSTAB;
    }
    const android::fs_mgr::FstabEntry *v = android::fs_mgr::GetEntryForPath(&fstab, volume);
    if (v == nullptr) {
        return VOL_UNKNOWN;
    }
    if (android::fs_mgr::EnsurePathUnmounted(&fstab, volume) != true) {
        return VOL_MOUNTED;
    }

    int fd = open(v->blk_device.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        return VOL_BLK_DEV_OPEN;
    }
    wipe_block_device(fd, get_block_device_size(fd));
    close(fd);

    return WIPE_OK;
}

int main(int argc, char** argv) {
    // Erase metadata partition.
    // Keep erasing Titan M even if failing on this case.
    auto wipe_status = wipe_volume("/metadata");

    // Connect to Titan M
    ::nos::NuggetClient client;
    client.Open();
    if (!client.IsOpen()) {
        std::cout << "open Titan M fail" << std::endl;
        return 1;
    }

    // Tell Titan M to wipe user data
    const uint32_t magicValue = htole32(ERASE_CONFIRMATION);
    std::vector<uint8_t> magic(sizeof(magicValue));
    memcpy(magic.data(), &magicValue, sizeof(magicValue));
    const uint8_t retry_count = 5;
    uint32_t nugget_status;
    for(uint8_t i = 0; i < retry_count; i++) {
        nugget_status = client.CallApp(APP_ID_NUGGET, NUGGET_PARAM_NUKE_FROM_ORBIT, magic, nullptr);
        if (nugget_status == APP_SUCCESS && wipe_status == WIPE_OK) {
            std::cout << wipe_vol_ret_msg[wipe_status] << std::endl;
            return 2;
        }
    }

    // Return exactly what happened
    if (nugget_status != APP_SUCCESS && wipe_status != WIPE_OK) {
        std::cout << "Fail on wiping metadata and Titan M user data" << std::endl;
    } else if (nugget_status != APP_SUCCESS) {
        std::cout << "Titan M user data wipe failed" << std::endl;
    } else {
        if (wipe_vol_ret_msg.find(wipe_status) != wipe_vol_ret_msg.end())
            std::cout << wipe_vol_ret_msg[wipe_status] << std::endl;
        else  // Should not reach here, but handle it anyway
            std::cout << "Unknown failure" << std::endl;
    }

    return 0;
}
