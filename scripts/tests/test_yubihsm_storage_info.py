#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import pytest
from conftest import yubihsm_config
from signing.vendor_yubihsm import (
    StorageInfo,
    get_storage_info,
    should_make_space_on_hsm,
)
from yubihsm.defs import COMMAND, ERROR
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import (
    Connector,
    EmulatedYubiHsm,
)


def test_get_storage_info_parses_big_endian_response(
    yubihsm: Connector,
) -> None:
    device = EmulatedYubiHsm(total_records=200, total_pages=900)
    yubihsm.plug(device)
    device.put_wrap_key(0x0010)
    device.put_asymmetric_key(0x2000)

    info = get_storage_info(yubihsm_config(yubihsm))

    assert info == StorageInfo(
        total_records=200,
        free_records=197,
        total_pages=900,
        free_pages=888,
        page_size=126,
    )
    assert (info.free_records, info.free_pages) == device.storage()


def test_get_storage_info_raises_on_device_failure(
    yubihsm: Connector,
) -> None:
    yubihsm.device.fail_next(
        COMMAND.GET_STORAGE_INFO,
        ERROR.INSUFFICIENT_PERMISSIONS,
    )

    with pytest.raises(YubiHsmDeviceError) as raised:
        get_storage_info(yubihsm_config(yubihsm))

    assert raised.value.code == ERROR.INSUFFICIENT_PERMISSIONS


@pytest.mark.parametrize(
    ("free_records", "free_pages", "expected"),
    [
        (10, 100, False),
        (4, 100, True),
        (10, 14, True),
        (4, 14, True),
        (5, 15, False),
    ],
)
def test_should_make_space_on_hsm_thresholds(
    free_records: int,
    free_pages: int,
    expected: bool,
) -> None:
    info = StorageInfo(
        total_records=100,
        free_records=free_records,
        total_pages=100,
        free_pages=free_pages,
        page_size=126,
    )
    assert should_make_space_on_hsm(info) is expected
