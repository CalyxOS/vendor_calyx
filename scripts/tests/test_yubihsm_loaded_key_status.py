#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shutil

import pytest
from conftest import run, yubihsm_config
from signing.vendor_yubihsm import (
    get_device_identity,
    get_loaded_key_ids,
)
from yubihsm.defs import COMMAND
from yubihsm_emulator import (
    Connector,
)

SCOPED_AUTHKEY_ID = 0x0002
SCOPED_PASSWORD = "scoped"


def test_get_loaded_key_ids_reports_only_keys_in_every_domain(
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    device.put_key_and_certificate(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b001)
    device.put_certificate(0x2002, device.attestation_certificate)
    device.put_wrap_key(0x2003)
    objects = dict(device.objects)

    loaded = get_loaded_key_ids(yubihsm_config(yubihsm))

    assert loaded == {0x2000, 0x2001}
    assert device.objects == objects
    assert COMMAND.LIST_OBJECTS in {command for command, _ in device.history}


def test_get_loaded_key_ids_skips_objects_outside_the_auth_key_domains(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(
        SCOPED_AUTHKEY_ID,
        SCOPED_PASSWORD,
        domains=0b001,
    )
    yubihsm.device.put_key_and_certificate(0x2000, domains=0b001)
    yubihsm.device.put_key_and_certificate(0x2100, domains=0b100)
    yubihsm.device.put_asymmetric_key(0x2200, domains=0b100)
    yubihsm.device.put_certificate(
        0x2200,
        yubihsm.device.attestation_certificate,
        domains=0b011,
    )

    loaded = get_loaded_key_ids(
        yubihsm_config(
            yubihsm,
            auth_key=SCOPED_AUTHKEY_ID,
            password=SCOPED_PASSWORD,
        ),
    )

    assert loaded == {0x2000}


def test_device_identity_reports_device_info_as_yubihsm_shell_does(
    yubihsm: Connector,
) -> None:
    shell = shutil.which("yubihsm-shell")
    if shell is None:
        pytest.skip("yubihsm-shell is not installed")
    printed = run(
        [shell, f"--connector={yubihsm.url}", "-a", "get-device-info"],
    )

    identity = get_device_identity(yubihsm_config(yubihsm))

    assert identity.device_info == printed.stdout
    assert identity.name == "YubiHSM2-123456"


def test_device_identity_needs_a_part_number(yubihsm: Connector) -> None:
    yubihsm.device.part_number = ""

    with pytest.raises(RuntimeError, match="did not report a part number"):
        get_device_identity(yubihsm_config(yubihsm))
