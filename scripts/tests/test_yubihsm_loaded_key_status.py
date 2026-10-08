#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shutil

import pytest
from conftest import run, yubihsm_config
from signing.vendor_yubihsm import (
    LoadedKeyStatus,
    YubiHsmConfig,
    get_device_identity,
    get_loaded_key_status,
)
from yubihsm.defs import COMMAND
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
)

SCOPED_AUTHKEY_ID = 0x0002
SCOPED_PASSWORD = "scoped"


def config(
    yubihsm: Connector,
    auth_key: int = DEFAULT_AUTHKEY_ID,
    password: str = DEFAULT_PASSWORD,
) -> YubiHsmConfig:
    return YubiHsmConfig(
        connector_url=yubihsm.url,
        auth_key=f"0x{auth_key:04x}",
        password=password,
    )


def put_key_and_certificate(
    device: EmulatedYubiHsm,
    object_id: int,
    domains: int,
) -> None:
    device.put_asymmetric_key(object_id, domains=domains)
    device.put_certificate(
        object_id,
        device.attestation_certificate,
        domains=domains,
    )


def test_get_loaded_key_status_partitions_keys_certs_and_both(
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    put_key_and_certificate(device, 0x2000, 0xFFFF)
    device.put_asymmetric_key(0x2001)
    device.put_certificate(0x2002, device.attestation_certificate)
    device.put_wrap_key(0x2003)
    objects = dict(device.objects)

    status = get_loaded_key_status(config(yubihsm))

    assert status == LoadedKeyStatus(
        loaded_key_ids=frozenset({0x2000, 0x2001}),
        loaded_cert_ids=frozenset({0x2000, 0x2002}),
        fully_loaded_ids=frozenset({0x2000}),
    )
    assert device.objects == objects
    assert COMMAND.LIST_OBJECTS in {command for _, command, _ in device.history}


def test_get_loaded_key_status_reports_keys_in_every_domain(
    yubihsm: Connector,
) -> None:
    """
    Keys outside the on-demand domain are reported as loaded too.
    """
    put_key_and_certificate(yubihsm.device, 0x2000, 0b100)
    put_key_and_certificate(yubihsm.device, 0x2100, 0b001)

    status = get_loaded_key_status(config(yubihsm))

    assert status.fully_loaded_ids == frozenset({0x2000, 0x2100})


def test_get_loaded_key_status_skips_objects_outside_the_auth_key_domains(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(
        SCOPED_AUTHKEY_ID,
        SCOPED_PASSWORD,
        domains=0b001,
    )
    put_key_and_certificate(yubihsm.device, 0x2000, 0b001)
    put_key_and_certificate(yubihsm.device, 0x2100, 0b100)
    yubihsm.device.put_asymmetric_key(0x2200, domains=0b100)
    yubihsm.device.put_certificate(
        0x2200,
        yubihsm.device.attestation_certificate,
        domains=0b011,
    )

    status = get_loaded_key_status(
        config(yubihsm, SCOPED_AUTHKEY_ID, SCOPED_PASSWORD),
    )

    assert status == LoadedKeyStatus(
        loaded_key_ids=frozenset({0x2000}),
        loaded_cert_ids=frozenset({0x2000, 0x2200}),
        fully_loaded_ids=frozenset({0x2000}),
    )


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
