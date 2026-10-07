#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import pytest
from conftest import yubihsm_config
from cryptography.hazmat.primitives import serialization
from signing.vendor_yubihsm import generate_asymmetric_key
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, ERROR, OBJECT, ORIGIN
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import (
    Connector,
    EmulatedYubiHsm,
    StoredObject,
)


def generated_keys(device: EmulatedYubiHsm) -> list[StoredObject]:
    return [
        obj
        for obj in device.objects.values()
        if obj.object_type == OBJECT.ASYMMETRIC_KEY
    ]


@pytest.mark.parametrize(
    ("pkcs11_algorithm", "expected_member"),
    [
        ("RSA:2048", "RSA_2048"),
        ("RSA:3072", "RSA_3072"),
    ],
)
def test_generate_asymmetric_key_maps_every_known_algorithm(
    yubihsm: Connector,
    pkcs11_algorithm: str,
    expected_member: str,
) -> None:
    generate_asymmetric_key(
        yubihsm_config(yubihsm),
        key_id="0x2000",
        label="vbmeta",
        domains="3",
        capabilities="sign-pkcs",
        algorithm=pkcs11_algorithm,
    )

    key = yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert key is not None
    assert key.algorithm == ALGORITHM[expected_member]
    assert key.origin == ORIGIN.GENERATED


def test_generate_asymmetric_key_passes_id_label_domain_and_capabilities(
    yubihsm: Connector,
) -> None:
    generate_asymmetric_key(
        yubihsm_config(yubihsm),
        key_id="0x2000",
        label="vbmeta",
        domains="1,2",
        capabilities="sign-pkcs,sign-pss",
        algorithm="RSA:4096",
    )

    (key,) = generated_keys(yubihsm.device)
    assert key.object_id == 0x2000
    assert key.label.rstrip(b"\0") == b"vbmeta"
    assert key.domains == 0b11
    assert key.capabilities == CAPABILITY.SIGN_PKCS | CAPABILITY.SIGN_PSS
    assert key.algorithm == ALGORITHM.RSA_4096
    assert key.origin == ORIGIN.GENERATED
    assert [
        target
        for command, target in yubihsm.device.history
        if command == COMMAND.GENERATE_ASYMMETRIC_KEY
    ] == [(0x2000, 0xFFFF)]


@pytest.mark.parametrize("algorithm", ["RSA:1024", "EC:secp256r1"])
def test_generate_asymmetric_key_rejects_unknown_algorithm(
    yubihsm: Connector,
    algorithm: str,
) -> None:
    with pytest.raises(ValueError, match=f"Unknown algorithm '{algorithm}'"):
        generate_asymmetric_key(
            yubihsm_config(yubihsm),
            key_id="0x2000",
            label="vbmeta",
            domains="3",
            capabilities="sign-pkcs",
            algorithm=algorithm,
        )

    assert generated_keys(yubihsm.device) == []
    assert yubihsm.device.history == []


def test_generate_asymmetric_key_keeps_an_existing_key(
    yubihsm: Connector,
) -> None:
    existing = yubihsm.device.put_asymmetric_key(0x2000, "vbmeta")

    with pytest.raises(YubiHsmDeviceError) as raised:
        generate_asymmetric_key(
            yubihsm_config(yubihsm),
            key_id="0x2000",
            label="vbmeta",
            domains="3",
            capabilities="sign-pkcs",
            algorithm="RSA:4096",
        )

    assert raised.value.code == ERROR.OBJECT_EXISTS
    key = yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert key is not None
    assert key.algorithm == ALGORITHM.RSA_2048
    assert key.data == existing.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
