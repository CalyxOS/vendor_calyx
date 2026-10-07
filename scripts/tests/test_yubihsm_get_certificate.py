#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import pytest
from conftest import yubihsm_config
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from signing.vendor_yubihsm import (
    get_certificate,
    get_public_key,
)
from yubihsm.defs import COMMAND, ERROR
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import Connector, self_signed_certificate


def test_get_certificate_returns_the_attestation_certificate_as_pem(
    yubihsm: Connector,
) -> None:
    pem = get_certificate(yubihsm_config(yubihsm), "0x0000")

    assert (
        x509.load_pem_x509_certificate(pem)
        == yubihsm.device.attestation_certificate
    )


def test_get_certificate_reads_the_requested_object(
    yubihsm: Connector,
) -> None:
    config = yubihsm_config(yubihsm)
    for key_id in (0x2000, 0x2001):
        yubihsm.device.put_certificate(
            key_id,
            self_signed_certificate(f"{key_id:#06x}"),
        )

    pem = get_certificate(config, "0x2001")

    certificate = x509.load_pem_x509_certificate(pem)
    assert certificate.subject.rfc4514_string() == "CN=0x2001"


def test_get_certificate_raises_the_device_error(yubihsm: Connector) -> None:
    config = yubihsm_config(yubihsm)
    yubihsm.device.fail_next(COMMAND.GET_OPAQUE, ERROR.INSUFFICIENT_PERMISSIONS)

    with pytest.raises(YubiHsmDeviceError, match="INSUFFICIENT_PERMISSIONS"):
        get_certificate(config, "0x0000")


def test_get_public_key_returns_the_key_of_the_requested_id(
    yubihsm: Connector,
) -> None:
    config = yubihsm_config(yubihsm)
    key = yubihsm.device.put_asymmetric_key(0x2000)
    yubihsm.device.put_asymmetric_key(0x2001)

    assert get_public_key(config, "0x2000") == key.public_key().public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
