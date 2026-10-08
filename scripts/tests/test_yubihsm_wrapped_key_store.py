#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64

import pytest
from conftest import YUBIHSM_WRAP_ID, yubihsm_config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signing.vendor_yubihsm import (
    decode_wrapped_key_backup,
    export_wrapped_key,
    import_wrapped_key,
)
from yubihsm.defs import COMMAND, ERROR, OBJECT
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import Connector

KEY_ID = "2000"


def test_export_wrapped_key_wraps_the_key_under_the_wrap_key(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_wrap_key(YUBIHSM_WRAP_ID)
    yubihsm.device.put_asymmetric_key(0x2000)

    wrapped = export_wrapped_key(yubihsm_config(yubihsm), KEY_ID)

    assert yubihsm.device.unwrap(wrapped, YUBIHSM_WRAP_ID) == (
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )


def test_import_wrapped_key_restores_the_exported_key(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_wrap_key(YUBIHSM_WRAP_ID)
    key = yubihsm.device.put_asymmetric_key(0x2000)
    wrapped = yubihsm.device.wrapped(
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
        YUBIHSM_WRAP_ID,
    )
    del yubihsm.device.objects[(0x2000, OBJECT.ASYMMETRIC_KEY)]

    import_wrapped_key(yubihsm_config(yubihsm), KEY_ID, wrapped)

    restored = yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    restored_key = serialization.load_der_private_key(restored.data, None)
    assert isinstance(restored_key, rsa.RSAPrivateKey)
    assert (
        restored_key.public_key().public_numbers()
        == key.public_key().public_numbers()
    )


def test_import_wrapped_key_rejects_id_mismatch(yubihsm: Connector) -> None:
    yubihsm.device.put_wrap_key(YUBIHSM_WRAP_ID)
    yubihsm.device.put_asymmetric_key(0x2001)
    wrapped = yubihsm.device.wrapped(
        0x2001,
        OBJECT.ASYMMETRIC_KEY,
        YUBIHSM_WRAP_ID,
    )
    del yubihsm.device.objects[(0x2001, OBJECT.ASYMMETRIC_KEY)]

    with pytest.raises(ValueError, match="does not match expected key id"):
        import_wrapped_key(yubihsm_config(yubihsm), KEY_ID, wrapped)

    assert yubihsm.device.get(0x2001, OBJECT.ASYMMETRIC_KEY) is None


def test_export_wrapped_key_raises_on_device_failure(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_wrap_key(YUBIHSM_WRAP_ID)
    yubihsm.device.put_asymmetric_key(0x2000)
    yubihsm.device.fail_next(
        COMMAND.EXPORT_WRAPPED,
        ERROR.INSUFFICIENT_PERMISSIONS,
    )

    with pytest.raises(YubiHsmDeviceError) as raised:
        export_wrapped_key(yubihsm_config(yubihsm), KEY_ID)

    assert raised.value.code == ERROR.INSUFFICIENT_PERMISSIONS


def test_import_wrapped_key_raises_when_the_key_exists(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_wrap_key(YUBIHSM_WRAP_ID)
    yubihsm.device.put_asymmetric_key(0x2000)
    wrapped = yubihsm.device.wrapped(
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
        YUBIHSM_WRAP_ID,
    )

    with pytest.raises(YubiHsmDeviceError) as raised:
        import_wrapped_key(yubihsm_config(yubihsm), KEY_ID, wrapped)

    assert raised.value.code == ERROR.OBJECT_EXISTS


def test_wrapped_key_backup_matches_yubihsm_shell_format() -> None:
    """
    yubihsm-shell get-wrapped writes the wrapped blob as one line of
    base64 with no trailing newline, and put-wrapped reads that back.
    The provisioning ceremony's restore_signing_keys.py reads the same
    files the same way.
    """
    blob = bytes(range(256)) * 7 + b"\x00\x01"
    shell_text = base64.b64encode(blob)

    assert decode_wrapped_key_backup(shell_text, "backup") == blob
    assert decode_wrapped_key_backup(shell_text + b"\n", "backup") == blob
