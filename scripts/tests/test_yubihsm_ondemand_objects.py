#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from signing.vendor_yubihsm import (
    RestorableObject,
    YubiHsmConfig,
    is_object_available_on_disk,
    limit_ondemand_objects,
    list_restorable_objects,
    parse_domains,
)
from yubihsm.core import AuthSession
from yubihsm.defs import ALGORITHM, COMMAND, ERROR, OBJECT
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm.objects import YhsmObject
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
    StoredObject,
    stored_certificate,
)

WRAP_ID = 0x0010
FIXED_RECORDS = 2


def config(yubihsm: Connector) -> YubiHsmConfig:
    return YubiHsmConfig(
        connector_url=yubihsm.url,
        auth_key=f"{DEFAULT_AUTHKEY_ID:#06x}",
        password=DEFAULT_PASSWORD,
    )


def _plug(
    yubihsm: Connector,
    *,
    objects: int = 0,
    free_records: int = 100,
) -> EmulatedYubiHsm:
    """
    Plug in a device holding a wrap key, sized to have free_records
    free records once `objects` more objects are stored on it.
    """
    device = EmulatedYubiHsm(
        total_records=FIXED_RECORDS + objects + free_records,
    )
    device.put_wrap_key(WRAP_ID)
    yubihsm.plug(device)
    return device


def _back_up_key(device: EmulatedYubiHsm, key_dir: Path, key_id: int) -> None:
    (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
        base64.b64encode(
            device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, WRAP_ID),
        ),
    )


def _back_up_certificate(
    device: EmulatedYubiHsm,
    key_dir: Path,
    key_id: int,
) -> None:
    obj = device.get(key_id, OBJECT.OPAQUE)
    assert obj is not None
    (key_dir / f"{key_id:#06x}.x509.pem").write_bytes(
        stored_certificate(obj).public_bytes(serialization.Encoding.PEM),
    )


def _put_key_and_certificate(
    device: EmulatedYubiHsm,
    key_id: int,
    *,
    domains: int = 0xFFFF,
) -> None:
    device.put_asymmetric_key(key_id, domains=domains)
    device.put_certificate(key_id, device.attest(key_id), domains=domains)


def _on_device(device: EmulatedYubiHsm) -> list[tuple[int, OBJECT]]:
    return sorted(
        key
        for key in device.objects
        if key[1] in (OBJECT.ASYMMETRIC_KEY, OBJECT.OPAQUE)
    )


def _deleted(device: EmulatedYubiHsm) -> list[int]:
    return [
        target[0]
        for _, command, target in device.history
        if command == COMMAND.DELETE_OBJECT
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", 0b1),
        ("3", 0b100),
        ("1,2", 0b11),
        ("1:2:3", 0b111),
        ("all", 0xFFFF),
        ("ALL", 0xFFFF),
        ("0x0007", 0x0007),
        (",3", 0b100),
    ],
)
def test_parse_domains(value: str, expected: int) -> None:
    assert parse_domains(value) == expected


def test_parse_domains_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="numbered from 1 to 16"):
        parse_domains("17")


def test_list_restorable_objects_returns_keys_and_certs_in_the_domain(
    yubihsm: Connector,
) -> None:
    device = _plug(yubihsm)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)

    result = list_restorable_objects(config(yubihsm), "3")

    assert len(result) == 2
    assert set(result) == {
        RestorableObject(0x2000, OBJECT.ASYMMETRIC_KEY, ALGORITHM.RSA_2048),
        RestorableObject(
            0x2000,
            OBJECT.OPAQUE,
            ALGORITHM.OPAQUE_X509_CERTIFICATE,
        ),
    }


def test_list_restorable_objects_excludes_non_x509_opaques_and_other_types(
    yubihsm: Connector,
) -> None:
    device = _plug(yubihsm)
    device.objects[(0x2000, OBJECT.OPAQUE)] = StoredObject(
        0x2000,
        OBJECT.OPAQUE,
        ALGORITHM.OPAQUE_DATA,
        b"",
        0xFFFF,
        0,
        0,
        b"opaque data",
    )

    assert list_restorable_objects(config(yubihsm), "3") == ()


def test_list_restorable_objects_takes_every_listed_domain(
    yubihsm: Connector,
) -> None:
    device = _plug(yubihsm)
    device.put_asymmetric_key(0x2000, domains=0b001)
    device.put_asymmetric_key(0x2100, domains=0b010)
    device.put_asymmetric_key(0x2200, domains=0b100)

    result = list_restorable_objects(config(yubihsm), "1,3")

    assert [obj.id for obj in result] == [0x2000, 0x2200]


def test_list_restorable_objects_without_domains_lists_every_domain(
    yubihsm: Connector,
) -> None:
    device = _plug(yubihsm)
    device.put_asymmetric_key(0x2000, domains=0b001)
    device.put_asymmetric_key(0x2100, domains=0x8000)

    result = list_restorable_objects(config(yubihsm), None)

    assert [obj.id for obj in result] == [0x2000, 0x2100]


def test_list_restorable_objects_orders_them_by_id(
    yubihsm: Connector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = _plug(yubihsm)
    device.put_asymmetric_key(0x2100, domains=0b100)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    listed = AuthSession.list_objects

    def list_objects(
        session: AuthSession,
        domains: int | None = None,
    ) -> Sequence[YhsmObject]:
        return listed(session, domains=domains)[::-1]

    monkeypatch.setattr(AuthSession, "list_objects", list_objects)

    result = list_restorable_objects(config(yubihsm), "3")

    assert [(obj.id, obj.object_type) for obj in result] == [
        (0x2000, OBJECT.OPAQUE),
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2100, OBJECT.ASYMMETRIC_KEY),
    ]


def test_is_object_available_on_disk_asymmetric_key(tmp_path: Path) -> None:
    assert not is_object_available_on_disk(
        tmp_path,
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )
    (tmp_path / "0x2000-asymmetric-key.yhw").write_bytes(b"d3JhcHBlZA==")
    assert is_object_available_on_disk(tmp_path, 0x2000, OBJECT.ASYMMETRIC_KEY)


def test_is_object_available_on_disk_rejects_empty_wrapped_key_file(
    tmp_path: Path,
) -> None:
    """
    A zero-byte wrapped key file does not count as an available backup.
    """
    (tmp_path / "0x2000-asymmetric-key.yhw").touch()
    assert not is_object_available_on_disk(
        tmp_path,
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )


def test_is_object_available_on_disk_rejects_a_truncated_wrapped_key_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "0x2000-asymmetric-key.yhw").write_bytes(b"d3JhcHBlZA")
    assert not is_object_available_on_disk(
        tmp_path,
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )


CERTIFICATE = EmulatedYubiHsm().attestation_certificate.public_bytes(
    serialization.Encoding.PEM,
)
CERTIFICATE_LINES = CERTIFICATE.splitlines(keepends=True)


def test_is_object_available_on_disk_opaque(tmp_path: Path) -> None:
    assert not is_object_available_on_disk(tmp_path, 0x2000, OBJECT.OPAQUE)
    (tmp_path / "0x2000.x509.pem").write_bytes(CERTIFICATE)
    assert is_object_available_on_disk(tmp_path, 0x2000, OBJECT.OPAQUE)


@pytest.mark.parametrize(
    ("contents", "available"),
    (
        (b"\n  " + CERTIFICATE, True),
        (CERTIFICATE_LINES[0], False),
        (CERTIFICATE[: len(CERTIFICATE) // 2], False),
        (b"".join((*CERTIFICATE_LINES[:2], CERTIFICATE_LINES[-1])), False),
    ),
    ids=("leading-blanks", "header", "truncated", "corrupt"),
)
def test_is_object_available_on_disk_parses_the_certificate(
    tmp_path: Path,
    contents: bytes,
    available: bool,
) -> None:
    (tmp_path / "0x2000.x509.pem").write_bytes(contents)

    assert (
        is_object_available_on_disk(tmp_path, 0x2000, OBJECT.OPAQUE)
        is available
    )


def test_is_object_available_on_disk_rejects_non_pem_certificate_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "0x2000.x509.pem").write_bytes(b"not a certificate")
    assert not is_object_available_on_disk(tmp_path, 0x2000, OBJECT.OPAQUE)


def test_limit_ondemand_objects_stops_once_space_is_sufficient(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=2, free_records=4)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        _back_up_key(device, tmp_path, key_id)

    limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2001, OBJECT.ASYMMETRIC_KEY)]
    assert device.storage()[0] == 5


def test_limit_ondemand_objects_finishes_current_id_before_stopping(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=3, free_records=4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    _back_up_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2001, OBJECT.ASYMMETRIC_KEY)]
    assert _deleted(device) == [0x2000, 0x2000]


def test_limit_ondemand_objects_keeps_a_certificate_whose_backup_is_corrupt(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=3, free_records=4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    certificate = tmp_path / "0x2000.x509.pem"
    lines = certificate.read_bytes().splitlines(keepends=True)
    certificate.write_bytes(b"".join((*lines[:2], lines[-1])))
    _back_up_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [
        (0x2000, OBJECT.OPAQUE),
        (0x2001, OBJECT.ASYMMETRIC_KEY),
    ]
    assert _deleted(device) == [0x2000]


def test_limit_ondemand_objects_reports_every_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=2, free_records=4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    reported: list[str] = []

    limit_ondemand_objects(config(yubihsm), tmp_path, "3", reported.append)

    assert sorted(reported) == [
        "Command: delete-object --object-id 0x2000 --object-type "
        "asymmetric-key Result: 0",
        "Command: delete-object --object-id 0x2000 --object-type "
        "opaque Result: 0",
    ]
    assert _on_device(device) == []


def test_limit_ondemand_objects_reports_a_failed_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=1, free_records=4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    device.fail_next(COMMAND.DELETE_OBJECT, ERROR.INSUFFICIENT_PERMISSIONS)
    reported: list[str] = []

    with pytest.raises(YubiHsmDeviceError) as raised:
        limit_ondemand_objects(config(yubihsm), tmp_path, "3", reported.append)

    assert raised.value.code == ERROR.INSUFFICIENT_PERMISSIONS
    assert reported == [
        "Command: delete-object --object-id 0x2000 --object-type "
        "asymmetric-key Result: 1",
    ]
    assert _on_device(device) == [(0x2000, OBJECT.ASYMMETRIC_KEY)]


def test_limit_ondemand_objects_evicts_only_backed_up_ondemand_objects(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=3, free_records=4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)
    device.put_asymmetric_key(0x2200, domains=0b100)
    _back_up_key(device, tmp_path, 0x2100)
    _back_up_key(device, tmp_path, 0x2200)

    limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2100, OBJECT.ASYMMETRIC_KEY),
    ]


def test_limit_ondemand_objects_never_evicts_outside_the_ondemand_domains(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=2, free_records=1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_key(device, tmp_path, 0x2100)

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2100, OBJECT.ASYMMETRIC_KEY)]


def test_limit_ondemand_objects_raises_if_still_low_after_sweep(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, objects=1, free_records=1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(config(yubihsm), tmp_path, "3")

    assert _on_device(device) == []


def test_limit_ondemand_objects_dry_run_prints_deletes_without_deleting(
    yubihsm: Connector,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    device = _plug(yubihsm, objects=1, free_records=1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    deletes: list[str] = []

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(
            config(yubihsm),
            tmp_path,
            "3",
            deletes.append,
            dry_run=True,
        )

    assert _on_device(device) == [(0x2000, OBJECT.ASYMMETRIC_KEY)]
    assert _deleted(device) == []
    assert deletes == []
    assert (
        "yubihsm -a delete-object --object-id 0x2000 "
        "--object-type asymmetric-key\n"
    ) in capsys.readouterr().err
