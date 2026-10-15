#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from conftest import back_up_yubihsm_key, plug_yubihsm, yubihsm_config
from cryptography.hazmat.primitives import serialization
from signing.vendor_yubihsm import (
    RestorableObject,
    extract_and_save_audit_log,
    is_object_available_on_disk,
    limit_ondemand_objects,
    list_restorable_objects,
    parse_capabilities,
    parse_domains,
)
from yubihsm.core import AuthSession
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, ERROR, OBJECT
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm.objects import YhsmObject
from yubihsm_emulator import (
    Connector,
    EmulatedYubiHsm,
    StoredObject,
    self_signed_certificate,
    stored_certificate,
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


def _deleted(device: EmulatedYubiHsm) -> list[int]:
    return [
        target[0]
        for command, target in device.history
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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "sign-pkcs,exportable-under-wrap",
            CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        ),
        (
            "put-asymmetric-key,put-mac-key,put-public-wrap-key,"
            "delete-public-wrap-key",
            CAPABILITY.PUT_ASYMMETRIC
            | CAPABILITY.PUT_HMAC_KEY
            | CAPABILITY.PUBLIC_WRAP_KEY_WRITE
            | CAPABILITY.PUBLIC_WRAP_KEY_DELETE,
        ),
        ("none", CAPABILITY(0)),
        ("all", ~CAPABILITY(0)),
        ("ALL", ~CAPABILITY(0)),
        (",exportable-under-wrap", CAPABILITY.EXPORTABLE_UNDER_WRAP),
    ],
)
def test_parse_capabilities(value: str, expected: CAPABILITY) -> None:
    assert parse_capabilities(value) == expected


def test_parse_capabilities_names_an_unknown_capability() -> None:
    with pytest.raises(
        ValueError,
        match="unknown capability 'sign-everything'",
    ):
        parse_capabilities("sign-pkcs,sign-everything")


def test_list_restorable_objects_returns_keys_and_certs_in_the_domain(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    device.put_key_and_certificate(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)

    result = list_restorable_objects(yubihsm_config(yubihsm), "3")

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
    device = plug_yubihsm(yubihsm)
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

    assert list_restorable_objects(yubihsm_config(yubihsm), "3") == ()


def test_list_restorable_objects_takes_every_listed_domain(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    device.put_asymmetric_key(0x2000, domains=0b001)
    device.put_asymmetric_key(0x2100, domains=0b010)
    device.put_asymmetric_key(0x2200, domains=0b100)

    result = list_restorable_objects(yubihsm_config(yubihsm), "1,3")

    assert [obj.id for obj in result] == [0x2000, 0x2200]


def test_list_restorable_objects_without_domains_lists_every_domain(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    device.put_asymmetric_key(0x2000, domains=0b001)
    device.put_asymmetric_key(0x2100, domains=0x8000)

    result = list_restorable_objects(yubihsm_config(yubihsm), None)

    assert [obj.id for obj in result] == [0x2000, 0x2100]


def test_list_restorable_objects_orders_them_by_id(
    yubihsm: Connector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = plug_yubihsm(yubihsm)
    device.put_asymmetric_key(0x2100, domains=0b100)
    device.put_key_and_certificate(0x2000, domains=0b100)
    listed = AuthSession.list_objects

    def list_objects(
        session: AuthSession,
        domains: int | None = None,
    ) -> Sequence[YhsmObject]:
        return listed(session, domains=domains)[::-1]

    monkeypatch.setattr(AuthSession, "list_objects", list_objects)

    result = list_restorable_objects(yubihsm_config(yubihsm), "3")

    assert [(obj.id, obj.object_type) for obj in result] == [
        (0x2000, OBJECT.OPAQUE),
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2100, OBJECT.ASYMMETRIC_KEY),
    ]


@pytest.mark.parametrize(
    ("contents", "available"),
    (
        (None, False),
        (b"d3JhcHBlZA==", True),
        (b"", False),
        (b"d3JhcHBlZA", False),
    ),
    ids=("missing", "base64", "empty", "truncated"),
)
def test_is_object_available_on_disk_reads_the_key_backup(
    tmp_path: Path,
    contents: bytes | None,
    available: bool,
) -> None:
    if contents is not None:
        (tmp_path / "0x2000-asymmetric-key.yhw").write_bytes(contents)

    assert (
        is_object_available_on_disk(tmp_path, 0x2000, OBJECT.ASYMMETRIC_KEY)
        is available
    )


CERTIFICATE = self_signed_certificate().public_bytes(
    serialization.Encoding.PEM,
)
CERTIFICATE_LINES = CERTIFICATE.splitlines(keepends=True)


@pytest.mark.parametrize(
    ("contents", "available"),
    (
        (None, False),
        (CERTIFICATE, True),
        (b"\n  " + CERTIFICATE, True),
        (CERTIFICATE_LINES[0], False),
        (CERTIFICATE[: len(CERTIFICATE) // 2], False),
        (b"".join((*CERTIFICATE_LINES[:2], CERTIFICATE_LINES[-1])), False),
        (b"not a certificate", False),
    ),
    ids=(
        "missing",
        "certificate",
        "leading-blanks",
        "header",
        "truncated",
        "corrupt",
        "not-pem",
    ),
)
def test_is_object_available_on_disk_parses_the_certificate(
    tmp_path: Path,
    contents: bytes | None,
    available: bool,
) -> None:
    if contents is not None:
        (tmp_path / "0x2000.x509.pem").write_bytes(contents)

    assert (
        is_object_available_on_disk(tmp_path, 0x2000, OBJECT.OPAQUE)
        is available
    )


def test_limit_ondemand_objects_stops_once_space_is_sufficient(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=2 + 4)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        back_up_yubihsm_key(device, tmp_path, key_id)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert device.key_objects() == {(0x2001, OBJECT.ASYMMETRIC_KEY)}
    assert device.storage()[0] == 5


def test_limit_ondemand_objects_finishes_current_id_before_stopping(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=3 + 4)
    device.put_key_and_certificate(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    back_up_yubihsm_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert device.key_objects() == {(0x2001, OBJECT.ASYMMETRIC_KEY)}
    assert _deleted(device) == [0x2000, 0x2000]


def test_limit_ondemand_objects_keeps_a_certificate_whose_backup_is_corrupt(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=3 + 4)
    device.put_key_and_certificate(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    certificate = tmp_path / "0x2000.x509.pem"
    lines = certificate.read_bytes().splitlines(keepends=True)
    certificate.write_bytes(b"".join((*lines[:2], lines[-1])))
    back_up_yubihsm_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert device.key_objects() == {
        (0x2000, OBJECT.OPAQUE),
        (0x2001, OBJECT.ASYMMETRIC_KEY),
    }
    assert _deleted(device) == [0x2000]


def test_limit_ondemand_objects_audits_every_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=2 + 4)
    device.put_key_and_certificate(0x2000, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    device.audit(COMMAND.DELETE_OBJECT)
    config = yubihsm_config(yubihsm)
    log_file = tmp_path / "audit.log"

    def after_delete(comment: str) -> None:
        extract_and_save_audit_log(config, log_file, comment)

    limit_ondemand_objects(config, tmp_path, "3", after_delete)

    assert device.key_objects() == set()
    sections: list[tuple[str, list[str]]] = []
    for line in log_file.read_text().splitlines():
        if line.startswith("#"):
            sections.append((line, []))
        else:
            sections[-1][1].append(line)
    assert len(sections) == 2
    for (comment, entries), object_type in zip(
        sections,
        ("opaque", "asymmetric-key"),
    ):
        assert comment.endswith(
            " Operation: delete-object --object-id 0x2000 "
            f"--object-type {object_type} Result: 0",
        )
        assert " cmd: 0x58 " in entries[-1]
        assert " tKey: 0x2000 " in entries[-1]


def test_limit_ondemand_objects_reports_a_failed_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=1 + 4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)
    device.fail_next(COMMAND.DELETE_OBJECT, ERROR.INSUFFICIENT_PERMISSIONS)
    reported: list[str] = []

    with pytest.raises(YubiHsmDeviceError) as raised:
        limit_ondemand_objects(
            yubihsm_config(yubihsm),
            tmp_path,
            "3",
            reported.append,
        )

    assert raised.value.code == ERROR.INSUFFICIENT_PERMISSIONS
    assert reported == [
        "Operation: delete-object --object-id 0x2000 --object-type "
        "asymmetric-key Result: 1",
    ]
    assert device.key_objects() == {(0x2000, OBJECT.ASYMMETRIC_KEY)}


def test_limit_ondemand_objects_evicts_only_backed_up_ondemand_objects(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=3 + 4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)
    device.put_asymmetric_key(0x2200, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2100)
    back_up_yubihsm_key(device, tmp_path, 0x2200)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert device.key_objects() == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2100, OBJECT.ASYMMETRIC_KEY),
    }


def test_limit_ondemand_objects_raises_if_still_low_after_sweep(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=1 + 1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert device.key_objects() == set()


def test_limit_ondemand_objects_dry_run_prints_deletes_without_deleting(
    yubihsm: Connector,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    device = plug_yubihsm(yubihsm, free_records=1 + 1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    back_up_yubihsm_key(device, tmp_path, 0x2000)
    deletes: list[str] = []

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(
            yubihsm_config(yubihsm),
            tmp_path,
            "3",
            deletes.append,
            dry_run=True,
        )

    assert device.key_objects() == {(0x2000, OBJECT.ASYMMETRIC_KEY)}
    assert _deleted(device) == []
    assert deletes == []
    assert (
        "Operation: delete-object --object-id 0x2000 "
        "--object-type asymmetric-key\n"
    ) in capsys.readouterr().err
