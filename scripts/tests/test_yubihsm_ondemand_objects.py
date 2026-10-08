#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
from collections.abc import Sequence
from pathlib import Path

import pytest
from conftest import YUBIHSM_WRAP_ID, plug_yubihsm, yubihsm_config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from signing.vendor_yubihsm import (
    RestorableObject,
    import_certificate,
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

FIXED_RECORDS = 2


def _back_up_key(device: EmulatedYubiHsm, key_dir: Path, key_id: int) -> None:
    (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
        base64.b64encode(
            device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, YUBIHSM_WRAP_ID),
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


def _self_signed_certificate_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")],
    )
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(
            key,
            hashes.SHA256(),
        )
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


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


def test_parse_capabilities_combines_named_flags() -> None:
    result = parse_capabilities("sign-pkcs,exportable-under-wrap")

    assert result == (CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP)


def test_parse_capabilities_takes_libyubihsm_names() -> None:
    result = parse_capabilities(
        "put-asymmetric-key,put-mac-key,put-public-wrap-key,"
        "delete-public-wrap-key",
    )

    assert result == (
        CAPABILITY.PUT_ASYMMETRIC
        | CAPABILITY.PUT_HMAC_KEY
        | CAPABILITY.PUBLIC_WRAP_KEY_WRITE
        | CAPABILITY.PUBLIC_WRAP_KEY_DELETE
    )


def test_parse_capabilities_names_an_unknown_capability() -> None:
    with pytest.raises(
        ValueError,
        match="unknown capability 'sign-everything'",
    ):
        parse_capabilities("sign-pkcs,sign-everything")


def test_parse_capabilities_none_is_empty() -> None:
    assert parse_capabilities("none") == CAPABILITY(0)


def test_parse_capabilities_all_is_every_flag() -> None:
    assert parse_capabilities("all") == ~CAPABILITY(0)
    assert parse_capabilities("ALL") == ~CAPABILITY(0)


def test_parse_capabilities_skips_empty_segment_from_empty_base() -> None:
    assert (
        parse_capabilities(",exportable-under-wrap")
        == CAPABILITY.EXPORTABLE_UNDER_WRAP
    )


def test_list_restorable_objects_returns_keys_and_certs_in_the_domain(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
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
    _put_key_and_certificate(device, 0x2000, domains=0b100)
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


CERTIFICATE = self_signed_certificate().public_bytes(
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


def test_import_certificate_parses_pem_and_imports(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    pem = _self_signed_certificate_pem()

    import_certificate(
        yubihsm_config(yubihsm),
        key_id="0x2000",
        domains="3",
        capabilities="get-opaque",
        certificate_pem=pem,
    )

    stored = device.get(0x2000, OBJECT.OPAQUE)
    assert stored is not None
    assert stored.algorithm == ALGORITHM.OPAQUE_X509_CERTIFICATE
    assert stored.label.rstrip(b"\0") == b""
    assert stored.domains == 0b100
    assert stored.capabilities == CAPABILITY.GET_OPAQUE
    assert (
        stored_certificate(stored).public_bytes(serialization.Encoding.PEM)
        == pem
    )


def test_import_certificate_refuses_an_existing_object(
    yubihsm: Connector,
) -> None:
    device = plug_yubihsm(yubihsm)
    _put_key_and_certificate(device, 0x2000)
    existing = device.get(0x2000, OBJECT.OPAQUE)

    with pytest.raises(YubiHsmDeviceError) as raised:
        import_certificate(
            yubihsm_config(yubihsm),
            key_id="0x2000",
            domains="3",
            capabilities="get-opaque",
            certificate_pem=_self_signed_certificate_pem(),
        )

    assert raised.value.code == ERROR.OBJECT_EXISTS
    assert device.get(0x2000, OBJECT.OPAQUE) is existing


def test_limit_ondemand_objects_stops_once_space_is_sufficient(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 2 + 4)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        _back_up_key(device, tmp_path, key_id)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2001, OBJECT.ASYMMETRIC_KEY)]
    assert device.storage()[0] == 5


def test_limit_ondemand_objects_finishes_current_id_before_stopping(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 3 + 4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    _back_up_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2001, OBJECT.ASYMMETRIC_KEY)]
    assert _deleted(device) == [0x2000, 0x2000]


def test_limit_ondemand_objects_keeps_a_certificate_whose_backup_is_corrupt(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 3 + 4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    device.put_asymmetric_key(0x2001, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    certificate = tmp_path / "0x2000.x509.pem"
    lines = certificate.read_bytes().splitlines(keepends=True)
    certificate.write_bytes(b"".join((*lines[:2], lines[-1])))
    _back_up_key(device, tmp_path, 0x2001)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [
        (0x2000, OBJECT.OPAQUE),
        (0x2001, OBJECT.ASYMMETRIC_KEY),
    ]
    assert _deleted(device) == [0x2000]


def test_limit_ondemand_objects_reports_every_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 2 + 4)
    _put_key_and_certificate(device, 0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_certificate(device, tmp_path, 0x2000)
    reported: list[str] = []

    limit_ondemand_objects(
        yubihsm_config(yubihsm),
        tmp_path,
        "3",
        reported.append,
    )

    assert sorted(reported) == [
        "Operation: delete-object --object-id 0x2000 --object-type "
        "asymmetric-key Result: 0",
        "Operation: delete-object --object-id 0x2000 --object-type "
        "opaque Result: 0",
    ]
    assert _on_device(device) == []


def test_limit_ondemand_objects_reports_a_failed_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 1 + 4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
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
    assert _on_device(device) == [(0x2000, OBJECT.ASYMMETRIC_KEY)]


def test_limit_ondemand_objects_evicts_only_backed_up_ondemand_objects(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 3 + 4)
    device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)
    device.put_asymmetric_key(0x2200, domains=0b100)
    _back_up_key(device, tmp_path, 0x2100)
    _back_up_key(device, tmp_path, 0x2200)

    limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2100, OBJECT.ASYMMETRIC_KEY),
    ]


def test_limit_ondemand_objects_never_evicts_outside_the_ondemand_domains(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_asymmetric_key(0x2100, domains=0b001)
    _back_up_key(device, tmp_path, 0x2000)
    _back_up_key(device, tmp_path, 0x2100)

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == [(0x2100, OBJECT.ASYMMETRIC_KEY)]


def test_limit_ondemand_objects_raises_if_still_low_after_sweep(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 1 + 1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(yubihsm_config(yubihsm), tmp_path, "3")

    assert _on_device(device) == []


def test_limit_ondemand_objects_dry_run_prints_deletes_without_deleting(
    yubihsm: Connector,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    device = plug_yubihsm(yubihsm, total_records=FIXED_RECORDS + 1 + 1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    _back_up_key(device, tmp_path, 0x2000)
    deletes: list[str] = []

    with pytest.raises(RuntimeError, match="Failed to make enough space"):
        limit_ondemand_objects(
            yubihsm_config(yubihsm),
            tmp_path,
            "3",
            deletes.append,
            dry_run=True,
        )

    assert _on_device(device) == [(0x2000, OBJECT.ASYMMETRIC_KEY)]
    assert _deleted(device) == []
    assert deletes == []
    assert (
        "Operation: delete-object --object-id 0x2000 "
        "--object-type asymmetric-key\n"
    ) in capsys.readouterr().err
