#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run_cli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import Connector, EmulatedYubiHsm

PASSWORD_ENV = "YUBIHSM_ONDEMAND_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def _backed_up_device(
    yubihsm: Connector,
    key_dir: Path,
    free_records: int,
) -> EmulatedYubiHsm:
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    device.put_wrap_key(0x0010)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
            base64.b64encode(
                device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, 0x0010),
            ),
        )
    device.total_records = len(device.objects) + free_records
    return device


@pytest.mark.parametrize(
    ("free_records", "expected_deleted"),
    [(100, []), (4, [0x2000])],
)
def test_limit_ondemand_objects_cli_evicts_only_when_space_is_low(
    yubihsm: Connector,
    tmp_path: Path,
    free_records: int,
    expected_deleted: list[int],
) -> None:
    device = _backed_up_device(yubihsm, tmp_path, free_records)

    run_cli(
        [
            "limit-ondemand-objects",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-dir",
            str(tmp_path),
            "--ondemand-domain",
            "3",
        ],
        env=cli_environment(),
    )

    assert [
        key_id
        for key_id in (0x2000, 0x2001)
        if device.get(key_id, OBJECT.ASYMMETRIC_KEY) is None
    ] == expected_deleted


def test_limit_ondemand_objects_cli_extracts_the_audit_log_per_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _backed_up_device(yubihsm, tmp_path, 3)
    device.audit(COMMAND.DELETE_OBJECT)
    audit_log = tmp_path / "audit.log"

    run_cli(
        [
            "limit-ondemand-objects",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-dir",
            str(tmp_path),
            "--ondemand-domain",
            "3",
            "--audit-log",
            str(audit_log),
        ],
        env=cli_environment(),
    )

    sections: list[tuple[str, list[str]]] = []
    for line in audit_log.read_text().splitlines():
        if line.startswith("#"):
            sections.append((line, []))
        else:
            sections[-1][1].append(line)
    assert len(sections) == 2
    for (comment, entries), key_id in zip(sections, ("0x2000", "0x2001")):
        assert comment.endswith(
            f" Command: delete-object --object-id {key_id} "
            "--object-type asymmetric-key Result: 0",
        )
        assert " cmd: 0x58 " in entries[-1]
        assert f" tKey: {key_id} " in entries[-1]


def _ensure_keys_available(
    yubihsm: Connector,
    key_dir: Path,
    *arguments: str,
) -> list[str | Path]:
    return [
        "ensure-keys-available",
        "--connector",
        yubihsm.url,
        "--password-env",
        PASSWORD_ENV,
        "--key-dir",
        str(key_dir),
        "--key-id",
        "0x2000",
        *arguments,
        "--exportable-domain",
        "1",
        "--ondemand-domain",
        "3",
        "--opaque-capabilities",
        "get-opaque",
    ]


def _backed_up_missing_key(yubihsm: Connector, key_dir: Path) -> None:
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    device.put_wrap_key(0x0010)
    key = device.put_asymmetric_key(0x2000, domains=0b100)
    (key_dir / "0x2000-asymmetric-key.yhw").write_bytes(
        base64.b64encode(device.wrapped(0x2000, OBJECT.ASYMMETRIC_KEY, 0x0010)),
    )
    (key_dir / "0x2000.x509.pem").write_bytes(
        _certificate(key).public_bytes(serialization.Encoding.PEM),
    )
    del device.objects[(0x2000, OBJECT.ASYMMETRIC_KEY)]


def _certificate(key: rsa.RSAPrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_ensure_keys_available_cli_imports_missing_key(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    _backed_up_missing_key(yubihsm, tmp_path)

    run_cli(
        _ensure_keys_available(
            yubihsm,
            tmp_path,
            "--ondemand-key-id",
            "0x2000",
        ),
        env=cli_environment(),
    )

    assert yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is not None
    assert yubihsm.device.get(0x2000, OBJECT.OPAQUE) is not None


def test_ensure_keys_available_cli_is_a_noop_when_already_loaded(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    key = device.put_asymmetric_key(0x2000, domains=0b100)
    device.put_certificate(0x2000, _certificate(key), domains=0b100)

    run_cli(
        _ensure_keys_available(
            yubihsm,
            tmp_path,
            "--ondemand-key-id",
            "0x2000",
        ),
        env=cli_environment(),
    )

    assert COMMAND.IMPORT_WRAPPED not in [
        command for _, command, _ in device.history
    ]


def test_ensure_keys_available_cli_no_verify_key_ids_processes_non_ondemand(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    _backed_up_missing_key(yubihsm, tmp_path)

    run_cli(
        _ensure_keys_available(yubihsm, tmp_path, "--no-verify-key-ids"),
        env=cli_environment(),
    )

    assert yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is not None
