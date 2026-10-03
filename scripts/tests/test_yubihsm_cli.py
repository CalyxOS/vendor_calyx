#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
import os
import stat
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run_cli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from yubihsm.defs import CAPABILITY, COMMAND, ERROR, OBJECT
from yubihsm_emulator import Connector, EmulatedYubiHsm

PASSWORD_ENV = "YUBIHSM_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    """
    Build an environment that exposes the in-tree signing package.

    Args:
        extra: Additional environment variables to set for the process.

    Returns:
        Process environment overrides for CLI subprocesses.
    """
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def _device(yubihsm: Connector) -> EmulatedYubiHsm:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    return yubihsm.device


def _signing(
    yubihsm: Connector,
    command: str,
    *arguments: str,
) -> list[str | Path]:
    return [
        command,
        "--connector",
        yubihsm.url,
        "--password-env",
        PASSWORD_ENV,
        *arguments,
    ]


def test_attest_key_cli_writes_certificate_from_sdk(
    yubihsm: Connector,
) -> None:
    key = _device(yubihsm).put_asymmetric_key(0x2000)

    result = run_cli(
        _signing(yubihsm, "attest-key", "--key-id", "2000"),
        env=cli_environment(),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate.subject.rfc4514_string() == (
        "CN=YubiHSM Attestation id:0x2000"
    )
    assert certificate.public_key() == key.public_key()


def test_attest_key_cli_attests_the_key_with_the_attestation_key(
    yubihsm: Connector,
) -> None:
    device = _device(yubihsm)
    device.put_authentication_key(0x0002, "secret")
    device.put_asymmetric_key(0x2000)
    attesting = device.put_asymmetric_key(
        0x0003,
        capabilities=CAPABILITY.SIGN_ATTESTATION_CERTIFICATE,
    )
    device.put_certificate(0x0003, _certificate(attesting, "attester"))

    result = run_cli(
        _signing(
            yubihsm,
            "attest-key",
            "--authkey",
            "0x0002",
            "--attestation-id",
            "3",
            "--key-id",
            "2000",
        ),
        env=cli_environment(),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate.issuer.rfc4514_string() == "CN=attester"
    assert certificate.signature_hash_algorithm is not None
    attesting.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


def test_attest_key_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "attest-key",
            "--password",
            "command-line-secret",
            "--key-id",
            "2000",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr


def test_attest_key_cli_propagates_sdk_failure(yubihsm: Connector) -> None:
    _device(yubihsm).put_asymmetric_key(0x2000)
    yubihsm.device.fail_next(
        COMMAND.SIGN_ATTESTATION_CERTIFICATE,
        ERROR.INSUFFICIENT_PERMISSIONS,
    )

    result = run_cli(
        _signing(yubihsm, "attest-key", "--key-id", "2000"),
        env=cli_environment(),
        check=False,
    )

    assert result.returncode != 0
    assert "INSUFFICIENT_PERMISSIONS" in result.stderr


def test_extract_audit_log_cli_writes_and_acknowledges_entries(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _device(yubihsm)
    log_file = tmp_path / "audit.log"

    run_cli(
        _signing(
            yubihsm,
            "extract-audit-log",
            "--log-file",
            str(log_file),
            "--comment",
            "cli test",
        ),
        env=cli_environment(),
    )

    contents = log_file.read_text()
    assert "cli test" in contents
    assert "hash: " + device.log[0][2].hex() in contents
    assert device.unread_log() == []


def test_extract_audit_log_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "extract-audit-log",
            "--password",
            "command-line-secret",
            "--log-file",
            "audit.log",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr


def test_export_wrapped_key_cli_writes_base64_backup(
    yubihsm: Connector,
) -> None:
    device = _device(yubihsm)
    device.put_wrap_key(0x0010)
    device.put_asymmetric_key(0x2000)

    result = run_cli(
        _signing(yubihsm, "export-wrapped-key", "--key-id", "2000"),
        env=cli_environment(),
    )

    assert device.unwrap(base64.b64decode(result.stdout), 0x0010) == (
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )


def test_import_wrapped_key_cli_decodes_base64_backup(
    yubihsm: Connector,
) -> None:
    device = _device(yubihsm)
    device.put_wrap_key(0x0010)
    key = device.put_asymmetric_key(0x2000)
    wrapped = device.wrapped(0x2000, OBJECT.ASYMMETRIC_KEY, 0x0010)
    del device.objects[(0x2000, OBJECT.ASYMMETRIC_KEY)]

    run_cli(
        _signing(
            yubihsm,
            "import-wrapped-key",
            "--key-id",
            "2000",
        ),
        env=cli_environment(),
        input_text=base64.b64encode(wrapped).decode(),
    )

    restored = device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    assert restored.data == _private_der(key)


def test_export_wrapped_key_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "export-wrapped-key",
            "--password",
            "command-line-secret",
            "--key-id",
            "2000",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr


@pytest.fixture
def fake_yubihsm_connector_binary(tmp_path: Path) -> Path:
    """Create a long-lived process to stand in for yubihsm-connector."""
    binary = tmp_path / "fake-yubihsm-connector"
    binary.write_text("#!/bin/sh\nsleep 300\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def _private_der(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate(key: rsa.RSAPrivateKey, common_name: str) -> x509.Certificate:
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)],
    )
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


def test_start_yubihsm_connector_cli_writes_pidfile(
    fake_yubihsm_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"

    run_cli(
        [
            "start-yubihsm-connector",
            "--pid-file",
            pid_file,
            "--binary",
            fake_yubihsm_connector_binary,
        ],
        env=cli_environment(),
    )

    assert pid_file.exists()
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pytest.fail("connector process is not running")

    run_cli(
        [
            "stop-yubihsm-connector",
            "--pid-file",
            pid_file,
            "--binary",
            fake_yubihsm_connector_binary,
        ],
        env=cli_environment(),
    )
    assert not pid_file.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
