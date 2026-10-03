#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import datetime
from pathlib import Path

from conftest import SCRIPTS_DIR, run_cli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from yubihsm.defs import COMMAND, ERROR
from yubihsm_emulator import Connector

PASSWORD_ENV = "YUBIHSM_GET_CERTIFICATE_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def test_get_certificate_cli_writes_pem(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    output = tmp_path / "attestation.pem"

    run_cli(
        [
            "get-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x0000",
            "--output",
            str(output),
        ],
        env=cli_environment(),
    )

    certificate = x509.load_pem_x509_certificate(output.read_bytes())
    assert certificate == yubihsm.device.attestation_certificate


def _certificate_pem(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)],
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
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_get_certificate_cli_reads_the_requested_object(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    for key_id in (0x2000, 0x2001):
        yubihsm.device.put_certificate(
            key_id,
            x509.load_pem_x509_certificate(_certificate_pem(f"{key_id:#06x}")),
        )

    result = run_cli(
        [
            "get-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2001",
        ],
        env=cli_environment(),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate.subject.rfc4514_string() == "CN=0x2001"


def test_get_certificate_cli_propagates_sdk_failure(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    yubihsm.device.fail_next(COMMAND.GET_OPAQUE, ERROR.INSUFFICIENT_PERMISSIONS)
    result = run_cli(
        [
            "get-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x0000",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode != 0
    assert "INSUFFICIENT_PERMISSIONS" in result.stderr


def test_get_certificate_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "get-certificate",
            "--password",
            "command-line-secret",
            "--key-id",
            "0x0000",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr
