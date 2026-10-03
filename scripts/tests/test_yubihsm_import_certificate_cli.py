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
from yubihsm.defs import COMMAND, ERROR, OBJECT
from yubihsm_emulator import Connector, stored_certificate

PASSWORD_ENV = "YUBIHSM_IMPORT_CERTIFICATE_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def _self_signed_certificate_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
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


def test_import_certificate_cli_imports_from_file(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    certificate_pem = _self_signed_certificate_pem()
    certificate_file = tmp_path / "cert.pem"
    certificate_file.write_bytes(certificate_pem)

    run_cli(
        [
            "import-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2000",
            "--input",
            str(certificate_file),
            "--domain",
            "3",
            "--capabilities",
            "get-opaque",
        ],
        env=cli_environment(),
    )

    stored = yubihsm.device.get(0x2000, OBJECT.OPAQUE)
    assert stored is not None
    assert stored.domains == 0b100
    assert stored_certificate(stored) == x509.load_pem_x509_certificate(
        certificate_pem,
    )


def test_import_certificate_cli_reads_stdin_by_default(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    certificate_pem = _self_signed_certificate_pem()

    run_cli(
        [
            "import-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2000",
            "--domain",
            "3",
            "--capabilities",
            "get-opaque",
        ],
        env=cli_environment(),
        input_text=certificate_pem.decode(),
    )

    stored = yubihsm.device.get(0x2000, OBJECT.OPAQUE)
    assert stored is not None
    assert stored_certificate(stored) == x509.load_pem_x509_certificate(
        certificate_pem,
    )


def test_import_certificate_cli_propagates_sdk_failure(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    yubihsm.device.fail_next(COMMAND.PUT_OPAQUE, ERROR.INSUFFICIENT_PERMISSIONS)
    certificate_file = tmp_path / "cert.pem"
    certificate_file.write_bytes(_self_signed_certificate_pem())

    result = run_cli(
        [
            "import-certificate",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2000",
            "--input",
            str(certificate_file),
            "--domain",
            "3",
            "--capabilities",
            "get-opaque",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode != 0
    assert "INSUFFICIENT_PERMISSIONS" in result.stderr


def test_import_certificate_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "import-certificate",
            "--password",
            "command-line-secret",
            "--key-id",
            "0x2000",
            "--domain",
            "3",
            "--capabilities",
            "get-opaque",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr
