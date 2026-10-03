#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, SOFTHSM_KEY_ID, run, run_bytes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from software_rsa import rsa_key

HELPER = SCRIPTS_DIR / "pkcs11" / "apksigner_signing_helper.py"


KEY_ID = SOFTHSM_KEY_ID


def _certificate(
    directory: Path,
    key_id: str,
    public_key: rsa.RSAPublicKey,
) -> Path:
    issuer = rsa_key("issuer")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, key_id)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(issuer, hashes.SHA256())
    )
    directory.mkdir(exist_ok=True)
    (directory / f"{key_id}.x509.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    return directory


def _softhsm_key_dir(directory: Path, public_key: Path) -> str:
    key = serialization.load_der_public_key(public_key.read_bytes())
    assert isinstance(key, rsa.RSAPublicKey)
    return f"{_certificate(directory, KEY_ID, key)}/"


@pytest.mark.parametrize(
    ("mechanism", "digest_flag"),
    (
        ("sha256-rsa-pkcs", "sha256"),
        ("sha384-rsa-pkcs", "sha384"),
        ("sha512-rsa-pkcs", "sha512"),
    ),
)
def test_apksigner_signing_helper_signs_raw_data(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
    mechanism: str,
    digest_flag: str,
) -> None:
    environment, public_key = softhsm_rsa_key
    data = b"apksigner signable content, unhashed" * 100

    result = run_bytes(
        [HELPER, mechanism, KEY_ID],
        env={
            **environment,
            "KEY_DIR": _softhsm_key_dir(tmp_path / "keys", public_key),
        },
        input_data=data,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    data_file = tmp_path / "data.bin"
    data_file.write_bytes(data)
    signature = tmp_path / "signature.bin"
    signature.write_bytes(result.stdout)

    verified = run(
        [
            "openssl",
            "dgst",
            f"-{digest_flag}",
            "-verify",
            public_key,
            "-keyform",
            "DER",
            "-signature",
            signature,
            data_file,
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert signature.stat().st_size == 256


def test_apksigner_signing_helper_rejects_unsupported_mechanism(
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key

    result = run_bytes(
        [HELPER, "rsa-pkcs", KEY_ID],
        env=environment,
        input_data=b"data",
        check=False,
    )
    assert result.returncode != 0
    assert b"Unsupported mechanism: rsa-pkcs" in result.stderr


def test_apksigner_signing_helper_rejects_extra_arguments() -> None:
    result = run(
        [HELPER, "sha256-rsa-pkcs", KEY_ID, "unexpected"],
        env={"PKCS11_MODULE": "/dev/null"},
        check=False,
    )
    assert result.returncode != 0
    assert "Unexpected arguments: unexpected" in result.stderr


def test_apksigner_signing_helper_refuses_a_certificate_of_another_key(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key
    key_dir = _certificate(tmp_path / "keys", KEY_ID, rsa_key("b").public_key())

    result = run_bytes(
        [HELPER, "sha256-rsa-pkcs", KEY_ID],
        env={**environment, "KEY_DIR": f"{key_dir}/"},
        input_data=b"apksigner signable content",
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"does not verify under the certificate" in result.stderr


def test_apksigner_signing_helper_refuses_to_sign_without_the_certificate(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key

    result = run_bytes(
        [HELPER, "sha256-rsa-pkcs", KEY_ID],
        env={
            **environment,
            "KEY_DIR": f"{tmp_path / 'keys'}/",
            "PKCS11_MODULE": str(tmp_path / "missing-module.so"),
        },
        input_data=b"apksigner signable content",
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr.startswith(b"no certificate")
