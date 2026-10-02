#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_bytes
from openssl_shim import generate_rsa_key, helper_env, write_openssl_pkcs11_shim

SIGNING_HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.openssl.sh"
PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.openssl.sh"


@pytest.fixture
def openssl_pkcs11_shim(tmp_path: Path) -> Path:
    return write_openssl_pkcs11_shim(tmp_path)


@pytest.mark.parametrize(
    ("algorithm", "bits", "padding_size", "digest"),
    (
        ("SHA256_RSA2048", 2048, 205, bytes(range(32))),
        ("SHA512_RSA4096", 4096, 429, bytes(range(64))),
    ),
)
def test_signing_helper_strips_avb_padding_and_signs_digest(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
    algorithm: str,
    bits: int,
    padding_size: int,
    digest: bytes,
) -> None:
    private_key = generate_rsa_key(tmp_path, bits)
    result = run_bytes(
        [SIGNING_HELPER, algorithm, "keys/test-key.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        input_data=b"\x00" * padding_size + digest,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    signature = tmp_path / "signature.bin"
    signature.write_bytes(result.stdout)
    digest_file = tmp_path / "digest.bin"
    digest_file.write_bytes(digest)

    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-inkey",
            private_key,
            "-in",
            digest_file,
            "-sigfile",
            signature,
            "-pkeyopt",
            "rsa_padding_mode:pkcs1",
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert signature.stat().st_size == bits // 8


def test_signing_helper_rejects_unsupported_algorithm(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    result = run(
        [SIGNING_HELPER, "SHA1_RSA2048", "keys/test-key.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert "Unsupported/untested algorithm: SHA1_RSA2048" in result.stderr


def test_signing_helper_rejects_extra_arguments(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    result = run(
        [SIGNING_HELPER, "SHA256_RSA2048", "keys/test-key.pem", "unexpected"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert "Unexpected arguments: unexpected" in result.stderr


def test_payload_signer_signs_sha256_digest(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"

    result = run(
        [
            PAYLOAD_SIGNER,
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            "keys/ota.pem",
        ],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-inkey",
            private_key,
            "-in",
            digest,
            "-sigfile",
            signature,
            "-pkeyopt",
            "rsa_padding_mode:pkcs1",
            "-pkeyopt",
            "digest:sha256",
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr


def test_payload_signer_rejects_missing_required_arguments(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    signature = tmp_path / "payload.signature"
    result = run(
        [PAYLOAD_SIGNER, "-out", signature, "-inkey", "keys/ota.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert not signature.exists()
