#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest
from conftest import run
from cryptography.hazmat.primitives import serialization
from signing.avb_signing import key_reference_from_path
from signing.payload_signing import (
    sign_payload_digest,
    verify_payload_signature,
)
from software_rsa import SoftwareSigner, rsa_key


def _sign_payload_digest(
    signer: SoftwareSigner,
    key_path: Path,
    digest: bytes,
    environment: Mapping[str, str],
) -> bytes:
    return sign_payload_digest(
        signer,
        key_reference_from_path(signer, key_path, environment),
        digest,
    )


def public_der(name: str) -> bytes:
    return (
        rsa_key(name)
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_payload_signature_verifies_under_the_key_id_override() -> None:
    signer = SoftwareSigner({"0x2000": rsa_key("a"), "0x1200": rsa_key("b")})
    digest = bytes(range(32))

    signature = _sign_payload_digest(
        signer,
        Path("keys/0x2000.pem"),
        digest,
        {"KEY_DIR": "keys/", "KEY_ID": "0x1200"},
    )

    verify_payload_signature(public_der("b"), digest, signature)
    with pytest.raises(subprocess.CalledProcessError):
        verify_payload_signature(public_der("a"), digest, signature)


@pytest.mark.parametrize("size", (0, 31, 33))
def test_payload_adapter_rejects_invalid_digest_size(size: int) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _sign_payload_digest(
            SoftwareSigner({}),
            Path("keys/ota.pem"),
            b"x" * size,
            {},
        )


def test_payload_signature_verification_accepts_only_valid_signature(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.der"
    digest = tmp_path / "digest.bin"
    signature = tmp_path / "signature.bin"
    digest.write_bytes(bytes(range(32)))
    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            private_key,
        ],
    )
    run(
        [
            "openssl",
            "pkey",
            "-in",
            private_key,
            "-pubout",
            "-outform",
            "DER",
            "-out",
            public_key,
        ],
    )
    run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            private_key,
            "-in",
            digest,
            "-out",
            signature,
            "-pkeyopt",
            "digest:sha256",
        ],
    )

    verify_payload_signature(
        public_key.read_bytes(),
        digest.read_bytes(),
        signature.read_bytes(),
    )
    corrupted = bytearray(signature.read_bytes())
    corrupted[-1] ^= 1
    with pytest.raises(subprocess.CalledProcessError):
        verify_payload_signature(
            public_key.read_bytes(),
            digest.read_bytes(),
            bytes(corrupted),
        )
