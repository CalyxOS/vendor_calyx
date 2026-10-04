#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import run
from signing.payload_signing import verify_payload_signature


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
