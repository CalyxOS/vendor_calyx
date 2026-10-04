#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Verification of OTA payload signatures.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

_SHA256_DIGEST_SIZE = 32


def verify_payload_signature(
    public_key: bytes,
    digest: bytes,
    signature: bytes,
    openssl: str = "openssl",
) -> None:
    """
    Verify an RSA PKCS#1 v1.5 payload signature before releasing it.

    Args:
        public_key: DER-encoded SubjectPublicKeyInfo from the token.
        digest: Precomputed SHA-256 payload digest.
        signature: Raw RSA signature returned by the backend.
        openssl: OpenSSL executable name or path.

    Returns:
        None.

    Raises:
        OSError: If temporary files or OpenSSL cannot be accessed.
        subprocess.CalledProcessError: If signature verification fails.
        ValueError: If the digest is not exactly 32 bytes.
    """
    if len(digest) != _SHA256_DIGEST_SIZE:
        raise ValueError(
            "payload SHA-256 digest must be exactly "
            f"{_SHA256_DIGEST_SIZE} bytes",
        )
    with tempfile.TemporaryDirectory(prefix="payload-signature.") as directory:
        temporary = Path(directory)
        public_key_file = temporary / "public.der"
        digest_file = temporary / "digest.bin"
        signature_file = temporary / "signature.bin"
        public_key_file.write_bytes(public_key)
        digest_file.write_bytes(digest)
        signature_file.write_bytes(signature)
        subprocess.run(
            (
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(public_key_file),
                "-in",
                str(digest_file),
                "-sigfile",
                str(signature_file),
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
                "-pkeyopt",
                "digest:sha256",
            ),
            check=True,
            capture_output=True,
        )
