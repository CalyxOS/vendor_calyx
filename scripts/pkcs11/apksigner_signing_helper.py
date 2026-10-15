#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Sign apksigner's KMS extension-point input through the signing server, or
through the backend-neutral Python PKCS#11 layer when no server answers.

The command line is "apksigner_signing_helper.py MECHANISM KEY_ID". The
raw, unhashed signable content comes on standard input, and the raw
signature goes to standard output. MECHANISM is a full-message PKCS#11
mechanism such as "sha256-rsa-pkcs". The helper hashes the content with
its hash for the server, and the PKCS#11 layer hashes it otherwise.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signing import signing_helpers
from signing.key_consistency import require_signature_from_certificate
from signing.models import KeyReference, SignRequest

_MECHANISMS = frozenset(
    {"sha1-rsa-pkcs", "sha256-rsa-pkcs", "sha384-rsa-pkcs", "sha512-rsa-pkcs"},
)


def main(argv: list[str] | None = None) -> int:
    """
    Run apksigner's KMS-extension-point signing-helper protocol.

    Args:
        argv: Mechanism and key ID, defaulting to process arguments.

    Returns:
        Zero after writing a signature to standard output.

    Raises:
        ValueError: If arguments are invalid.
        OSError: If the PKCS#11 signing tool cannot be executed.
    """
    mechanism, key_id = signing_helpers.two_arguments(
        argv,
        "MECHANISM and KEY_ID",
    )
    if mechanism not in _MECHANISMS:
        raise ValueError(f"Unsupported mechanism: {mechanism}")
    data = sys.stdin.buffer.read()
    hash_name = mechanism.split("-", 1)[0]
    certificate = Path(f"{os.environ.get('KEY_DIR', '')}{key_id}.x509.pem")
    if "KEY_DIR" not in os.environ or not certificate.is_file():
        raise ValueError(
            f"no certificate {certificate} to check the signature of "
            f"{key_id} against",
        )

    def pkcs11_sign() -> bytes:
        signer = signing_helpers.pkcs11_signer_from_environment()
        reference = KeyReference(key_id=key_id, label=key_id)
        return signer.sign(SignRequest(reference, data, mechanism))

    signature = signing_helpers.sign(
        key_id,
        hashlib.new(hash_name, data).digest(),
        pkcs11_sign,
    )
    require_signature_from_certificate(certificate, data, signature, hash_name)
    sys.stdout.buffer.write(signature)
    return 0


if __name__ == "__main__":
    signing_helpers.run_helper(main)
