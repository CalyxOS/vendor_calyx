#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Sign avbtool input through the release's SigningServer, or for a SoftHSM
release through the backend-neutral Python PKCS#11 layer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signing import signing_helpers
from signing.avb_signing import avb_input_digest
from signing.key_consistency import (
    require_matching_public_key,
    require_signature_from_public_key,
)
from signing.models import KeyReference, SignRequest


def main(argv: list[str] | None = None) -> int:
    """
    Run avbtool's external signing-helper protocol.

    Args:
        argv: Algorithm and public-key path, defaulting to process arguments.

    Returns:
        Zero after writing a signature to standard output.

    Raises:
        ValueError: If arguments or AVB input are invalid.
        OSError: If the PKCS#11 signing tool cannot be executed.
        RuntimeError: If PKCS11_VENDOR is yubihsm and the signing server
            does not sign.
    """
    algorithm, key_file = signing_helpers.two_arguments(
        argv,
        "ALGORITHM and KEY_FILE",
    )
    key_path = Path(key_file)
    data = sys.stdin.buffer.read()
    digest_info, digest = avb_input_digest(algorithm, data)
    key_name = signing_helpers.key_name_from_path(key_path, os.environ)

    def pkcs11_sign() -> bytes:
        signer = signing_helpers.pkcs11_signer_from_environment()
        reference = KeyReference(key_name, key_name)
        require_matching_public_key(signer, reference, key_path)
        return signer.sign(SignRequest(reference, digest_info, "rsa-pkcs"))

    signature = signing_helpers.sign(key_name, digest, pkcs11_sign)
    require_signature_from_public_key(key_path, digest_info, signature)
    sys.stdout.buffer.write(signature)
    return 0


if __name__ == "__main__":
    signing_helpers.run_helper(main)
