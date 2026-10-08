#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Sign avbtool input through the release's SigningServer, or else through
the backend-neutral Python PKCS#11 layer.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signing.avb_signing import (
    avb_input_digest,
    key_name_from_path,
    pkcs11_signer_from_environment,
)
from signing.key_consistency import (
    require_matching_public_key,
    require_signature_from_public_key,
)
from signing.models import KeyReference, SignRequest
from signing.yubihsm_session_service import sign_digest_through_server


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
    """
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) < 2:
        raise ValueError("expected ALGORITHM and KEY_FILE")
    if len(arguments) > 2:
        unexpected = " ".join(arguments[2:])
        raise ValueError(f"Unexpected arguments: {unexpected}")
    algorithm, key_file = arguments
    key_path = Path(key_file)
    data = sys.stdin.buffer.read()
    digest_info, digest = avb_input_digest(algorithm, data)
    key_name = key_name_from_path(key_path, os.environ)
    signature = None
    socket_path = os.environ.get("SIGNING_SERVER_SOCKET")
    if socket_path:
        signature = sign_digest_through_server(
            Path(socket_path),
            key_name,
            digest,
        )
    if signature is None:
        signer = pkcs11_signer_from_environment()
        reference = KeyReference(key_name, key_name)
        require_matching_public_key(signer, reference, key_path)
        signature = signer.sign(SignRequest(reference, digest_info, "rsa-pkcs"))
    require_signature_from_public_key(key_path, digest_info, signature)
    sys.stdout.buffer.write(signature)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        if error.stderr:
            sys.stderr.buffer.write(error.stderr)
        raise SystemExit(1) from None
    except (KeyError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
