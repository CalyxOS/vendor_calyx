#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
avbtool signing helper that signs through the release's SigningServer.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from signing.avb_signing import avb_input_digest, key_name_from_path
from signing.key_consistency import require_signature_from_public_key
from signing.yubihsm_session_service import sign_digest_through_server

FALLBACK_HELPER = SCRIPT_DIR / "signing_helper.openssl.sh"


def sign_through_server(
    socket_path: Path,
    algorithm: str,
    key_file: str,
    data: bytes,
) -> bytes | None:
    """
    Ask the signing server for an AVB signature.

    Returns:
        The signature, or None if the server could not produce one.

    Raises:
        ValueError: If data is not a valid avbtool signing input for
            algorithm, or the signature does not verify under the public
            key in key_file.
    """
    digest_info, digest = avb_input_digest(algorithm, data)
    key_name = os.environ.get("KEY_ID") or key_name_from_path(
        Path(key_file),
        os.environ,
    )
    signature = sign_digest_through_server(socket_path, key_name, digest)
    if signature is not None:
        require_signature_from_public_key(
            Path(key_file),
            digest_info,
            signature,
        )
    return signature


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    data = sys.stdin.buffer.read()
    socket_path = os.environ.get("SIGNING_SERVER_SOCKET")
    if socket_path and len(arguments) == 2:
        algorithm, key_file = arguments
        signature = sign_through_server(
            Path(socket_path),
            algorithm,
            key_file,
            data,
        )
        if signature is not None:
            sys.stdout.buffer.write(signature)
            return 0
    return subprocess.run(
        [str(FALLBACK_HELPER), *arguments],
        input=data,
    ).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
