#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
OTA payload signer that signs through the release's SigningServer.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))
sys.path.insert(0, str(SCRIPT_DIR))

from payload_signer import public_key_file
from signing.avb_signing import SHA256_DIGEST_INFO_PREFIX, key_name_from_path
from signing.key_consistency import require_signature_from_public_key
from signing.yubihsm_session_service import sign_digest_through_server

FALLBACK_SIGNER = SCRIPT_DIR / "payload_signer.py"


def _option(arguments: list[str], name: str) -> str | None:
    for index, argument in enumerate(arguments[:-1]):
        if argument == name:
            return arguments[index + 1]
    return None


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    socket_path = os.environ.get("SIGNING_SERVER_SOCKET")
    input_file = _option(arguments, "-in")
    output_file = _option(arguments, "-out")
    key_file = _option(arguments, "-inkey")
    if socket_path and input_file and output_file and key_file:
        digest = Path(input_file).read_bytes()
        key_name = os.environ.get("KEY_ID") or key_name_from_path(
            Path(key_file),
            os.environ,
        )
        signature = (
            sign_digest_through_server(Path(socket_path), key_name, digest)
            if len(digest) == 32
            else None
        )
        if signature is not None:
            require_signature_from_public_key(
                public_key_file(Path(key_file)),
                SHA256_DIGEST_INFO_PREFIX + digest,
                signature,
            )
            Path(output_file).write_bytes(signature)
            return 0
    return subprocess.run([str(FALLBACK_SIGNER), *arguments]).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
