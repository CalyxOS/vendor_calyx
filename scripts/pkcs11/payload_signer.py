#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Sign OTA payload digests through the backend-neutral Python PKCS#11 layer.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signing.avb_signing import (
    key_reference_from_path,
    pkcs11_signer_from_environment,
)
from signing.key_consistency import require_matching_public_key
from signing.payload_signing import (
    sign_payload_digest,
    verify_payload_signature,
)


def write_signature_atomically(output: Path, signature: bytes) -> None:
    """
    Replace a payload signature only after writing it successfully.

    Args:
        output: Final signature destination.
        signature: Complete signature bytes to store.

    Returns:
        None.

    Raises:
        OSError: If the temporary or final output cannot be written.
    """
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent,
            prefix=f".{output.name}.",
            delete=False,
        ) as temporary:
            temporary.write(signature)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def public_key_file(key_path: Path) -> Path:
    """
    Find the PEM public key that a payload signer's -inkey names.

    With a PKCS#11 configuration, releasetools passes the package key
    without a suffix ("keys/0x2000"), and the key directory holds its
    public key as "keys/0x2000.pem".

    Args:
        key_path: Key path supplied through ``-inkey``.

    Returns:
        ``key_path`` if it is a file, otherwise ``key_path`` with
        ``.pem`` appended.
    """
    if key_path.is_file():
        return key_path
    return Path(f"{key_path}.pem")


def build_parser() -> argparse.ArgumentParser:
    """
    Build the OpenSSL-compatible payload-signer argument parser.

    Returns:
        Parser for the input, output, and key paths used by release tools.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-in",
        dest="input_file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "-out",
        dest="output_file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "-inkey",
        dest="key_file",
        type=Path,
        required=True,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Run the external OTA payload-signer protocol.

    Args:
        argv: OpenSSL-style arguments, defaulting to process arguments.

    Returns:
        Zero after writing the payload signature.

    Raises:
        OSError: If input, output, or the PKCS#11 tool cannot be accessed.
        ValueError: If the payload digest is invalid.
    """
    args, _ = build_parser().parse_known_args(argv)
    verify_signature = os.environ.get("DEBUG_PAYLOAD_SIGNER") or "y"
    if verify_signature not in {"y", "n"}:
        raise ValueError("DEBUG_PAYLOAD_SIGNER must be 'y' or 'n'")
    signer = pkcs11_signer_from_environment()
    digest = args.input_file.read_bytes()
    reference = key_reference_from_path(signer, args.key_file, os.environ)
    openssl = os.environ.get("OPENSSL_BIN", "openssl")
    public_key = require_matching_public_key(
        signer,
        reference,
        public_key_file(args.key_file),
        openssl,
    )
    signature = sign_payload_digest(signer, reference, digest)
    if verify_signature == "y":
        verify_payload_signature(
            public_key,
            digest,
            signature,
            openssl,
        )
    write_signature_atomically(args.output_file, signature)
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
