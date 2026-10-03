#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Sign avbtool input through the backend-neutral Python PKCS#11 layer.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signing.avb_signing import (
    avb_input_digest,
    key_reference_from_path,
    pkcs11_signer_from_environment,
    sign_avb_input,
)
from signing.key_consistency import (
    require_matching_public_key,
    require_signature_from_public_key,
)


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
    signer = pkcs11_signer_from_environment()
    key_path = Path(key_file)
    reference = key_reference_from_path(signer, key_path, os.environ)
    require_matching_public_key(
        signer,
        reference,
        key_path,
        os.environ.get("OPENSSL_BIN", "openssl"),
    )
    data = sys.stdin.buffer.read()
    signature = sign_avb_input(signer, algorithm, reference, data)
    require_signature_from_public_key(
        key_path,
        avb_input_digest(algorithm, data)[0],
        signature,
        os.environ.get("OPENSSL_BIN", "openssl"),
    )
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
