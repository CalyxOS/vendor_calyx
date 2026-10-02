#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Command-line front ends of the key scripts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .models import KeyReference, KeySpec
from .plaintext import PlaintextBackend

EXAMPLE_SUBJECT = (
    "'/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/"
    "emailAddress=android@android.com'"
)


class ScriptError(Exception):
    """The script stopped with exit status 1 after printing why."""


def _error(message: str, usage: Sequence[str]) -> ScriptError:
    """Print the message and the usage, and return the error to raise."""
    print(f"error: {message}, please try again", file=sys.stderr)
    for line in usage:
        print(line)
    return ScriptError()


def mkkey_main(program: str, arguments: Sequence[str]) -> int:
    """
    Generate a 2048-bit RSA key and its self-signed certificate as
    <key_name>.pk8 and <key_name>.x509.pem.

    Args:
        program: The script path to name in the usage text.
        arguments: The key name and the subject the script takes.

    Returns:
        0 on success, 1 for any failure.
    """
    usage = (
        f"Usage: {program} key_name subject",
        "Example key_name: networkstack",
        f"Example subject: {EXAMPLE_SUBJECT}",
    )
    try:
        if len(arguments) != 2:
            raise _error("incorrect number of arguments", usage)
        key_name, subject = arguments
        if shutil.which("openssl") is None:
            raise _error("openssl not found in PATH.", usage)
        if os.path.exists(f"{key_name}.pk8") and not os.path.exists(
            f"{key_name}.x509.pem",
        ):
            print(
                f"error: key {key_name} exists without {key_name}.x509.pem.",
                file=sys.stderr,
            )
            print(
                "Restore the certificate from a backup, or delete "
                f"{key_name}.pk8 if the key was never used.",
                file=sys.stderr,
            )
            return 1
        for suffix in (".pk8", ".pem", ".x509.pem"):
            if os.path.exists(f"{key_name}{suffix}"):
                raise _error(f"key {key_name} already exists", usage)
    except ScriptError:
        return 1

    spec = KeySpec(KeyReference(label=Path(key_name).name), 2048)
    backend = PlaintextBackend(Path(key_name).parent)
    try:
        backend.generate_key(spec)
        backend.generate_certificate(spec, subject)
    except subprocess.CalledProcessError as error:
        sys.stderr.write(os.fsdecode(error.stderr or b""))
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0
