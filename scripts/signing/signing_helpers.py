#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
What the signing helpers that avbtool, apksigner and the OTA tools run
share.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NoReturn

from .pkcs11 import Pkcs11Backend, Pkcs11Config
from .yubihsm_session_service import sign_digest_through_server


def run_helper(main: Callable[[], int]) -> NoReturn:
    """
    Exit with the status main() returns, or with 1 after printing why it
    failed.

    Args:
        main: The helper's entry point.

    Raises:
        SystemExit: Always.
    """
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        if error.stderr:
            sys.stderr.buffer.write(error.stderr)
        raise SystemExit(1) from None
    except (KeyError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error


def two_arguments(argv: Sequence[str] | None, names: str) -> tuple[str, str]:
    """
    Take the two arguments of a helper's command line.

    Args:
        argv: The arguments, or None for the process arguments.
        names: The arguments' names, for the error.

    Returns:
        The two arguments.

    Raises:
        ValueError: If there are not exactly two arguments.
    """
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) < 2:
        raise ValueError(f"expected {names}")
    if len(arguments) > 2:
        unexpected = " ".join(arguments[2:])
        raise ValueError(f"Unexpected arguments: {unexpected}")
    return arguments[0], arguments[1]


def key_name_from_path(key_path: Path, environment: Mapping[str, str]) -> str:
    """
    Derive a key's name from the key path a release tool passes.

    Args:
        key_path: The key path the release tool passes.
        environment: Variables containing the optional ``KEY_DIR`` prefix.

    Returns:
        Key name with the configured directory prefix and ``.pem`` suffix
        removed.
    """
    rendered = str(key_path)
    key_directory = environment.get("KEY_DIR")
    if key_directory and rendered.startswith(key_directory):
        rendered = rendered[len(key_directory) :]
    return rendered.removesuffix(".pem")


def pkcs11_signer_from_environment() -> Pkcs11Backend:
    """
    Construct the generic PKCS#11 signer from the process environment.

    Returns:
        Configured generic PKCS#11 signing backend.

    Raises:
        KeyError: If ``PKCS11_MODULE`` is absent.
    """
    values = os.environ
    use_so_pin = values.get("SIGNING_USES_SO_PIN", "n") == "y"
    pin_variable = "PKCS11_SO_PIN" if use_so_pin else "PKCS11_PIN"
    return Pkcs11Backend(
        Pkcs11Config(
            module=Path(values["PKCS11_MODULE"]),
            pin=values.get(pin_variable) or None,
            discovery_pin=(values.get("PKCS11_PIN") or None)
            if use_so_pin
            else None,
            token_label=values.get("PKCS11_TOKEN_LABEL"),
            slot=values.get("PKCS11_SLOT"),
            tool=values.get("PKCS11_TOOL_BIN", "pkcs11-tool"),
            use_so_pin=use_so_pin,
            list_requires_no_pin=(
                values.get("LIST_REQUIRES_NO_PIN", "n") == "y"
            ),
            preload_module=values.get("PKCS11_VENDOR") == "yubihsm",
        ),
    )


def sign(
    key_name: str,
    digest: bytes,
    pkcs11_sign: Callable[[], bytes],
) -> bytes:
    """
    Sign a digest through the signing server SIGNING_SERVER_SOCKET names,
    or through pkcs11_sign() when no server answers.

    Args:
        key_name: The key's name.
        digest: The digest the server signs.
        pkcs11_sign: Signs through PKCS#11 instead.

    Returns:
        The signature.
    """
    socket_path = os.environ.get("SIGNING_SERVER_SOCKET")
    if socket_path:
        signature = sign_digest_through_server(
            Path(socket_path),
            key_name,
            digest,
        )
        if signature is not None:
            return signature
    return pkcs11_sign()
