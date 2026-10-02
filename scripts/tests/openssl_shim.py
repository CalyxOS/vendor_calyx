#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
from pathlib import Path

from conftest import run

OPENSSL_PKCS11_SHIM = """#!/bin/bash
set -euo pipefail
translated=()
while [ $# -gt 0 ]; do
  case "$1" in
    -engine|-keyform)
      shift 2
      ;;
    -inkey)
      translated+=("-inkey" "${TEST_PRIVATE_KEY:?}")
      shift 2
      ;;
    *)
      translated+=("$1")
      shift
      ;;
  esac
done
exec openssl "${translated[@]}"
"""


def write_openssl_pkcs11_shim(directory: Path) -> Path:
    """
    Write an OpenSSL wrapper that signs with TEST_PRIVATE_KEY in place of
    the PKCS#11 engine key the OpenSSL helpers name.

    Args:
        directory: Directory to create the wrapper in.

    Returns:
        Path of the executable wrapper.
    """
    shim = directory / "openssl-pkcs11-shim"
    shim.write_text(OPENSSL_PKCS11_SHIM)
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return shim


def generate_rsa_key(directory: Path, bits: int) -> Path:
    """
    Generate a PEM RSA private key with OpenSSL.

    Args:
        directory: Directory to write the key to.
        bits: RSA modulus size.

    Returns:
        Path of the private key.
    """
    key = directory / f"rsa-{bits}.pem"
    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            f"rsa_keygen_bits:{bits}",
            "-out",
            key,
        ],
    )
    return key


def helper_env(shim: Path, private_key: Path) -> dict[str, str]:
    """
    Environment for the OpenSSL helpers to sign through the shim.

    Args:
        shim: Wrapper from write_openssl_pkcs11_shim().
        private_key: Key the wrapper signs with.

    Returns:
        Environment overrides.
    """
    return {
        "OPENSSL_BIN": str(shim),
        "PKCS11_TOOL_BIN": "/bin/true",
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "PKCS11_MODULE": "/dev/null",
        "PKCS11_PIN": "test-only",
        "TEST_PRIVATE_KEY": str(private_key),
    }
