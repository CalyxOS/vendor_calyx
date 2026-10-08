#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Construct signing backends for executable signing helpers.
"""

from __future__ import annotations

import os
from pathlib import Path

from .pkcs11 import Pkcs11Backend, Pkcs11Config


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
