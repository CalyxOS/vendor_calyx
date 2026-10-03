#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Signing backend capabilities.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import SignRequest


class Signer(Protocol):
    """
    Backend capability for producing signatures with an existing key.
    """

    def sign(self, request: SignRequest) -> bytes:
        """
        Sign request data with its referenced key and mechanism.

        Args:
            request: Key, input data, and signing mechanism to use.

        Returns:
            The generated signature bytes.
        """
        ...


@runtime_checkable
class KeyLabelResolver(Protocol):
    """
    Backend capability for resolving a private key's label to its object ID.
    """

    def key_id_for_label(self, label: str) -> str:
        """
        Return the unique PKCS#11 object ID associated with a label.

        Args:
            label: Private-key label used by legacy signing key paths.

        Returns:
            Lowercase hexadecimal object ID without a prefix.

        Raises:
            KeyError: If no private key has the label.
            ValueError: If private keys with the label name different IDs.
        """
        ...
