#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Domain objects shared by plaintext and HSM signing backends.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_CERTIFICATE_DAYS = 10000


@dataclass(frozen=True, slots=True)
class KeyReference:
    """
    Backend-independent identity for an existing signing key.
    """

    key_id: str = ""
    label: str = ""


@dataclass(frozen=True, slots=True)
class KeySpec:
    """
    Properties required when creating a new RSA key.
    """

    reference: KeyReference
    key_size: int
    exportable: bool = False

    def __post_init__(self) -> None:
        """
        Reject nonsensical key sizes at the domain boundary.

        Raises:
            ValueError: If the key size is not positive.
        """
        if self.key_size <= 0:
            raise ValueError("key size must be positive")


@dataclass(frozen=True, slots=True)
class SignRequest:
    """
    Data and mechanism supplied to a signing backend.
    """

    key: KeyReference
    data: bytes
    mechanism: str
