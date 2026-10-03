#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Typed configuration and built-in registration for signing backends.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from .models import DEFAULT_CERTIFICATE_DAYS
from .pkcs11 import Pkcs11Backend, Pkcs11Config, environment_with


class PinSource(Protocol):
    """
    Resolve a PKCS#11 PIN only when constructing a backend.
    """

    def resolve(self, environment: Mapping[str, str] | None = None) -> str:
        """
        Resolve a non-empty PIN from an external source.

        Args:
            environment: Optional environment mapping used for resolution.

        Returns:
            The resolved PIN.

        Raises:
            KeyError: If a requested environment variable is absent.
            OSError: If an external source cannot be read.
            ValueError: If the resolved PIN is invalid.
        """
        ...


@dataclass(frozen=True, slots=True)
class EnvironmentPin:
    """
    Resolve a PIN from a named environment variable.
    """

    variable: str

    def __post_init__(self) -> None:
        """
        Reject an empty environment-variable name.

        Returns:
            None.

        Raises:
            ValueError: If the variable name is empty.
        """
        if not self.variable:
            raise ValueError("PIN environment variable must not be empty")

    def resolve(self, environment: Mapping[str, str] | None = None) -> str:
        """
        Read a non-empty PIN from an environment mapping.

        Args:
            environment: Mapping to inspect, defaulting to ``os.environ``.

        Returns:
            The resolved PIN.

        Raises:
            KeyError: If the variable is absent.
            ValueError: If its value is empty.
        """
        values = os.environ if environment is None else environment
        pin = values.get(self.variable)
        if pin is None:
            raise KeyError(
                f"PIN environment variable is not set: {self.variable}",
            )
        if not pin:
            raise ValueError(
                f"PIN environment variable is empty: {self.variable}",
            )
        return pin


@dataclass(frozen=True, slots=True)
class FilePin:
    """
    Resolve a PIN from a permission-restricted text file.
    """

    path: Path

    def resolve(self, environment: Mapping[str, str] | None = None) -> str:
        """
        Read one non-empty line from a private PIN file.

        Args:
            environment: Unused environment mapping accepted for source parity.

        Returns:
            The PIN with its final line ending removed.

        Raises:
            FileNotFoundError: If the path is not a regular file.
            PermissionError: If group or other permission bits are present.
            UnicodeDecodeError: If the file is not valid UTF-8.
            ValueError: If the file is empty or contains multiple lines.
        """
        del environment
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        if self.path.stat().st_mode & 0o077:
            message = (
                "PIN file must not have group or other permissions: "
                f"{self.path}"
            )
            raise PermissionError(message)
        lines = self.path.read_text().splitlines()
        if not lines or not lines[0]:
            raise ValueError("PIN file must not be empty")
        if len(lines) != 1:
            raise ValueError("PIN file must contain exactly one line")
        return lines[0]


@dataclass(frozen=True, slots=True)
class Pkcs11BackendConfiguration:
    """
    Typed settings used to construct a generic PKCS#11 backend.
    """

    module: Path
    pin_source: PinSource | None = None
    token_label: str | None = None
    slot: str | None = None
    tool: str = "pkcs11-tool"
    openssl: str = "openssl"
    openssl_engine: Path | None = None
    certificate_days: int = DEFAULT_CERTIFICATE_DAYS
    environment: Mapping[str, str] = field(
        default_factory=dict[str, str],
        repr=False,
    )

    def __post_init__(self) -> None:
        """
        Snapshot provider environment settings as an immutable mapping.

        Returns:
            None.
        """
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(self.environment)),
        )

    def create_backend(self) -> Pkcs11Backend:
        """
        Resolve credentials and construct the generic PKCS#11 backend.

        Returns:
            A backend configured for the selected module and token.

        Raises:
            KeyError: If a configured PIN environment variable is absent.
            OSError: If a configured PIN file cannot be read.
            ValueError: If PIN or backend configuration is invalid.
        """
        environment = environment_with(self.environment)
        pin = None
        if self.pin_source is not None:
            pin = self.pin_source.resolve(environment)
        return Pkcs11Backend(
            Pkcs11Config(
                module=self.module,
                pin=pin,
                token_label=self.token_label,
                slot=self.slot,
                tool=self.tool,
                openssl=self.openssl,
                openssl_engine=self.openssl_engine,
                certificate_days=self.certificate_days,
                environment=self.environment,
            ),
        )
