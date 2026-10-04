#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Generic PKCS#11 discovery and signing through ``pkcs11-tool``.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import quote

from .models import (
    DEFAULT_CERTIFICATE_DAYS,
    KeyReference,
    KeySpec,
    SignRequest,
)

_HEX_ID = re.compile(r"(?:0x)?([0-9a-fA-F]+)")
_ANNOTATED_ID = re.compile(r".*\(0x([0-9a-fA-F:]+)\)$")
_SIGNING_MECHANISMS = {
    "rsa-pkcs": "RSA-PKCS",
    "sha256-rsa-pkcs": "SHA256-RSA-PKCS",
    "sha384-rsa-pkcs": "SHA384-RSA-PKCS",
    "sha512-rsa-pkcs": "SHA512-RSA-PKCS",
}


def environment_with(overrides: Mapping[str, str]) -> dict[str, str]:
    """
    Copy the process environment and apply overrides onto it.

    Args:
        overrides: Variables to set or replace in the copy.

    Returns:
        A new environment mapping suitable for ``subprocess.run(env=...)``.
    """
    environment = os.environ.copy()
    environment.update(overrides)
    return environment


def preload_module(environment: dict[str, str], module: Path) -> None:
    """
    Preload a PKCS#11 module into pkcs11-tool, so that the module's getopt
    state binds to pkcs11-tool's instead of the private copy loading it
    with RTLD_DEEPBIND gives it. See "pkcs11-tool and the YubiHSM PKCS#11
    module" in DOCUMENTATION.md.

    Args:
        environment: Subprocess environment to mutate in place.
        module: PKCS#11 provider module path.

    Returns:
        None.
    """
    preload = environment.get("LD_PRELOAD")
    environment["LD_PRELOAD"] = (
        f"{module}:{preload}" if preload else str(module)
    )


@dataclass(frozen=True, slots=True)
class Pkcs11Config:
    """
    Provider-neutral connection settings for a PKCS#11 token.
    """

    module: Path
    pin: str | None = field(default=None, repr=False)
    discovery_pin: str | None = field(default=None, repr=False)
    # Certificates are signed with this PIN, since pin may hold the SO PIN.
    signing_pin: str | None = field(default=None, repr=False)
    token_label: str | None = None
    slot: str | None = None
    tool: str = "pkcs11-tool"
    openssl: str = "openssl"
    openssl_engine: Path | None = None
    certificate_days: int = DEFAULT_CERTIFICATE_DAYS
    use_so_pin: bool = False
    list_requires_no_pin: bool = False
    preload_module: bool = False
    environment: Mapping[str, str] = field(
        default_factory=dict[str, str],
        repr=False,
    )

    def __post_init__(self) -> None:
        """
        Validate selectors that would otherwise produce ambiguous commands.

        Returns:
            None.

        Raises:
            ValueError: If the module or token selector is invalid.
        """
        if not str(self.module):
            raise ValueError("PKCS#11 module must not be empty")
        if self.token_label is not None and not self.token_label:
            raise ValueError("PKCS#11 token label must not be empty")
        if self.slot is not None and not self.slot:
            raise ValueError("PKCS#11 slot must not be empty")
        if self.token_label is not None and self.slot is not None:
            raise ValueError(
                "select a PKCS#11 token by label or slot, not both",
            )
        if not self.tool:
            raise ValueError("PKCS#11 tool must not be empty")
        if not self.openssl:
            raise ValueError("OpenSSL executable must not be empty")
        if self.certificate_days <= 0:
            raise ValueError("certificate validity must be positive")
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(self.environment)),
        )


class Pkcs11Backend:
    """
    Discover objects and sign through a standard PKCS#11 provider.
    """

    def __init__(self, config: Pkcs11Config) -> None:
        """
        Configure access to one PKCS#11 token.

        Args:
            config: Module, token selector, credentials, and tool settings.

        Returns:
            None.
        """
        self.config = config

    def key_exists(self, key: KeyReference) -> bool:
        """
        Return whether a key exists for a reference, by its public key
        object, which a listing without login also shows.

        Args:
            key: Reference whose key ID identifies the PKCS#11 object.

        Returns:
            Whether the token contains a matching public key object.

        Raises:
            ValueError: If the key ID is not an even-length hexadecimal value.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If object discovery fails.
        """
        return self._object_exists("pubkey", self._object_id(key))

    def certificate_exists(self, key: KeyReference) -> bool:
        """
        Return whether a certificate object exists for a reference.

        Args:
            key: Reference whose key ID identifies the PKCS#11 object.

        Returns:
            Whether the token contains a matching certificate object.

        Raises:
            ValueError: If the key ID is not an even-length hexadecimal value.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If object discovery fails.
        """
        return self._object_exists("cert", self._object_id(key))

    def export_public_key(self, key: KeyReference) -> bytes:
        """
        Export a public-key object in the provider's DER representation.

        Args:
            key: Reference whose key ID identifies the PKCS#11 object.

        Returns:
            DER-encoded public-key object data.

        Raises:
            ValueError: If the key ID is invalid.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If no public key has the ID, or
                the export fails.
        """
        return self.run(
            "--read-object",
            "--type",
            "pubkey",
            "--id",
            self._object_id(key),
        ).stdout

    def sign(self, request: SignRequest) -> bytes:
        """
        Sign request bytes with a private PKCS#11 key object.

        Args:
            request: Key reference, input bytes, and PKCS#11 signing mechanism.

        Returns:
            Signature bytes returned by the provider.

        Raises:
            ValueError: If the key ID or signing mechanism is invalid.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If signing fails, including when
                no private key matches the reference.
        """
        try:
            mechanism = _SIGNING_MECHANISMS[request.mechanism.lower()]
        except KeyError as error:
            raise ValueError(
                f"unsupported PKCS#11 signing mechanism: {request.mechanism}",
            ) from error
        return self.run(
            "--sign",
            "--mechanism",
            mechanism,
            "--id",
            self._object_id(request.key),
            input_data=request.data,
        ).stdout

    def key_id_for_label(self, label: str) -> str:
        """
        Resolve a private key's label to one unique object ID.

        Args:
            label: Private-key label derived from a signing key path.

        Returns:
            Lowercase hexadecimal object ID without a prefix.

        Raises:
            KeyError: If no private key has the label.
            ValueError: If the label is empty or resolves to multiple IDs.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If object discovery fails.
        """
        if not label:
            raise ValueError("PKCS#11 private key label must not be empty")
        output = self.run(
            "--list-objects",
            "--type",
            "privkey",
            "--label",
            label,
            include_pin=not self.config.list_requires_no_pin,
            use_discovery_pin=True,
        ).stdout
        identifiers = [
            self._normalize_listing_id(
                line.split(b":", 1)[1].strip().decode("ascii"),
            )
            for line in output.splitlines()
            if line.lstrip().startswith(b"ID:")
        ]
        if not identifiers:
            raise KeyError(f"PKCS#11 private key label not found: {label}")
        unique = set(identifiers)
        if len(unique) != 1:
            raise ValueError(
                f"PKCS#11 private key label is ambiguous: {label}",
            )
        return identifiers[0]

    def generate_key(self, spec: KeySpec) -> None:
        """
        Generate a persistent RSA key pair on the configured token.

        Args:
            spec: Object identity, key size, and private-key export policy.

        Returns:
            None.

        Raises:
            ValueError: If the ID, label or key size is invalid, or
                either half of the key pair already exists.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If discovery or generation fails.
        """
        object_id = self._object_id(spec.reference)
        if not spec.reference.label:
            raise ValueError("PKCS#11 key label must not be empty")
        if self._object_exists("privkey", object_id) or self._object_exists(
            "pubkey",
            object_id,
        ):
            raise ValueError(
                f"PKCS#11 key already exists: {spec.reference.key_id}",
            )

        arguments = [
            "--keypairgen",
            "--key-type",
            f"RSA:{spec.key_size}",
            "--sensitive",
        ]
        if spec.exportable:
            arguments.append("--extractable")
        arguments.extend(("--id", object_id, "--label", spec.reference.label))
        self.run(*arguments)

    def generate_certificate(self, spec: KeySpec, subject: str) -> bytes:
        """
        Create and import a self-signed certificate for a token-held key.

        Args:
            spec: Identity and size of an existing private key.
            subject: OpenSSL distinguished-name string for the certificate.

        Returns:
            The generated PEM-encoded certificate.

        Raises:
            KeyError: If no matching key exists.
            ValueError: If configuration, identity, subject, or certificate
                state prevents generation.
            OSError: If OpenSSL or ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If signing or import fails.
        """
        if self.config.openssl_engine is None:
            raise ValueError(
                "PKCS#11 OpenSSL engine is required for certificates",
            )
        signing_pin = (
            self.config.signing_pin
            if self.config.signing_pin is not None
            else self.config.pin
        )
        if signing_pin is None:
            raise ValueError("PKCS#11 PIN is required for certificates")
        if not subject:
            raise ValueError("certificate subject must not be empty")
        if not spec.reference.label:
            raise ValueError("PKCS#11 certificate label must not be empty")
        self._require_key(spec.reference)
        if self.certificate_exists(spec.reference):
            raise ValueError(
                f"PKCS#11 certificate already exists: {spec.reference.key_id}",
            )

        object_id = self._object_id(spec.reference)
        with tempfile.TemporaryDirectory(
            prefix="pkcs11-certificate.",
        ) as directory:
            temporary_directory = Path(directory)
            openssl_config = temporary_directory / "openssl.cnf"
            certificate = temporary_directory / "certificate.pem"
            openssl_config.write_text(self._openssl_config())
            openssl_config.chmod(0o600)
            environment = environment_with(self.config.environment)
            environment["PKCS11_BACKEND_PIN"] = signing_pin
            environment["OPENSSL_CONF"] = str(openssl_config)
            subprocess.run(
                [
                    self.config.openssl,
                    "req",
                    "-new",
                    "-x509",
                    "-engine",
                    "pkcs11",
                    "-sha256",
                    "-keyform",
                    "engine",
                    "-key",
                    self._private_key_uri(object_id),
                    "-days",
                    str(self.config.certificate_days),
                    "-subj",
                    subject,
                    "-out",
                    str(certificate),
                ],
                check=True,
                capture_output=True,
                env=environment,
            )
            contents = certificate.read_bytes()
            self.run(
                "--write-object",
                str(certificate),
                "--type",
                "cert",
                "--id",
                object_id,
                "--label",
                spec.reference.label,
            )
        return contents

    def _openssl_config(self) -> str:
        """
        Render a temporary OpenSSL configuration for the PKCS#11 engine.

        Returns:
            OpenSSL configuration containing module and PIN environment hooks.
        """
        return f"""openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = {self.config.openssl_engine}
MODULE_PATH = {self.config.module}
init = 0
PIN = ${{ENV::PKCS11_BACKEND_PIN}}
"""

    def _private_key_uri(self, object_id: str) -> str:
        """
        Build an RFC 7512 URI for a private key selected by byte ID.

        Args:
            object_id: Lowercase hexadecimal object ID without a prefix.

        Returns:
            PKCS#11 URI scoped to the configured token selector.
        """
        attributes: list[str] = []
        if self.config.token_label is not None:
            attributes.append(
                f"token={quote(self.config.token_label, safe='')}",
            )
        if self.config.slot is not None:
            attributes.append(f"slot-id={quote(self.config.slot, safe='')}")
        encoded_id = "".join(
            f"%{object_id[index : index + 2]}"
            for index in range(0, len(object_id), 2)
        )
        attributes.extend((f"id={encoded_id}", "type=private"))
        return "pkcs11:" + ";".join(attributes)

    def _require_key(self, key: KeyReference) -> None:
        """
        Require a referenced key to exist before an operation.

        Args:
            key: Private key reference to check.

        Returns:
            None.

        Raises:
            KeyError: If no matching key exists.
            ValueError: If the key ID is invalid.
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If object discovery fails.
        """
        if not self.key_exists(key):
            raise KeyError(f"PKCS#11 key not found: {key.key_id}")

    def _object_exists(self, object_type: str, object_id: str) -> bool:
        """
        Return whether an object of one type exists for a normalized ID.

        Args:
            object_type: ``pkcs11-tool`` object type to list.
            object_id: Lowercase hexadecimal object ID without a prefix.

        Returns:
            Whether a matching object was listed.

        Raises:
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If object discovery fails.
        """
        output = self.run(
            "--list-objects",
            "--type",
            object_type,
            "--id",
            object_id,
            include_pin=not self.config.list_requires_no_pin,
            use_discovery_pin=True,
        ).stdout
        return self.listing_contains_id(output, object_id)

    @staticmethod
    def _object_id(key: KeyReference) -> str:
        """
        Normalize a hexadecimal key ID for ``pkcs11-tool``.

        Args:
            key: Reference containing a hexadecimal object ID.

        Returns:
            Lowercase hexadecimal bytes without a ``0x`` prefix.

        Raises:
            ValueError: If the ID is malformed or contains partial bytes.
        """
        match = _HEX_ID.fullmatch(key.key_id)
        if match is None or len(match.group(1)) % 2:
            raise ValueError(f"invalid PKCS#11 key ID: {key.key_id!r}")
        return match.group(1).lower()

    @staticmethod
    def _normalize_listing_id(rendered: str) -> str:
        """
        Normalize plain and annotated ``pkcs11-tool`` object IDs.

        Args:
            rendered: Text following an object listing's ``ID:`` field.

        Returns:
            Lowercase hexadecimal object ID without separators or a prefix.

        Raises:
            ValueError: If the listing does not contain a hexadecimal ID.
        """
        annotated = _ANNOTATED_ID.fullmatch(rendered)
        candidate = (
            annotated.group(1).replace(":", "") if annotated else rendered
        )
        match = _HEX_ID.fullmatch(candidate)
        if match is None or len(match.group(1)) % 2:
            raise ValueError(f"invalid PKCS#11 object ID listing: {rendered}")
        return match.group(1).lower()

    @classmethod
    def listing_contains_id(cls, output: bytes, object_id: str) -> bool:
        """
        Return whether ``pkcs11-tool`` listed an object with an ID.

        Args:
            output: Raw object-listing output.
            object_id: Lowercase hexadecimal object ID without a prefix.

        Returns:
            Whether an ``ID:`` field of the listing names object_id.
        """
        for line in output.splitlines():
            field = line.lstrip()
            if not field.startswith(b"ID:"):
                continue
            try:
                listed = cls._normalize_listing_id(
                    field[3:].strip().decode("ascii", errors="replace"),
                )
            except ValueError:
                continue
            if listed == object_id:
                return True
        return False

    def _base_arguments(
        self,
        include_pin: bool = True,
        use_discovery_pin: bool = False,
    ) -> list[str]:
        """
        Build common module, token, and login arguments.

        Returns:
            Arguments shared by discovery, export, and signing commands.
        """
        arguments = ["--module", str(self.config.module)]
        if self.config.token_label is not None:
            arguments.extend(("--token-label", self.config.token_label))
        if self.config.slot is not None:
            arguments.extend(("--slot", self.config.slot))
        pin = self.config.pin
        if use_discovery_pin:
            pin = self.config.discovery_pin
            if pin is None and not self.config.use_so_pin:
                pin = self.config.pin
        if include_pin and pin is not None:
            if self.config.use_so_pin and not use_discovery_pin:
                arguments.extend(
                    (
                        "--login-type",
                        "so",
                        "--so-pin",
                        "env:PKCS11_BACKEND_PIN",
                    ),
                )
            else:
                separate_discovery_pin = (
                    use_discovery_pin and self.config.discovery_pin is not None
                )
                variable = (
                    "PKCS11_BACKEND_DISCOVERY_PIN"
                    if separate_discovery_pin
                    else "PKCS11_BACKEND_PIN"
                )
                arguments.extend(("--pin", f"env:{variable}"))
        return arguments

    def _environment(self) -> dict[str, str]:
        """
        Build a subprocess environment containing provider settings and PIN.

        Returns:
            A copy of the process environment augmented for this backend.
        """
        environment = environment_with(self.config.environment)
        if self.config.pin is not None:
            environment["PKCS11_BACKEND_PIN"] = self.config.pin
        if self.config.discovery_pin is not None:
            environment["PKCS11_BACKEND_DISCOVERY_PIN"] = (
                self.config.discovery_pin
            )
        return environment

    def run(
        self,
        *arguments: str,
        input_data: bytes | None = None,
        include_pin: bool = True,
        use_discovery_pin: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        """
        Execute ``pkcs11-tool`` with credentials supplied through the
        environment.

        Args:
            arguments: Operation-specific ``pkcs11-tool`` arguments.
            input_data: Optional bytes supplied to standard input.
            include_pin: Whether to include configured login arguments.
            use_discovery_pin: Whether to use normal discovery credentials.

        Returns:
            The successful completed process.

        Raises:
            OSError: If ``pkcs11-tool`` cannot be executed.
            subprocess.CalledProcessError: If ``pkcs11-tool`` exits
                unsuccessfully.
        """
        environment = self._environment()
        if self.config.preload_module:
            preload_module(environment, self.config.module)
        return subprocess.run(
            [
                self.config.tool,
                *self._base_arguments(include_pin, use_discovery_pin),
                *arguments,
            ],
            input=input_data,
            check=True,
            capture_output=True,
            env=environment,
        )


_TOKEN_URI_LINE = re.compile(r"^ *uri *:")


def is_any_pkcs11_token_initialized(*, tool: str, module: Path) -> bool:
    """
    Return whether any slot behind a PKCS#11 module has an initialized
    token, identified by ``pkcs11-tool --list-token-slots`` printing a
    URI line for it.

    Args:
        tool: ``pkcs11-tool`` executable.
        module: PKCS#11 provider module path.

    Returns:
        Whether at least one token slot reports a URI.

    Raises:
        OSError: If ``pkcs11-tool`` cannot be executed.
        subprocess.CalledProcessError: If listing slots fails.
    """
    result = subprocess.run(
        [tool, "--module", str(module), "--list-token-slots"],
        check=True,
        capture_output=True,
    )
    return any(
        _TOKEN_URI_LINE.match(line)
        for line in result.stdout.decode(errors="replace").splitlines()
    )


def initialize_pkcs11_token(
    *,
    tool: str,
    module: Path,
    label: str,
    so_pin: str,
    user_pin: str,
) -> None:
    """
    Initialize a blank PKCS#11 token and set its user PIN, unless a
    token is already initialized behind this module.

    ``--init-token`` assigns a label and security-officer PIN to an
    uninitialized slot, then ``--init-pin`` (authenticated with that
    SO-PIN) sets the user PIN.

    Args:
        tool: ``pkcs11-tool`` executable.
        module: PKCS#11 provider module path.
        label: Label to assign to the newly initialized token.
        so_pin: Security-officer PIN to assign during initialization.
        user_pin: User PIN to set on the newly initialized token.

    Returns:
        None.

    Raises:
        OSError: If ``pkcs11-tool`` cannot be executed.
        subprocess.CalledProcessError: If either step fails.
        RuntimeError: If the token does not report as initialized
            immediately after ``--init-token`` succeeds.
    """
    if is_any_pkcs11_token_initialized(tool=tool, module=module):
        return

    environment = os.environ.copy()
    environment["PKCS11_BACKEND_SO_PIN"] = so_pin
    environment["PKCS11_BACKEND_PIN"] = user_pin
    subprocess.run(
        [
            tool,
            "--label",
            label,
            "--module",
            str(module),
            "--init-token",
            "--so-pin",
            "env:PKCS11_BACKEND_SO_PIN",
        ],
        check=True,
        capture_output=True,
        env=environment,
    )
    if not is_any_pkcs11_token_initialized(tool=tool, module=module):
        raise RuntimeError(
            "Initialized token, but it does not report as initialized",
        )
    subprocess.run(
        [
            tool,
            "--module",
            str(module),
            "--token-label",
            label,
            "--login-type",
            "so",
            "--so-pin",
            "env:PKCS11_BACKEND_SO_PIN",
            "--init-pin",
            "--pin",
            "env:PKCS11_BACKEND_PIN",
        ],
        check=True,
        capture_output=True,
        env=environment,
    )
