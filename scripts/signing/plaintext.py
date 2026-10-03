#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Plaintext OpenSSL backend for AOSP-compatible signing keys.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from .models import (
    DEFAULT_CERTIFICATE_DAYS,
    KeyReference,
    KeySpec,
)


class PlaintextBackend:
    """
    Manage AOSP-style plaintext keys beneath one key directory.
    """

    def __init__(self, key_directory: Path) -> None:
        """
        Configure a plaintext key directory.

        Args:
            key_directory: Root beneath which AOSP key files are stored.

        Returns:
            None.
        """
        self.key_directory = key_directory.resolve()

    def key_exists(self, key: KeyReference) -> bool:
        """
        Return whether the referenced PKCS#8 private key exists.

        Args:
            key: Reference whose label identifies a path below the key
                directory.

        Returns:
            Whether the ``.pk8`` file is a regular file.

        Raises:
            ValueError: If the key label escapes the configured directory.
        """
        return self._key_path(key, ".pk8").is_file()

    def certificate_exists(self, key: KeyReference) -> bool:
        """
        Return whether the referenced X.509 certificate exists.

        Args:
            key: Reference whose label identifies a path below the key
                directory.

        Returns:
            Whether the ``.x509.pem`` file is a regular file.

        Raises:
            ValueError: If the key label escapes the configured directory.
        """
        return self._key_path(key, ".x509.pem").is_file()

    def generate_key(self, spec: KeySpec) -> None:
        """
        Generate an unencrypted AOSP-compatible DER PKCS#8 private key.

        Args:
            spec: Key identity, size, and export policy.

        Returns:
            None.

        Raises:
            FileExistsError: If key or certificate material already exists.
            ValueError: If the key label is empty, absolute, or escapes the
                key directory.
            subprocess.CalledProcessError: If OpenSSL cannot generate the key.
        """
        private_key = self._key_path(spec.reference, ".pk8")
        certificate = self._key_path(spec.reference, ".x509.pem")
        self._require_absent(private_key, certificate)
        private_key.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            dir=private_key.parent,
            prefix=f".{private_key.name}.",
        ) as temporary_directory:
            temporary = Path(temporary_directory)
            pem_key = temporary / "private.pem"
            pkcs8_key = temporary / "private.pk8"
            self._run(
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                f"rsa_keygen_bits:{spec.key_size}",
                "-out",
                str(pem_key),
            )
            self._run(
                "pkcs8",
                "-in",
                str(pem_key),
                "-topk8",
                "-outform",
                "DER",
                "-out",
                str(pkcs8_key),
                "-nocrypt",
            )
            pkcs8_key.chmod(0o600)
            os.replace(pkcs8_key, private_key)

    def generate_certificate(self, spec: KeySpec, subject: str) -> bytes:
        """
        Generate an AOSP-compatible self-signed X.509 certificate.

        Args:
            spec: Identity and size of an existing private key.
            subject: OpenSSL distinguished-name string for the certificate.

        Returns:
            The generated PEM-encoded certificate.

        Raises:
            FileExistsError: If a certificate already exists for the key.
            ValueError: If the key label escapes the configured directory.
            subprocess.CalledProcessError: If OpenSSL cannot create the
                certificate.
        """
        private_key = self._key_path(spec.reference, ".pk8")
        certificate = self._key_path(spec.reference, ".x509.pem")
        if certificate.exists():
            raise FileExistsError(certificate)
        certificate.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=certificate.parent,
            prefix=f".{certificate.name}.",
        ) as temporary_directory:
            temporary_certificate = (
                Path(temporary_directory) / "certificate.pem"
            )
            self._run(
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-key",
                str(private_key),
                "-keyform",
                "DER",
                "-out",
                str(temporary_certificate),
                "-days",
                str(DEFAULT_CERTIFICATE_DAYS),
                "-subj",
                subject,
            )
            contents = temporary_certificate.read_bytes()
            os.replace(temporary_certificate, certificate)
        return contents

    def _key_path(self, key: KeyReference, suffix: str) -> Path:
        """
        Resolve one key artifact while preventing directory traversal.

        Args:
            key: Reference whose label supplies the relative storage path.
            suffix: AOSP artifact suffix to append to the label.

        Returns:
            Absolute path to the requested artifact.

        Raises:
            ValueError: If the label is empty, absolute, or escapes the key
                directory.
        """
        if not key.label:
            raise ValueError("plaintext key label must not be empty")
        relative = Path(key.label)
        if relative.is_absolute():
            raise ValueError("plaintext key label must be relative")
        path = (self.key_directory / f"{key.label}{suffix}").resolve()
        if not path.is_relative_to(self.key_directory):
            raise ValueError("plaintext key label escapes the key directory")
        return path

    @staticmethod
    def _require_absent(*paths: Path) -> None:
        """
        Reject generation when any destination artifact already exists.

        Args:
            paths: Destination paths that must all be absent.

        Returns:
            None.

        Raises:
            FileExistsError: If any destination already exists.
        """
        for path in paths:
            if path.exists():
                raise FileExistsError(path)

    def _run(
        self,
        *arguments: str,
        input_data: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """
        Run OpenSSL with captured binary output and checked status.

        Args:
            arguments: OpenSSL subcommand and arguments.
            input_data: Optional bytes to supply on standard input.

        Returns:
            The successful completed process.

        Raises:
            subprocess.CalledProcessError: If OpenSSL exits unsuccessfully.
        """
        return subprocess.run(
            ["openssl", *arguments],
            input=input_data,
            check=True,
            capture_output=True,
        )
