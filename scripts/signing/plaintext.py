#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Generate AOSP-compatible plaintext signing keys and certificates with
OpenSSL.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from .models import DEFAULT_CERTIFICATE_DAYS


def generate_certified_key(
    key_directory: Path,
    label: str,
    subject: str,
) -> None:
    """
    Generate an unencrypted RSA 2048 DER PKCS#8 private key and its
    self-signed X.509 certificate as <label>.pk8 and <label>.x509.pem
    beneath a key directory.

    Args:
        key_directory: Root beneath which AOSP key files are stored.
        label: Relative path of the key below the key directory.
        subject: OpenSSL distinguished-name string for the certificate.

    Raises:
        FileExistsError: If the key or its certificate already exists.
        ValueError: If the label is empty, absolute, or escapes the key
            directory.
        subprocess.CalledProcessError: If OpenSSL fails.
    """
    private_key = _key_path(key_directory, label, ".pk8")
    certificate = _key_path(key_directory, label, ".x509.pem")
    for path in (private_key, certificate):
        if path.exists():
            raise FileExistsError(path)

    private_key.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=private_key.parent,
        prefix=f".{private_key.name}.",
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        pem_key = temporary / "private.pem"
        pkcs8_key = temporary / "private.pk8"
        _openssl(
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(pem_key),
        )
        _openssl(
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

    certificate.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=certificate.parent,
        prefix=f".{certificate.name}.",
    ) as temporary_directory:
        temporary_certificate = Path(temporary_directory) / "certificate.pem"
        _openssl(
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
        os.replace(temporary_certificate, certificate)


def _key_path(key_directory: Path, label: str, suffix: str) -> Path:
    """
    Resolve one key file while preventing directory traversal.

    Args:
        key_directory: Root beneath which AOSP key files are stored.
        label: Relative path of the key below the key directory.
        suffix: AOSP file suffix to append to the label.

    Returns:
        Absolute path to the requested file.

    Raises:
        ValueError: If the label is empty, absolute, or escapes the key
            directory.
    """
    if not label:
        raise ValueError("plaintext key label must not be empty")
    if Path(label).is_absolute():
        raise ValueError("plaintext key label must be relative")
    root = key_directory.resolve()
    path = (root / f"{label}{suffix}").resolve()
    if not path.is_relative_to(root):
        raise ValueError("plaintext key label escapes the key directory")
    return path


def _openssl(*arguments: str) -> None:
    """
    Run OpenSSL with captured output and checked status.

    Raises:
        subprocess.CalledProcessError: If OpenSSL exits unsuccessfully.
    """
    subprocess.run(
        ["openssl", *arguments],
        check=True,
        capture_output=True,
    )


class InconsistentKeyStateError(RuntimeError):
    """
    A key and its certificate are not both present.
    """


def provision_certified_keys(
    key_directory: Path,
    labels: Iterable[str],
    subject: str,
) -> None:
    """
    Generate an RSA 2048 key and its self-signed certificate under every
    label that has neither, in label order.

    Every label is checked before anything is generated, so an
    inconsistent key leaves the key directory untouched.

    Args:
        key_directory: Key directory to provision.
        labels: Labels of the keys to provision.
        subject: Certificate subject of every key.

    Raises:
        InconsistentKeyStateError: If a key exists without its
            certificate, or a certificate without its key.
        FileExistsError: If a file a new key needs is already there.
        ValueError: If a label escapes the key directory.
        subprocess.CalledProcessError: If OpenSSL fails.
    """
    missing: list[str] = []
    for label in sorted(set(labels)):
        key_exists = _key_path(key_directory, label, ".pk8").is_file()
        certificate_exists = _key_path(
            key_directory,
            label,
            ".x509.pem",
        ).is_file()
        if certificate_exists and not key_exists:
            raise InconsistentKeyStateError(
                f"certificate exists without private key: {label}",
            )
        if key_exists and not certificate_exists:
            raise InconsistentKeyStateError(
                f"key {label} exists without its certificate. Restore the "
                "certificate from a backup, or delete the key if it was "
                "never used",
            )
        if not key_exists:
            missing.append(label)
    for label in missing:
        generate_certified_key(key_directory, label, subject)
