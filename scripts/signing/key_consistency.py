#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Public-key consistency checks for externally invoked signing helpers.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .models import KeyReference
from .pkcs11 import Pkcs11Backend


def public_key_der_from_file(
    public_key: Path,
    openssl: str = "openssl",
) -> bytes:
    """
    Normalize a PEM public key to DER SubjectPublicKeyInfo.

    Args:
        public_key: PEM public-key file supplied by release tooling.
        openssl: OpenSSL executable name or path.

    Returns:
        DER-encoded SubjectPublicKeyInfo bytes.

    Raises:
        OSError: If OpenSSL cannot be executed.
        subprocess.CalledProcessError: If the key cannot be parsed.
    """
    return subprocess.run(
        (
            openssl,
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
        ),
        check=True,
        capture_output=True,
    ).stdout


def require_matching_public_key(
    store: Pkcs11Backend,
    reference: KeyReference,
    public_key: Path,
    openssl: str = "openssl",
) -> bytes:
    """
    Require a supplied public key to match the selected backend object.

    Args:
        store: Backend used to export the selected object's public component.
        reference: Resolved backend key identity.
        public_key: PEM public-key file supplied by release tooling.
        openssl: OpenSSL executable name or path.

    Returns:
        Normalized DER public key from the supplied file.

    Raises:
        ValueError: If the supplied and backend public keys differ.
        OSError: If the key file or OpenSSL cannot be accessed.
        subprocess.CalledProcessError: If key parsing or export fails.
    """
    exported = store.export_public_key(reference)
    supplied = public_key_der_from_file(public_key, openssl)
    if supplied != exported:
        raise ValueError(
            "supplied public key does not match the selected PKCS#11 key",
        )
    return supplied


def require_signature_from_public_key(
    public_key: Path,
    digest_info: bytes,
    signature: bytes,
    openssl: str = "openssl",
) -> None:
    """
    Require an RSA PKCS#1 v1.5 signature over a DigestInfo to verify under
    a supplied public key.

    Args:
        public_key: PEM public-key file supplied by release tooling.
        digest_info: DER DigestInfo the signature must carry.
        signature: Raw RSA signature.
        openssl: OpenSSL executable name or path.

    Returns:
        None.

    Raises:
        ValueError: If the key is not RSA or the signature does not carry
            digest_info under it.
        OSError: If the key file or OpenSSL cannot be accessed.
        subprocess.CalledProcessError: If the key cannot be parsed.
    """
    key = serialization.load_der_public_key(
        public_key_der_from_file(public_key, openssl),
    )
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"{public_key} is not an RSA public key")
    try:
        recovered = key.recover_data_from_signature(
            signature,
            padding.PKCS1v15(),
            None,
        )
    except InvalidSignature:
        recovered = None
    if recovered != digest_info:
        raise ValueError(
            f"signature does not verify under the supplied public key "
            f"{public_key}",
        )


_HASHES: dict[str, type[hashes.SHA256 | hashes.SHA384 | hashes.SHA512]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def require_signature_from_certificate(
    certificate: Path,
    data: bytes,
    signature: bytes,
    hash_name: str,
) -> None:
    """
    Require an RSA PKCS#1 v1.5 signature over data to verify under a
    certificate's public key.

    Args:
        certificate: PEM certificate the signed artifact will carry.
        data: The signed data, before hashing.
        signature: Raw RSA signature.
        hash_name: "sha256", "sha384" or "sha512".

    Returns:
        None.

    Raises:
        ValueError: If the certificate's key is not RSA or the signature
            does not verify under it.
        OSError: If the certificate cannot be read.
    """
    key = x509.load_pem_x509_certificate(certificate.read_bytes()).public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"{certificate} does not hold an RSA public key")
    try:
        key.verify(signature, data, padding.PKCS1v15(), _HASHES[hash_name]())
    except InvalidSignature as error:
        raise ValueError(
            f"signature does not verify under the certificate {certificate}",
        ) from error
