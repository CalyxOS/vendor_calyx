#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Public-key consistency checks for externally invoked signing helpers.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .models import KeyReference
from .pkcs11 import Pkcs11Backend


def _load_public_key(public_key: Path) -> PublicKeyTypes:
    try:
        return serialization.load_pem_public_key(public_key.read_bytes())
    except (UnsupportedAlgorithm, ValueError) as error:
        raise ValueError(
            f"{public_key} holds no usable PEM public key ({error})",
        ) from error


def require_matching_public_key(
    store: Pkcs11Backend,
    reference: KeyReference,
    public_key: Path,
) -> None:
    """
    Require a supplied public key to match the selected backend object.

    Args:
        store: Backend used to export the selected object's public component.
        reference: Resolved backend key identity.
        public_key: PEM public-key file supplied by release tooling.

    Returns:
        None.

    Raises:
        ValueError: If the supplied and backend public keys differ, or the
            file holds no PEM public key.
        OSError: If the key file cannot be read.
        subprocess.CalledProcessError: If the key export fails.
    """
    exported = store.export_public_key(reference)
    supplied = _load_public_key(public_key).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if supplied != exported:
        raise ValueError(
            "supplied public key does not match the selected PKCS#11 key",
        )


def require_signature_from_public_key(
    public_key: Path,
    digest_info: bytes,
    signature: bytes,
) -> None:
    """
    Require an RSA PKCS#1 v1.5 signature over a DigestInfo to verify under
    a supplied public key.

    Args:
        public_key: PEM public-key file supplied by release tooling.
        digest_info: DER DigestInfo the signature must carry.
        signature: Raw RSA signature.

    Returns:
        None.

    Raises:
        ValueError: If the file holds no PEM RSA public key, or the
            signature does not carry digest_info under it.
        OSError: If the key file cannot be read.
    """
    key = _load_public_key(public_key)
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


_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
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
        hash_name: "sha1", "sha256", "sha384" or "sha512".

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
