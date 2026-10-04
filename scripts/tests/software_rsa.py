#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import functools
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from signing.avb_signing import SHA256_DIGEST_INFO_PREFIX


@functools.cache
def rsa_key(name: str) -> rsa.RSAPrivateKey:
    """
    Return one RSA-2048 key per name, generated once per process.

    Args:
        name: Arbitrary name distinguishing independent keys.

    Returns:
        RSA private key.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def verifies(
    key: rsa.RSAPrivateKey | rsa.RSAPublicKey,
    signature: bytes,
    digest: bytes,
    algorithm: hashes.HashAlgorithm | None = None,
) -> bool:
    """
    Check an RSA PKCS#1 v1.5 signature over a precomputed digest.

    Args:
        key: Public key that should verify the signature, or the private
            key whose public half should.
        signature: Signature to check.
        digest: Precomputed message digest.
        algorithm: Hash that produced the digest, SHA-256 by default.

    Returns:
        Whether the signature verifies.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    try:
        key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            Prehashed(algorithm or hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    return True


def avb_input(
    digest: bytes,
    padding_size: int = 205,
    prefix: bytes = SHA256_DIGEST_INFO_PREFIX,
) -> bytes:
    """
    Build the PKCS#1 v1.5 block avbtool hands its signing helper.

    Args:
        digest: Message digest at the end of the block.
        padding_size: Bytes before the DigestInfo prefix, 205 for
            SHA256_RSA2048.
        prefix: DigestInfo prefix of the digest's hash.

    Returns:
        Signing input for the helper's stdin.
    """
    return (
        b"\x00\x01" + b"\xff" * (padding_size - 3) + b"\x00" + prefix + digest
    )


def der_public_key(path: Path) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from a DER SubjectPublicKeyInfo file.

    Args:
        path: File holding the DER public key.

    Returns:
        RSA public key.
    """
    key = serialization.load_der_public_key(path.read_bytes())
    assert isinstance(key, rsa.RSAPublicKey)
    return key
