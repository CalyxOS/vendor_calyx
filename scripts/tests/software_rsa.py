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
from signing.models import SignRequest

FIXTURE_KEYS = Path(__file__).parent / "fixtures" / "rsa"


@functools.cache
def rsa_key(name: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    """
    Return one RSA key per name, generated once per process, or read
    from fixtures/rsa/<name>-<bits>.pem when the tests ship one for a
    size that is slow to generate.

    Args:
        name: Arbitrary name distinguishing independent keys.
        bits: RSA modulus size.

    Returns:
        RSA private key.
    """
    fixture = FIXTURE_KEYS / f"{name}-{bits}.pem"
    if fixture.is_file():
        key = serialization.load_pem_private_key(
            fixture.read_bytes(),
            None,
            unsafe_skip_rsa_key_validation=True,
        )
        assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == bits
        return key
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def normalized_id(key_id: str) -> str:
    """
    Normalize a hexadecimal object ID with or without its ``0x`` prefix.

    Args:
        key_id: Hexadecimal object ID.

    Returns:
        Lowercase ID without a prefix.
    """
    return key_id.lower().removeprefix("0x")


class SoftwareSigner:
    """
    Raw RSA PKCS#1 v1.5 signer holding its keys in memory by object ID.
    """

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """
        Hold keys addressed by hexadecimal object ID.

        Args:
            keys: Private keys by object ID, with or without ``0x``.

        Returns:
            None.
        """
        self.keys = {normalized_id(key): value for key, value in keys.items()}

    def sign(self, request: SignRequest) -> bytes:
        """
        Apply raw RSA PKCS#1 v1.5 type 1 padding to the request data.

        Args:
            request: Key reference and DigestInfo to sign.

        Returns:
            Raw RSA signature.

        Raises:
            KeyError: If no key has the requested object ID.
            ValueError: If the mechanism is not ``rsa-pkcs``.
        """
        if request.mechanism != "rsa-pkcs":
            raise ValueError(f"unsupported mechanism: {request.mechanism}")
        key = self.keys[normalized_id(request.key.key_id)]
        size = (key.key_size + 7) // 8
        block = (
            b"\x00\x01"
            + b"\xff" * (size - 3 - len(request.data))
            + b"\x00"
            + request.data
        )
        numbers = key.private_numbers()
        message = int.from_bytes(block, "big")
        by_p = pow(message, numbers.dmp1, numbers.p)
        by_q = pow(message, numbers.dmq1, numbers.q)
        value = by_q + numbers.q * (numbers.iqmp * (by_p - by_q) % numbers.p)
        return value.to_bytes(size, "big")


class LabelledSoftwareSigner(SoftwareSigner):
    """
    Software signer that also resolves private-key labels to object IDs.
    """

    def __init__(
        self,
        keys: dict[str, rsa.RSAPrivateKey],
        labels: dict[str, str],
    ) -> None:
        """
        Hold keys by object ID and a label-to-ID table.

        Args:
            keys: Private keys by object ID.
            labels: Object ID for each private-key label.

        Returns:
            None.
        """
        super().__init__(keys)
        self.labels = labels

    def key_id_for_label(self, label: str) -> str:
        """
        Resolve one private-key label.

        Args:
            label: Private-key label.

        Returns:
            Object ID without a prefix.

        Raises:
            KeyError: If no key has the label.
        """
        try:
            return normalized_id(self.labels[label])
        except KeyError as error:
            raise KeyError(f"label not found: {label}") from error


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
