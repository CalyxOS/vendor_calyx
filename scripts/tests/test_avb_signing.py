#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from signing.avb_signing import key_reference_from_path, sign_avb_input
from software_rsa import (
    LabelledSoftwareSigner,
    SoftwareSigner,
    rsa_key,
    verifies,
)

SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
SHA512_PREFIX = bytes.fromhex("3051300d060960864801650304020305000440")
AVB_ALGORITHMS = (
    ("SHA256_RSA2048", 2048, 205, SHA256_PREFIX, hashes.SHA256()),
    ("SHA256_RSA4096", 4096, 461, SHA256_PREFIX, hashes.SHA256()),
    ("SHA256_RSA8192", 8192, 973, SHA256_PREFIX, hashes.SHA256()),
    ("SHA512_RSA2048", 2048, 173, SHA512_PREFIX, hashes.SHA512()),
    ("SHA512_RSA4096", 4096, 429, SHA512_PREFIX, hashes.SHA512()),
    ("SHA512_RSA8192", 8192, 941, SHA512_PREFIX, hashes.SHA512()),
)
DIGEST = hashlib.sha256(b"vbmeta").digest()


def _sign_avb_input(
    signer: SoftwareSigner,
    algorithm: str,
    key_path: Path,
    data: bytes,
    environment: Mapping[str, str],
) -> bytes:
    return sign_avb_input(
        signer,
        algorithm,
        key_reference_from_path(signer, key_path, environment),
        data,
    )


def avb_input(padding_size: int, prefix: bytes, digest: bytes) -> bytes:
    """Build one valid avbtool RSA signing input."""
    return (
        b"\x00\x01" + b"\xff" * (padding_size - 3) + b"\x00" + prefix + digest
    )


def sign_sha256(
    signer: SoftwareSigner,
    key_path: str,
    environment: Mapping[str, str],
) -> bytes:
    return _sign_avb_input(
        signer,
        "SHA256_RSA2048",
        Path(key_path),
        avb_input(205, SHA256_PREFIX, DIGEST),
        environment,
    )


def test_avb_signature_uses_the_key_named_by_its_path() -> None:
    signer = SoftwareSigner({"0x2000": rsa_key("a"), "0x4321": rsa_key("b")})

    signature = sign_sha256(
        signer,
        "keys/0x2000.pem",
        {"KEY_DIR": "keys/", "FIND_KEYS_BY_ID": "y"},
    )

    assert verifies(rsa_key("a"), signature, DIGEST)
    assert not verifies(rsa_key("b"), signature, DIGEST)


def test_avb_signature_uses_the_key_id_override() -> None:
    signer = SoftwareSigner({"0x2000": rsa_key("a"), "0x4321": rsa_key("b")})

    signature = sign_sha256(
        signer,
        "keys/0x2000.pem",
        {"KEY_DIR": "keys/", "KEY_ID": "0x4321"},
    )

    assert verifies(rsa_key("b"), signature, DIGEST)
    assert not verifies(rsa_key("a"), signature, DIGEST)


@pytest.mark.parametrize(
    ("environment", "expected", "other"),
    (
        ({"KEY_DIR": "keys/"}, "b", "c"),
        ({}, "c", "b"),
        ({"KEY_DIR": "keys/", "KEY_ID": "shared-signing-key"}, "a", "b"),
    ),
)
def test_avb_signature_uses_the_key_with_the_derived_label(
    environment: dict[str, str],
    expected: str,
    other: str,
) -> None:
    signer = LabelledSoftwareSigner(
        {"2000": rsa_key("a"), "2100": rsa_key("b"), "2200": rsa_key("c")},
        {
            "shared-signing-key": "2000",
            "release": "2100",
            "keys/release": "2200",
        },
    )

    signature = sign_sha256(signer, "keys/release.pem", environment)

    assert verifies(rsa_key(expected), signature, DIGEST)
    assert not verifies(rsa_key(other), signature, DIGEST)


def test_avb_signature_uses_the_explicit_id_in_hex_uri_mode() -> None:
    signer = LabelledSoftwareSigner(
        {"2000": rsa_key("a"), "2100": rsa_key("b")},
        {"release": "2100"},
    )

    signature = sign_sha256(
        signer,
        "keys/release.pem",
        {
            "KEY_DIR": "keys/",
            "KEY_ID": "0x2000",
            "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
        },
    )

    assert verifies(rsa_key("a"), signature, DIGEST)
    assert not verifies(rsa_key("b"), signature, DIGEST)


def test_avb_adapter_rejects_unsupported_algorithm() -> None:
    with pytest.raises(
        ValueError,
        match="Unsupported/untested algorithm: SHA1_RSA2048",
    ):
        _sign_avb_input(
            SoftwareSigner({}),
            "SHA1_RSA2048",
            Path("keys/test.pem"),
            b"input",
            {},
        )


def test_avb_adapter_rejects_truncated_input() -> None:
    with pytest.raises(ValueError, match="must be exactly 256 bytes"):
        _sign_avb_input(
            SoftwareSigner({}),
            "SHA256_RSA2048",
            Path("keys/test.pem"),
            b"\x00" * 205,
            {},
        )


@pytest.mark.parametrize(
    ("algorithm", "bits", "padding_size", "prefix", "hash_algorithm"),
    AVB_ALGORITHMS,
)
def test_avb_signature_verifies_for_every_supported_algorithm(
    algorithm: str,
    bits: int,
    padding_size: int,
    prefix: bytes,
    hash_algorithm: hashes.HashAlgorithm,
) -> None:
    key = rsa_key("sized", bits)
    digest = hashlib.new(hash_algorithm.name, b"vbmeta").digest()

    signature = _sign_avb_input(
        SoftwareSigner({"0x2000": key}),
        algorithm,
        Path("keys/0x2000.pem"),
        avb_input(padding_size, prefix, digest),
        {"KEY_DIR": "keys/", "FIND_KEYS_BY_ID": "y"},
    )

    assert len(signature) == bits // 8
    assert verifies(key, signature, digest, hash_algorithm)


@pytest.mark.parametrize(
    ("offset", "replacement", "message"),
    (
        (0, 1, "invalid PKCS#1 header"),
        (2, 0, "invalid PKCS#1 padding"),
        (204, 1, "no PKCS#1 separator"),
        (205, 0, "invalid DigestInfo prefix"),
    ),
)
def test_avb_adapter_rejects_malformed_encoding(
    offset: int,
    replacement: int,
    message: str,
) -> None:
    data = bytearray(avb_input(205, SHA256_PREFIX, DIGEST))
    data[offset] = replacement

    with pytest.raises(ValueError, match=message):
        _sign_avb_input(
            SoftwareSigner({"0x2000": rsa_key("a")}),
            "SHA256_RSA2048",
            Path("keys/0x2000.pem"),
            bytes(data),
            {"KEY_DIR": "keys/", "FIND_KEYS_BY_ID": "y"},
        )
