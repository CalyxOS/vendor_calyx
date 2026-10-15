#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from signing.avb_signing import SHA256_DIGEST_INFO_PREFIX, avb_input_digest
from signing.signing_helpers import key_name_from_path
from software_rsa import avb_input

SHA512_PREFIX = bytes.fromhex("3051300d060960864801650304020305000440")
AVB_ALGORITHMS = (
    ("SHA256_RSA2048", 205, SHA256_DIGEST_INFO_PREFIX, "sha256"),
    ("SHA256_RSA4096", 461, SHA256_DIGEST_INFO_PREFIX, "sha256"),
    ("SHA256_RSA8192", 973, SHA256_DIGEST_INFO_PREFIX, "sha256"),
    ("SHA512_RSA2048", 173, SHA512_PREFIX, "sha512"),
    ("SHA512_RSA4096", 429, SHA512_PREFIX, "sha512"),
    ("SHA512_RSA8192", 941, SHA512_PREFIX, "sha512"),
)
DIGEST = hashlib.sha256(b"vbmeta").digest()


def test_avb_adapter_rejects_unsupported_algorithm() -> None:
    with pytest.raises(
        ValueError,
        match="Unsupported/untested algorithm: SHA1_RSA2048",
    ):
        avb_input_digest("SHA1_RSA2048", b"input")


def test_avb_adapter_rejects_truncated_input() -> None:
    with pytest.raises(ValueError, match="must be exactly 256 bytes"):
        avb_input_digest("SHA256_RSA2048", b"\x00" * 205)


@pytest.mark.parametrize(
    ("algorithm", "padding_size", "prefix", "hash_name"),
    AVB_ALGORITHMS,
)
def test_avb_input_digest_for_every_supported_algorithm(
    algorithm: str,
    padding_size: int,
    prefix: bytes,
    hash_name: str,
) -> None:
    digest = hashlib.new(hash_name, b"vbmeta").digest()

    assert avb_input_digest(
        algorithm,
        avb_input(digest, padding_size, prefix),
    ) == (prefix + digest, digest)


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
    data = bytearray(avb_input(DIGEST))
    data[offset] = replacement

    with pytest.raises(ValueError, match=message):
        avb_input_digest("SHA256_RSA2048", bytes(data))


@pytest.mark.parametrize("key_dir", ("", "keys/"))
def test_key_name_drops_the_pem_suffix_whatever_key_dir_is(
    key_dir: str,
) -> None:
    assert (
        key_name_from_path(Path(f"{key_dir}0x2000.pem"), {"KEY_DIR": key_dir})
        == "0x2000"
    )
