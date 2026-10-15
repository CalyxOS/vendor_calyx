#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Take apart the signing input avbtool hands its signing helper.
"""

from __future__ import annotations

SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420",
)
_SHA512_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3051300d060960864801650304020305000440",
)
_AVB_ALGORITHMS = {
    "SHA256_RSA2048": (256, 205, SHA256_DIGEST_INFO_PREFIX, 32),
    "SHA256_RSA4096": (512, 461, SHA256_DIGEST_INFO_PREFIX, 32),
    "SHA256_RSA8192": (1024, 973, SHA256_DIGEST_INFO_PREFIX, 32),
    "SHA512_RSA2048": (256, 173, _SHA512_DIGEST_INFO_PREFIX, 64),
    "SHA512_RSA4096": (512, 429, _SHA512_DIGEST_INFO_PREFIX, 64),
    "SHA512_RSA8192": (1024, 941, _SHA512_DIGEST_INFO_PREFIX, 64),
}


def avb_input_digest(algorithm: str, data: bytes) -> tuple[bytes, bytes]:
    """
    Validate avbtool's padded signing input and take its digest apart.

    Args:
        algorithm: Algorithm name supplied by avbtool.
        data: Padded signing input supplied by avbtool on standard input.

    Returns:
        (DigestInfo, the bare digest inside it).

    Raises:
        ValueError: If the AVB algorithm is unsupported or the input is
            not a well-formed PKCS#1 v1.5 block for it.
    """
    try:
        total_size, padding_size, digest_info_prefix, digest_size = (
            _AVB_ALGORITHMS[algorithm]
        )
    except KeyError as error:
        raise ValueError(
            f"Unsupported/untested algorithm: {algorithm}",
        ) from error
    if len(data) != total_size:
        raise ValueError(
            f"AVB signing input must be exactly {total_size} bytes",
        )
    if data[:2] != b"\x00\x01":
        raise ValueError("AVB signing input has an invalid PKCS#1 header")
    if data[2 : padding_size - 1] != b"\xff" * (padding_size - 3):
        raise ValueError("AVB signing input has invalid PKCS#1 padding")
    if data[padding_size - 1] != 0:
        raise ValueError("AVB signing input has no PKCS#1 separator")
    digest_info = data[padding_size:]
    if not digest_info.startswith(digest_info_prefix):
        raise ValueError("AVB signing input has an invalid DigestInfo prefix")
    if len(digest_info) != len(digest_info_prefix) + digest_size:
        raise ValueError("AVB signing input has an invalid digest length")
    return digest_info, digest_info[len(digest_info_prefix) :]
