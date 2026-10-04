#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Adapter between avbtool's signing-helper protocol and signing backends.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from .backend import KeyLabelResolver, Signer
from .configuration import EnvironmentPin, Pkcs11BackendConfiguration
from .models import KeyReference, SignRequest
from .pkcs11 import Pkcs11Backend

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


def key_name_from_path(key_path: Path, environment: Mapping[str, str]) -> str:
    """
    Derive the legacy PKCS#11 key name from an avbtool key path.

    Args:
        key_path: Public-key path supplied to avbtool through ``--key``.
        environment: Variables containing the optional ``KEY_DIR`` prefix.

    Returns:
        Key name with the configured directory prefix and ``.pem`` suffix
        removed.
    """
    rendered = str(key_path)
    key_directory = environment.get("KEY_DIR")
    if key_directory and rendered.startswith(key_directory):
        rendered = rendered[len(key_directory) :]
    return rendered.removesuffix(".pem")


def key_reference_from_path(
    signer: Signer,
    key_path: Path,
    environment: Mapping[str, str],
) -> KeyReference:
    """
    Resolve an external helper key path using legacy ID-or-label behavior.

    Args:
        signer: Backend that may support private-key label resolution.
        key_path: Public-key path supplied by the calling signing tool.
        environment: Variables controlling key mapping and explicit IDs.

    Returns:
        Backend-neutral key reference containing the resolved object ID.

    Raises:
        KeyError: If label lookup is requested but no private key has the
            label.
        ValueError: If label lookup is ambiguous.
    """
    label = key_name_from_path(key_path, environment)
    key_id = environment.get("KEY_ID")
    find_by_id = environment.get("FIND_KEYS_BY_ID", "n") == "y"
    uri_uses_id = (
        environment.get("OPENSSL_PKCS11_URI_USES_HEX_KEY_ID", "n") == "y"
    )
    lookup_label = label if key_id is None else key_id
    if (
        not find_by_id
        and not uri_uses_id
        and isinstance(signer, KeyLabelResolver)
    ):
        key_id = signer.key_id_for_label(lookup_label)
    elif key_id is None:
        key_id = label
    return KeyReference(key_id, label)


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


def sign_avb_input(
    signer: Signer,
    algorithm: str,
    reference: KeyReference,
    data: bytes,
) -> bytes:
    """
    Remove AVB's precomputed RSA padding and sign its DigestInfo value.

    Args:
        signer: Backend used for the raw RSA PKCS#1 v1.5 operation.
        algorithm: Algorithm name supplied by avbtool.
        reference: Token key to sign with.
        data: Padded signing input supplied by avbtool on standard input.

    Returns:
        Raw RSA signature produced by the selected backend.

    Raises:
        ValueError: If the AVB algorithm is unsupported or input is too short.
    """
    digest_info, _ = avb_input_digest(algorithm, data)
    return signer.sign(SignRequest(reference, digest_info, "rsa-pkcs"))


def pkcs11_signer_from_environment() -> Pkcs11Backend:
    """
    Construct the generic PKCS#11 signer from the process environment.

    Returns:
        Configured generic PKCS#11 signing backend.

    Raises:
        KeyError: If ``PKCS11_MODULE`` is absent.
    """
    values = os.environ
    use_so_pin = values.get("SIGNING_USES_SO_PIN", "n") == "y"
    pin_variable = "PKCS11_SO_PIN" if use_so_pin else "PKCS11_PIN"
    pin_source = (
        EnvironmentPin(pin_variable) if values.get(pin_variable) else None
    )
    discovery_pin_source = (
        EnvironmentPin("PKCS11_PIN")
        if use_so_pin and values.get("PKCS11_PIN")
        else None
    )
    configuration = Pkcs11BackendConfiguration(
        module=Path(values["PKCS11_MODULE"]),
        pin_source=pin_source,
        discovery_pin_source=discovery_pin_source,
        token_label=values.get("PKCS11_TOKEN_LABEL"),
        slot=values.get("PKCS11_SLOT"),
        tool=values.get("PKCS11_TOOL_BIN", "pkcs11-tool"),
        use_so_pin=use_so_pin,
        list_requires_no_pin=(values.get("LIST_REQUIRES_NO_PIN", "n") == "y"),
        preload_module=values.get("PKCS11_VENDOR") == "yubihsm",
        environment=values,
    )
    return configuration.create_backend()
