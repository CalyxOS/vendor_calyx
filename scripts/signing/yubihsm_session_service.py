#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
SigningServer handler that holds one authenticated YubiHSM session for a
whole release.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from .signing_server import Message, request
from .vendor_yubihsm import (
    YubiHsmConfig,
    connect_yubihsm_session,
)

if TYPE_CHECKING:
    from yubihsm.core import AuthSession

T = TypeVar("T")

_DIGEST_HASHES: dict[int, Callable[[], hashes.HashAlgorithm]] = {
    32: hashes.SHA256,
    48: hashes.SHA384,
    64: hashes.SHA512,
}


class YubiHsmSessionService:
    """
    Handle YubiHSM operations over one session, opened on first use.
    """

    def __init__(self, config: YubiHsmConfig) -> None:
        """
        Prepare a session service that opens its session on first use.

        Args:
            config: Connector URL, authentication key and password.
        """
        self._config = config
        self._session: AuthSession | None = None
        self._public_keys: dict[int, rsa.RSAPublicKey] = {}

    def handle(self, request: Message) -> Message:
        if request["op"] == "yubihsm_sign_pkcs1":
            return self._sign(request)
        return {"status": "unavailable"}

    def close(self) -> None:
        if self._session is not None:
            session, self._session = self._session, None
            try:
                session.close()
            except Exception:
                pass

    def with_session(self, operation: Callable[[AuthSession], T]) -> T:
        for attempt in (1, 2):
            if self._session is None:
                self._session = connect_yubihsm_session(self._config)
            try:
                return operation(self._session)
            except Exception:
                self.close()
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def _sign(self, request: Message) -> Message:
        from yubihsm.objects import AsymmetricKey

        key_id = int(request["key_id"])
        digest = base64.b64decode(request["digest"])
        try:
            hash_algorithm = _DIGEST_HASHES[len(digest)]()
        except KeyError as error:
            raise ValueError(
                f"unsupported digest length {len(digest)}",
            ) from error

        signature = self.with_session(
            lambda session: AsymmetricKey(session, key_id).sign_pkcs1v1_5(
                digest,
                cast(hashes.HashAlgorithm, Prehashed(hash_algorithm)),
            ),
        )
        if key_id not in self._public_keys:
            public_key = self.with_session(
                lambda session: AsymmetricKey(session, key_id).get_public_key(),
            )
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError(f"key {key_id:#06x} is not an RSA key")
            self._public_keys[key_id] = public_key
        self._public_keys[key_id].verify(
            signature,
            digest,
            padding.PKCS1v15(),
            Prehashed(hash_algorithm),
        )
        return {
            "status": "ok",
            "signature": base64.b64encode(signature).decode(),
        }


def sign_digest_through_server(
    socket_path: Path,
    key_name: str,
    digest: bytes,
) -> bytes | None:
    """
    Ask a SigningServer's YubiHsmSessionService for a PKCS#1 v1.5
    signature over a digest.

    Args:
        socket_path: The server's Unix socket.
        key_name: The key's name, a hexadecimal YubiHSM object ID with or
            without "0x".
        digest: SHA-256, SHA-384 or SHA-512 digest to sign.

    Returns:
        The signature, or None if key_name is not an object ID or the
        server could not produce a signature.
    """
    try:
        key_id = int(key_name.removeprefix("0x"), 16)
    except ValueError:
        return None
    response = request(
        socket_path,
        "yubihsm_sign_pkcs1",
        key_id=key_id,
        digest=base64.b64encode(digest).decode(),
    )
    if response is None:
        return None
    return base64.b64decode(response["signature"])
