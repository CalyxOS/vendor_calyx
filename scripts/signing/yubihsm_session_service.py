#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
SigningServer service that holds one authenticated YubiHSM session for a
whole release.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from .signing_server import Message, SigningServer, request
from .vendor_yubihsm import (
    AuditLogNotAcknowledged,
    YubiHsmConfig,
    connect_yubihsm,
    save_audit_log,
    unacknowledged_audit_entries,
)

if TYPE_CHECKING:
    from yubihsm.core import AuthSession, YubiHsm

T = TypeVar("T")

_DIGEST_HASHES: dict[int, Callable[[], hashes.HashAlgorithm]] = {
    20: hashes.SHA1,
    32: hashes.SHA256,
    48: hashes.SHA384,
    64: hashes.SHA512,
}


class YubiHsmSessionService:
    """
    Handle YubiHSM operations over one session, opened on first use.
    """

    def __init__(
        self,
        config: YubiHsmConfig,
        *,
        audit_log_path: Path | None = None,
    ) -> None:
        """
        Prepare a session service that opens its session on first use.

        Args:
            config: Connector URL, authentication key and password.
            audit_log_path: The release's audit log, the only one
                "yubihsm_extract_audit_log" writes to.
        """
        self._config = config
        self._audit_log_path = audit_log_path
        self._hsm: YubiHsm | None = None
        self._session: AuthSession | None = None

    def close(self) -> None:
        session, self._session = self._session, None
        self._hsm = None
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    def with_session(self, operation: Callable[[AuthSession], T]) -> T:
        for attempt in (1, 2):
            if self._session is None:
                self._hsm, self._session = connect_yubihsm(self._config)
            try:
                return operation(self._session)
            except Exception:
                self.close()
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def _unacknowledged_entries(self) -> int:
        def operation(_: AuthSession) -> int:
            assert self._hsm is not None
            return unacknowledged_audit_entries(self._hsm)

        return self.with_session(operation)

    def sign(self, request: Message) -> Message:
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
        return {
            "status": "ok",
            "signature": base64.b64encode(signature).decode(),
        }

    def extract_audit_log(self, request: Message) -> Message:
        if (
            self._audit_log_path is None
            or Path(request["log_path"]) != self._audit_log_path
        ):
            return {"status": "unavailable"}
        try:
            save_audit_log(
                self._unacknowledged_entries,
                lambda: self.with_session(
                    lambda session: session.get_log_entries().entries,
                ),
                lambda number: self.with_session(
                    lambda session: session.set_log_index(number),
                ),
                self._audit_log_path,
                request["comment"],
            )
        except AuditLogNotAcknowledged as error:
            return {"status": "ok", "unacknowledged": str(error)}
        return {"status": "ok"}


def yubihsm_signing_server(
    config: YubiHsmConfig,
    socket_path: Path,
    *,
    audit_log_path: Path | None,
) -> SigningServer:
    """
    Build a SigningServer that signs and extracts the audit log over one
    YubiHSM session.

    Args:
        config: Connector URL, authentication key and password.
        socket_path: Where the server binds its socket.
        audit_log_path: The audit log the server extracts into.

    Returns:
        The server, not started yet.
    """
    service = YubiHsmSessionService(config, audit_log_path=audit_log_path)
    server = SigningServer(socket_path)
    server.add_service(
        {
            "yubihsm_sign_pkcs1": service.sign,
            "yubihsm_extract_audit_log": service.extract_audit_log,
        },
        service.close,
    )
    return server


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
        digest: SHA-1, SHA-256, SHA-384 or SHA-512 digest to sign.

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
