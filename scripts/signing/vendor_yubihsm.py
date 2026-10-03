#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
YubiHSM attestation, wrapped-key backup and audit-log access.

Importing this module does not require the yubihsm SDK.
"""

from __future__ import annotations

import base64
import binascii
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar

from .vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)

if TYPE_CHECKING:
    from yubihsm.core import AuthSession, LogEntry


_RECENT_LOG_BYTES = 1 << 20


class _Closable(Protocol):
    def close(self) -> None: ...


S = TypeVar("S", bound=_Closable)
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class YubiHsmConfig:
    """
    Connection and authentication settings for a YubiHSM session.
    """

    connector_url: str
    auth_key: str
    password: str = field(repr=False)
    attestation_id: str = "0"
    wrap_id: str = "0x0010"


def restart_connector() -> None:
    """
    Restart the local yubihsm-connector this process manages, unless
    NEVER_START_YUBIHSM_CONNECTOR=y leaves the connector to the user.
    The caller sets YUBIHSM_CONNECTOR_PIDFILE.

    Raises:
        RuntimeError: If the existing connector cannot be stopped before
            restarting it.
        OSError: If the connector binary cannot be executed.
    """
    if os.environ.get("NEVER_START_YUBIHSM_CONNECTOR") == "y":
        return
    pid_file = os.environ["YUBIHSM_CONNECTOR_PIDFILE"]
    connector = YubiHsmConnector(
        YubiHsmConnectorConfig(
            connector_url=os.environ.get(
                "YUBIHSM_CONNECTOR",
                "http://127.0.0.1:12345",
            ),
            pid_file=Path(pid_file),
            binary=os.environ.get("YUBIHSM_CONNECTOR_BIN", "yubihsm-connector"),
        ),
    )
    connector.restart()


def _run_with_session(
    session_factory: Callable[[], S],
    operation: Callable[[S], T],
) -> T:
    """
    Open a session, run an operation, and retry once after a connector
    restart if either step fails with a connector-level connection error.

    Only retries when ``YUBIHSM_CONNECTOR_PIDFILE`` is set in the
    environment (meaning this process owns the connector's lifecycle),
    and only on the SDK's connection-error type. The SDK's HTTP backend
    raises that one exception for every kind of connector failure, so
    this always pauses briefly first, to let a still-dying connector
    process settle before restarting it.

    Args:
        session_factory: Callable returning a new, authenticated session,
            called again on retry.
        operation: Callable performing one or more calls against the
            session it is given.

    Returns:
        The operation's result, from the first attempt or the retry.

    Raises:
        Exception: Whatever session_factory or operation raise, if it is
            not a connection error, or if YUBIHSM_CONNECTOR_PIDFILE is
            unset, or if the retry itself fails.
    """
    from yubihsm.exceptions import YubiHsmConnectionError

    def attempt() -> T:
        session = session_factory()
        try:
            return operation(session)
        finally:
            session.close()

    try:
        return attempt()
    except YubiHsmConnectionError:
        if not os.environ.get("YUBIHSM_CONNECTOR_PIDFILE"):
            raise
        time.sleep(2)
        restart_connector()
        return attempt()


def decode_wrapped_key_backup(data: bytes, source: str) -> bytes:
    """
    Decode the contents of a *-asymmetric-key.yhw backup into the raw
    wrapped blob the SDK expects.

    A .yhw file holds the blob base64-encoded, in yubihsm-shell's own
    get-wrapped/put-wrapped format, so a backup written by either tool
    restores through the other.

    Args:
        data: Backup file contents.
        source: Where data came from, for the error message.

    Returns:
        The decoded wrapped-key blob.

    Raises:
        ValueError: If data is not valid base64.
    """
    try:
        return base64.b64decode(data.strip(), validate=True)
    except binascii.Error as error:
        raise ValueError(
            f"{source} is not a base64 wrapped-key backup",
        ) from error


def attest_key(config: YubiHsmConfig, key_id: str) -> bytes:
    """
    Return a certificate attesting a key's on-device origin, signed by
    the config's attestation key.

    Args:
        config: Connector URL, authentication key, password, and
            attestation key.
        key_id: The key's ID, e.g. "0x2000".

    Returns:
        The PEM-encoded attestation certificate.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or operation
            fails, e.g. because the key does not exist.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from yubihsm.objects import AsymmetricKey

    object_id = int(key_id, 16)
    attesting_key_id = int(config.attestation_id, 16)

    def operation(session: AuthSession) -> bytes:
        certificate = AsymmetricKey(session, object_id).attest(attesting_key_id)
        return certificate.public_bytes(Encoding.PEM)

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


def export_wrapped_key(config: YubiHsmConfig, key_id: str) -> bytes:
    """
    Return a key's private material wrapped under the config's wrap key.

    Args:
        config: Connector URL, authentication key, password, and wrap key.
        key_id: The key's ID, e.g. "0x2000".

    Returns:
        The wrap-encrypted key blob.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or operation
            fails, e.g. because the key is not marked exportable.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.objects import AsymmetricKey, WrapKey

    wrap_id = int(config.wrap_id, 16)
    object_id = int(key_id, 16)

    def operation(session: AuthSession) -> bytes:
        wrap_key = WrapKey(session, wrap_id)
        return wrap_key.export_wrapped(AsymmetricKey(session, object_id))

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


def import_wrapped_key(
    config: YubiHsmConfig,
    key_id: str,
    wrapped: bytes,
) -> None:
    """
    Restore a key from a blob export_wrapped_key() returned.

    The wrap envelope carries its own object ID, type, domain, and
    capabilities from when it was exported, which IMPORT_WRAPPED cannot
    override. Only the restored object's ID is verified against key_id,
    as a sanity check this is the blob the caller expected to restore, and
    an object restored under another ID is deleted again.

    Args:
        config: Connector URL, authentication key, password, and wrap key.
        key_id: The ID the restored key must have, e.g. "0x2000".
        wrapped: Wrap-encrypted key blob.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or operation
            fails, e.g. because an object with this ID already exists.
        ValueError: If the restored object's ID is not key_id.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.objects import WrapKey

    wrap_id = int(config.wrap_id, 16)
    expected_id = int(key_id, 16)

    def operation(session: AuthSession) -> None:
        restored = WrapKey(session, wrap_id).import_wrapped(wrapped)
        if restored.id != expected_id:
            restored.delete()
            raise ValueError(
                f"restored object id {restored.id:#06x} does not "
                f"match expected key id {key_id}",
            )

    _run_with_session(lambda: connect_yubihsm_session(config), operation)


def connect_yubihsm_session(config: YubiHsmConfig) -> AuthSession:
    """
    Open a python-yubihsm session, for any device capability.

    Args:
        config: Connector URL, authentication key, and password.

    Returns:
        An open, derived-credential python-yubihsm session.
    """
    from yubihsm.core import YubiHsm

    hsm = YubiHsm.connect(config.connector_url)
    return hsm.create_session_derived(int(config.auth_key, 16), config.password)


def format_audit_log_entry(entry: LogEntry) -> str:
    """
    Render one audit log entry in the on-disk log-file format.

    The layout is the one ``vendor.yubihsm.audit.logs.py`` writes, so
    both append to the same log files.

    Args:
        entry: Audit log entry to render.

    Returns:
        The one-line, human-readable rendering of the entry.
    """
    return (
        f"{entry.number:>{5}} "
        f"cmd: {entry.command:#0{4}x} "
        f"len: {entry.length:>{5}} "
        f"sKey: {entry.session_key:#0{6}x} "
        f"tKey: {entry.target_key:#0{6}x} "
        f"2Key: {entry.second_key:#0{6}x} "
        f"res: {entry.result:#0{4}x} "
        f"tick: {entry.tick:>{10}} "
        f"hash: {entry.digest.hex()}"
    )


def _recent_log_lines(log_file: Path) -> set[str]:
    """
    Return the lines at the end of an audit log file, more than enough to
    hold every entry the device can still return.

    Args:
        log_file: Audit log file.

    Returns:
        The file's last lines, or none when the file does not exist.
    """
    try:
        with log_file.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - _RECENT_LOG_BYTES))
            tail = handle.read()
    except FileNotFoundError:
        return set()
    lines = tail.decode(errors="replace").splitlines()
    return set(lines[1:] if size > _RECENT_LOG_BYTES else lines)


def extract_and_save_audit_log(
    config: YubiHsmConfig,
    log_file: Path,
    comment: str | None = None,
) -> tuple[LogEntry, ...]:
    """
    Append a device's new audit log entries and a comment line to a log
    file, reading and acknowledging them over one session.

    Nothing is written when there are no entries and no comment, a comment
    line is always written otherwise, and only entries appended to the log
    file are acknowledged to the device. An entry whose line log_file holds
    already, left on the device by an acknowledgement that failed, is not
    written again, and the file is synced before the acknowledgement.

    Args:
        config: Connector URL, authentication key, and password.
        log_file: Path to append the comment line and entries to.
        comment: Optional single-line comment recorded with the entries.

    Returns:
        The audit log entries appended to log_file.

    Raises:
        OSError: If log_file's directory cannot be created or written.
    """
    clean_comment = (
        "" if comment is None else comment.replace("\n", "").replace("\r", "")
    )
    session = connect_yubihsm_session(config)
    try:
        read = tuple(session.get_log_entries().entries)
        if not read and not clean_comment:
            return ()

        log_file.parent.mkdir(parents=True, exist_ok=True)
        written = _recent_log_lines(log_file)
        entries = tuple(
            entry
            for entry in read
            if format_audit_log_entry(entry) not in written
        )
        with log_file.open("a") as handle:
            handle.write(f"# {round(time.time() * 1000)} {clean_comment}\n")
            for entry in entries:
                handle.write(format_audit_log_entry(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        if read:
            session.set_log_index(read[-1].number)
    finally:
        session.close()
    return entries
