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
import re
import struct
import sys
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
    from yubihsm.defs import ALGORITHM, OBJECT


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


@dataclass(frozen=True, slots=True)
class StorageInfo:
    """
    Free/total record and page counts, as reported by the HSM itself.
    """

    total_records: int
    free_records: int
    total_pages: int
    free_pages: int
    page_size: int


def get_storage_info(config: YubiHsmConfig) -> StorageInfo:
    """
    Return the HSM's current record and page usage.

    Args:
        config: Connector URL, authentication key, and password.

    Returns:
        The parsed storage usage.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or command
            fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.defs import COMMAND

    def operation(session: AuthSession) -> StorageInfo:
        response = session.send_secure_cmd(COMMAND.GET_STORAGE_INFO)
        fields = struct.unpack(">5H", response)
        return StorageInfo(*fields)

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


def should_make_space_on_hsm(info: StorageInfo) -> bool:
    """
    Decide whether on-demand objects should be evicted before loading
    more.

    Args:
        info: Current storage usage, from get_storage_info().

    Returns:
        True if free records or free pages are running low.
    """
    return info.free_records < 5 or info.free_pages < 25


_DOMAIN_SEPARATORS = re.compile(r"[:,;|]")


def parse_domains(value: str) -> int:
    """
    Parse a domain-list string into the SDK's bitmask form.

    Matches yubihsm-shell's yh_string_to_domains(). "all" in any case
    means every domain, a "0x"-prefixed value is a literal bitmask, and
    anything else is a list of domain numbers from 1 to 16, separated by
    any of ``:``, ``,``, ``;`` and ``|``, each setting bit (number - 1).
    Empty segments are skipped, as yubihsm-shell's strtok_r() parsing
    skips them.

    Args:
        value: A domain string as used throughout this codebase, e.g.
            "3" or "1,2" or "all".

    Returns:
        The domain bitmask expected by the SDK's domains= parameters.

    Raises:
        ValueError: If value contains a domain number outside 1-16, or
            is not a recognized format.
    """
    if value.casefold() == "all":
        return 0xFFFF
    if value.startswith(("0x", "0X")):
        return int(value, 16)
    domains = 0
    for token in _DOMAIN_SEPARATORS.split(value):
        if not token:
            continue
        number = int(token)
        if not 1 <= number <= 16:
            raise ValueError(f"domains are numbered from 1 to 16, got {number}")
        domains |= 1 << (number - 1)
    return domains


@dataclass(frozen=True, slots=True)
class RestorableObject:
    """
    An on-device asymmetric key or X.509-certificate opaque, the object
    types that can be backed up and restored.
    """

    id: int
    object_type: OBJECT
    algorithm: ALGORITHM


def list_restorable_objects(
    config: YubiHsmConfig,
    domains: str | None,
) -> tuple[RestorableObject, ...]:
    """
    List asymmetric keys and X.509-certificate opaques in domains.

    An opaque counts only if its algorithm is OPAQUE_X509_CERTIFICATE.

    Args:
        config: Connector URL, authentication key, and password.
        domains: Domain(s) to search, e.g. "3" or "1,2", or None to
            search every domain.

    Returns:
        The matching objects, ordered by ID and type.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.defs import ALGORITHM, OBJECT

    domain_bits = parse_domains(domains) if domains is not None else None

    def operation(session: AuthSession) -> tuple[RestorableObject, ...]:
        results: list[RestorableObject] = []
        for obj in session.list_objects(domains=domain_bits):
            info = obj.get_info()
            if info.object_type == OBJECT.ASYMMETRIC_KEY or (
                info.object_type == OBJECT.OPAQUE
                and info.algorithm == ALGORITHM.OPAQUE_X509_CERTIFICATE
            ):
                results.append(
                    RestorableObject(info.id, info.object_type, info.algorithm),
                )
        return tuple(
            sorted(results, key=lambda obj: (obj.id, obj.object_type)),
        )

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


def _is_nonempty_regular_file(path: Path) -> bool:
    """
    Check whether a path is a regular file with at least one byte.

    Args:
        path: Candidate backup file.

    Returns:
        True if the path is a regular, nonempty file.
    """
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


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


def _parses_as_pem_certificate(path: Path) -> bool:
    """
    Check whether a file holds a PEM certificate that parses.

    Args:
        path: Candidate certificate backup file.

    Returns:
        True if the file can be read and parses as a PEM certificate.
    """
    from cryptography.x509 import load_pem_x509_certificate

    try:
        load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return False
    return True


def is_object_available_on_disk(
    key_dir: Path,
    object_id: int,
    object_type: OBJECT,
) -> bool:
    """
    Check whether a complete backup of an object exists on disk.

    Files are named after the "0x%04x"-formatted object ID. Only a
    regular, nonempty file that decodes as a wrapped-key backup, or for
    a certificate parses as a PEM certificate, counts, so that a file
    truncated by an interrupted export or otherwise corrupt does not.

    Args:
        key_dir: Directory backups are read from and written to.
        object_id: The object's ID.
        object_type: OBJECT.ASYMMETRIC_KEY or OBJECT.OPAQUE.

    Returns:
        True if a matching, non-truncated backup file exists.
    """
    from yubihsm.defs import OBJECT

    key_id = f"0x{object_id:04x}"
    if object_type == OBJECT.ASYMMETRIC_KEY:
        path = key_dir / f"{key_id}-asymmetric-key.yhw"
        if not _is_nonempty_regular_file(path):
            return False
        try:
            return bool(decode_wrapped_key_backup(path.read_bytes(), str(path)))
        except (OSError, ValueError):
            return False
    path = key_dir / f"{key_id}.x509.pem"
    return _is_nonempty_regular_file(path) and _parses_as_pem_certificate(path)


def delete_object(
    config: YubiHsmConfig,
    object_id: int,
    object_type: OBJECT,
) -> None:
    """
    Delete one object from the HSM.

    Args:
        config: Connector URL, authentication key, and password.
        object_id: The object's ID.
        object_type: The object's type.

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """

    def operation(session: AuthSession) -> None:
        session.get_object(object_id, object_type).delete()

    _run_with_session(lambda: connect_yubihsm_session(config), operation)


def _object_type_name(object_type: OBJECT) -> str:
    from yubihsm.defs import OBJECT

    return {OBJECT.ASYMMETRIC_KEY: "asymmetric-key", OBJECT.OPAQUE: "opaque"}[
        object_type
    ]


def limit_ondemand_objects(
    config: YubiHsmConfig,
    key_dir: Path,
    ondemand_domains: str,
    after_delete: Callable[[str], None] | None = None,
    *,
    dry_run: bool = False,
) -> None:
    """
    Evict on-demand objects until the HSM has enough free storage.

    Only objects backed up to disk (and therefore restorable later) are
    eligible for eviction. Once eviction starts for a given object ID,
    its remaining on-demand pieces (the key and its cert both share an
    ID) are deleted together even if space becomes sufficient partway
    through, so an ID is never left with only one of the pair evicted.

    Args:
        config: Connector URL, authentication key, and password.
        key_dir: Directory on-demand object backups live in.
        ondemand_domains: Domain(s) on-demand objects live in.
        after_delete: Called after every delete, successful or not, with
            a "Command: ... Result: N" line describing it.
        dry_run: Print each delete as a yubihsm-shell command instead of
            deleting it, so that nothing is freed.

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure, or if eviction could not free
            enough space.
    """
    objects = list_restorable_objects(config, ondemand_domains)
    last_id: int | None = None
    for obj in objects:
        if not is_object_available_on_disk(key_dir, obj.id, obj.object_type):
            continue

        should_make_space = should_make_space_on_hsm(get_storage_info(config))
        if not should_make_space and last_id != obj.id:
            return

        command = (
            f"Command: delete-object --object-id {obj.id:#06x} "
            f"--object-type {_object_type_name(obj.object_type)}"
        )
        if dry_run:
            print(
                "yubihsm -a delete-object --object-id "
                f"{obj.id:#06x} --object-type "
                f"{_object_type_name(obj.object_type)}\n",
                file=sys.stderr,
            )
            last_id = obj.id
            continue
        try:
            delete_object(config, obj.id, obj.object_type)
        except Exception:
            if after_delete is not None:
                after_delete(f"{command} Result: 1")
            raise
        if after_delete is not None:
            after_delete(f"{command} Result: 0")
        last_id = obj.id

    if should_make_space_on_hsm(get_storage_info(config)):
        raise RuntimeError(
            "Failed to make enough space on the HSM in limit_ondemand_objects.",
        )


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
