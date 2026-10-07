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
import contextlib
import os
import re
import struct
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar

from .vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)

if TYPE_CHECKING:
    from yubihsm.core import AuthSession, DeviceInfo, LogEntry
    from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT


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
    wrap_id: str = "0x0010"


def restart_connector() -> None:
    """
    Restart the local yubihsm-connector this process manages and wait
    until it listens, unless NEVER_START_YUBIHSM_CONNECTOR=y leaves the
    connector to the user. The caller sets YUBIHSM_CONNECTOR_PIDFILE.

    Raises:
        RuntimeError: If the existing connector cannot be stopped before
            restarting it, or the new one exits or does not listen.
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
    connector.wait_until_listening()


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

    def attempt() -> T:
        session = session_factory()
        try:
            return operation(session)
        finally:
            session.close()

    return _retry_after_connector_restart(attempt)


def _retry_after_connector_restart(attempt: Callable[[], T]) -> T:
    """
    Run an attempt, and run it once more after a pause and a connector
    restart if it fails with a connection error while
    ``YUBIHSM_CONNECTOR_PIDFILE`` is set.

    Args:
        attempt: Callable performing the whole operation, safe to call
            again after a connection error.

    Returns:
        The attempt's result, from the first call or the retry.

    Raises:
        Exception: Whatever attempt raises, if it is not a connection
            error, or if YUBIHSM_CONNECTOR_PIDFILE is unset, or if the
            retry itself fails.
    """
    from yubihsm.exceptions import YubiHsmConnectionError

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
    return info.free_records < 5 or info.free_pages < 15


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """
    A YubiHSM's name, its part number and serial number joined by a hyphen,
    identifying one physical device, and its device information as
    yubihsm-shell's get-device-info prints it.
    """

    name: str
    device_info: str


_ALGORITHM_NAMES = {
    1: "rsa-pkcs1-sha1",
    2: "rsa-pkcs1-sha256",
    3: "rsa-pkcs1-sha384",
    4: "rsa-pkcs1-sha512",
    5: "rsa-pss-sha1",
    6: "rsa-pss-sha256",
    7: "rsa-pss-sha384",
    8: "rsa-pss-sha512",
    9: "rsa2048",
    10: "rsa3072",
    11: "rsa4096",
    12: "ecp256",
    13: "ecp384",
    14: "ecp521",
    15: "eck256",
    16: "ecbp256",
    17: "ecbp384",
    18: "ecbp512",
    19: "hmac-sha1",
    20: "hmac-sha256",
    21: "hmac-sha384",
    22: "hmac-sha512",
    23: "ecdsa-sha1",
    24: "ecdh",
    25: "rsa-oaep-sha1",
    26: "rsa-oaep-sha256",
    27: "rsa-oaep-sha384",
    28: "rsa-oaep-sha512",
    29: "aes128-ccm-wrap",
    30: "opaque-data",
    31: "opaque-x509-certificate",
    32: "mgf1-sha1",
    33: "mgf1-sha256",
    34: "mgf1-sha384",
    35: "mgf1-sha512",
    36: "template-ssh",
    37: "aes128-yubico-otp",
    38: "aes128-yubico-authentication",
    39: "aes192-yubico-otp",
    40: "aes256-yubico-otp",
    41: "aes192-ccm-wrap",
    42: "aes256-ccm-wrap",
    43: "ecdsa-sha256",
    44: "ecdsa-sha384",
    45: "ecdsa-sha512",
    46: "ed25519",
    47: "ecp224",
    48: "rsa-pkcs1-decrypt",
    49: "ecp256-yubico-authentication",
    50: "aes128",
    51: "aes192",
    52: "aes256",
    53: "aes-ecb",
    54: "aes-cbc",
    55: "aes-kwp",
}


def _device_info_text(info: DeviceInfo) -> str:
    """
    Render device information as yubihsm-shell's get-device-info prints
    it, three algorithms to a line.
    """
    version = ".".join(str(part) for part in info.version)
    text = (
        f"Version number:\t\t{version}\n"
        f"Serial number:\t\t{info.serial}\n"
        f"Log used:\t\t{info.log_used}/{info.log_size}\n"
        "Supported algorithms:\t"
    )
    for index, algorithm in enumerate(sorted(info.supported_algorithms), 1):
        name = _ALGORITHM_NAMES.get(int(algorithm), str(int(algorithm)))
        text += f"{name}, " + ("\n\t\t\t" if index % 3 == 0 else "")
    return text + f"\nPart number:\t\t{info.part_number}\n"


def get_device_identity(config: YubiHsmConfig) -> DeviceIdentity:
    """
    Return the HSM's serial number, part number and device information.

    GET_DEVICE_INFO needs no authenticated session, so the configured
    authentication key and password go unused.

    Args:
        config: Connector URL.

    Returns:
        The device's serial number, part number and device information.

    Raises:
        RuntimeError: If the device did not report a part number (only
            reported on a second info page, absent on older firmware),
            or if a managed connector fails to restart after a
            connector-level failure.
        yubihsm.exceptions.YubiHsmError: If the SDK connection or
            command fails.
    """
    from yubihsm.core import YubiHsm

    def operation(hsm: YubiHsm) -> DeviceIdentity:
        info = hsm.get_device_info()
        if not info.part_number:
            raise RuntimeError("YubiHSM did not report a part number")
        return DeviceIdentity(
            name=f"{info.part_number}-{info.serial}",
            device_info=_device_info_text(info),
        )

    return _run_with_session(
        lambda: YubiHsm.connect(config.connector_url),
        operation,
    )


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


_SHELL_CAPABILITY_NAMES = {
    "put-asymmetric-key": "PUT_ASYMMETRIC",
    "put-mac-key": "PUT_HMAC_KEY",
    "put-public-wrap-key": "PUBLIC_WRAP_KEY_WRITE",
    "delete-public-wrap-key": "PUBLIC_WRAP_KEY_DELETE",
}


def parse_capabilities(value: str) -> CAPABILITY:
    """
    Parse a capability-list string into the SDK's CAPABILITY flag form.

    Matches yubihsm-shell's yh_string_to_capabilities(). "all" and
    "none" in any case are the full and the empty set, and anything else
    is a list of capability names separated by any of ``:``, ``,``, ``;``
    and ``|``. Each name matches a CAPABILITY member case-insensitively,
    with kebab-case for SCREAMING_SNAKE_CASE ("exportable-under-wrap"
    for CAPABILITY.EXPORTABLE_UNDER_WRAP), except for the four names
    libyubihsm spells differently from the SDK. Empty segments are
    skipped, as yubihsm-shell's strtok_r() parsing skips them.

    Args:
        value: A capability string as used throughout this codebase,
            e.g. "sign-pkcs,exportable-under-wrap".

    Returns:
        The combined CAPABILITY flags.

    Raises:
        ValueError: If a name does not match any known capability.
    """
    from yubihsm.defs import CAPABILITY

    if value.casefold() == "all":
        return ~CAPABILITY(0)
    if value.casefold() == "none":
        return CAPABILITY(0)
    capabilities = CAPABILITY(0)
    for token in _DOMAIN_SEPARATORS.split(value):
        if not token:
            continue
        name = token.casefold()
        member = _SHELL_CAPABILITY_NAMES.get(name) or name.upper().replace(
            "-",
            "_",
        )
        try:
            capabilities |= CAPABILITY[member]
        except KeyError as error:
            raise ValueError(f"unknown capability {token!r}") from error
    return capabilities


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


def get_loaded_key_ids(config: YubiHsmConfig) -> frozenset[int]:
    """
    Report which object IDs currently have their key loaded.

    Scans every object in the domains of the authentication key.

    Args:
        config: Connector URL, authentication key, and password.

    Returns:
        The object IDs of the loaded keys.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.defs import OBJECT

    objects = list_restorable_objects(config, None)
    return frozenset(
        obj.id for obj in objects if obj.object_type == OBJECT.ASYMMETRIC_KEY
    )


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


def _run_write_with_session(
    config: YubiHsmConfig,
    operation: Callable[[AuthSession], None],
    already_done: int,
) -> None:
    """
    Run a device write as _run_with_session() does, and take the error
    already_done on the retry for success, since the first attempt can take
    effect on the device before its connection fails.

    Args:
        config: Connection settings.
        operation: The write, run against an authenticated session.
        already_done: The error the device answers a repeated write with.
    """
    from yubihsm.exceptions import YubiHsmDeviceError

    attempts = 0

    def write(session: AuthSession) -> None:
        nonlocal attempts
        attempts += 1
        try:
            operation(session)
        except YubiHsmDeviceError as error:
            if attempts == 1 or error.code != already_done:
                raise

    _run_with_session(lambda: connect_yubihsm_session(config), write)


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
    from yubihsm.defs import ERROR

    def operation(session: AuthSession) -> None:
        session.get_object(object_id, object_type).delete()

    _run_write_with_session(config, operation, ERROR.OBJECT_NOT_FOUND)


_PKCS11_ALGORITHM_NAMES = {
    "RSA:2048": "RSA_2048",
    "RSA:3072": "RSA_3072",
    "RSA:4096": "RSA_4096",
}


def generate_asymmetric_key(
    config: YubiHsmConfig,
    *,
    key_id: str,
    label: str,
    domains: str,
    capabilities: str,
    algorithm: str,
) -> None:
    """
    Generate a new asymmetric key on the HSM.

    Args:
        config: Connector URL, authentication key, and password.
        key_id: The ID to give the new key, e.g. "0x2000".
        label: A text label for the key.
        domains: Domain(s) to assign the key to, e.g. "3".
        capabilities: Capabilities to give the key, e.g. "sign-pkcs".
        algorithm: "RSA:2048", "RSA:3072" or "RSA:4096".

    Returns:
        None.

    Raises:
        ValueError: If algorithm is none of those.
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails, e.g. because an object with this ID
            already exists.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.defs import ALGORITHM, ERROR
    from yubihsm.objects import AsymmetricKey

    try:
        algorithm_name = _PKCS11_ALGORITHM_NAMES[algorithm]
    except KeyError:
        raise ValueError(
            f"Unknown algorithm '{algorithm}'; cannot convert to yubico",
        ) from None
    yubihsm_algorithm = ALGORITHM[algorithm_name]
    object_id = int(key_id, 16)
    domain_bits = parse_domains(domains)
    capability_flags = parse_capabilities(capabilities)

    def operation(session: AuthSession) -> None:
        AsymmetricKey.generate(
            session,
            object_id,
            label,
            domain_bits,
            capability_flags,
            yubihsm_algorithm,
        )

    _run_write_with_session(config, operation, ERROR.OBJECT_EXISTS)


def get_certificate(config: YubiHsmConfig, key_id: str) -> bytes:
    """
    Return an opaque X.509 certificate object's data as PEM.

    Args:
        config: Connector URL, authentication key, and password.
        key_id: The object's ID, e.g. "0x0000".

    Returns:
        The certificate, PEM-encoded.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails, e.g. because no object with this ID
            exists.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import load_der_x509_certificate
    from yubihsm.objects import Opaque

    object_id = int(key_id, 16)

    def operation(session: AuthSession) -> bytes:
        data = Opaque(session, object_id).get()
        certificate = load_der_x509_certificate(data)
        return certificate.public_bytes(Encoding.PEM)

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


def get_public_key(config: YubiHsmConfig, key_id: str) -> bytes:
    """
    Return an asymmetric key's public key as DER SubjectPublicKeyInfo.

    Args:
        config: Connector URL, authentication key, and password.
        key_id: The key's ID, e.g. "0x2000".

    Returns:
        The public key, DER-encoded.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails, e.g. because no key with this ID exists.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    from yubihsm.objects import AsymmetricKey

    object_id = int(key_id, 16)

    def operation(session: AuthSession) -> bytes:
        public_key: PublicKeyTypes = AsymmetricKey(
            session,
            object_id,
        ).get_public_key()
        return public_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    return _run_with_session(lambda: connect_yubihsm_session(config), operation)


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
            an "Operation: ... Result: N" line describing it.
        dry_run: Print each delete's "Operation:" line instead of
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
    from yubihsm.defs import OBJECT

    objects = list_restorable_objects(config, ondemand_domains)
    last_id: int | None = None
    for obj in objects:
        if not is_object_available_on_disk(key_dir, obj.id, obj.object_type):
            continue

        should_make_space = should_make_space_on_hsm(get_storage_info(config))
        if not should_make_space and last_id != obj.id:
            return

        object_type_name = (
            "asymmetric-key"
            if obj.object_type == OBJECT.ASYMMETRIC_KEY
            else "opaque"
        )
        command = (
            f"Operation: delete-object --object-id {obj.id:#06x} "
            f"--object-type {object_type_name}"
        )
        if dry_run:
            print(command, file=sys.stderr)
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


def ensure_keys_are_available(
    config: YubiHsmConfig,
    key_dir: Path,
    key_ids: Sequence[str],
    *,
    is_ondemand: Callable[[int], bool],
    lookup_domains: str,
    after_key: Callable[[str], None] | None = None,
) -> None:
    """
    Ensure each of key_ids' asymmetric key is loaded onto the HSM,
    importing its wrapped backup from disk (evicting another on-demand
    key to make room if needed) when it is not already present.

    Signing never reads a certificate from the HSM, so none is
    imported. A certificate left on the HSM under an evicted key's ID
    is evicted with that key, once the new key has loaded.

    Only keys that is_ondemand marks as on-demand are evicted, also
    among the keys outside key_ids in the searched domains. A key
    evicted to make room for a key that then fails to import is
    imported again from its backup before the error is raised.

    Args:
        config: Connector URL, authentication key, and password.
        key_dir: Directory backups are read from.
        key_ids: The "0x%04x"-style key IDs to ensure are available,
            e.g. "0x2000".
        is_ondemand: True if an object ID may be freely evicted and
            reloaded, i.e. it was exported under wrap.
        lookup_domains: Comma-separated domains searched for loaded
            keys and eviction candidates.
        after_key: Called with each key ID once its key is loaded,
            unless it was loaded already.

    Returns:
        None.

    Raises:
        RuntimeError: If a key's wrapped backup cannot be found on disk,
            or if no eviction candidate can be found while space is
            needed.
        yubihsm.exceptions.YubiHsmError: If the SDK session or an
            operation fails.
    """
    from yubihsm.defs import OBJECT

    deletion_ineligible = {int(key_id, 16) for key_id in key_ids}

    existing = list_restorable_objects(config, lookup_domains)
    middle_id = existing[len(existing) // 2].id if existing else 0

    for key_id in key_ids:
        object_id = int(key_id, 16)
        if any(
            obj.id == object_id and obj.object_type == OBJECT.ASYMMETRIC_KEY
            for obj in existing
        ):
            continue

        backup = key_dir / f"{key_id}-asymmetric-key.yhw"
        if not _is_nonempty_regular_file(backup):
            raise RuntimeError(
                f"Wanted to load key {key_id} but could not find "
                "a wrapped copy on disk",
            )

        deletion_candidate: int | None = None
        if should_make_space_on_hsm(get_storage_info(config)):
            prefer_lowest_id = object_id >= middle_id
            for obj in existing:
                if (
                    obj.object_type == OBJECT.ASYMMETRIC_KEY
                    and obj.id not in deletion_ineligible
                    and is_ondemand(obj.id)
                    and is_object_available_on_disk(
                        key_dir,
                        obj.id,
                        obj.object_type,
                    )
                    and (not prefer_lowest_id or deletion_candidate is None)
                ):
                    deletion_candidate = obj.id
            if deletion_candidate is None:
                raise RuntimeError(
                    f"Could not find any on-demand key to delete to make "
                    f"room for {key_id}",
                )

        # Decode before evicting, so an unreadable backup fails with the
        # HSM still untouched.
        wrapped = decode_wrapped_key_backup(backup.read_bytes(), str(backup))
        if deletion_candidate is not None:
            delete_object(config, deletion_candidate, OBJECT.ASYMMETRIC_KEY)
            deletion_ineligible.add(deletion_candidate)
        try:
            import_wrapped_key(config, key_id, wrapped)
        except Exception:
            if deletion_candidate is not None:
                evicted = f"0x{deletion_candidate:04x}"
                evicted_backup = key_dir / f"{evicted}-asymmetric-key.yhw"
                import_wrapped_key(
                    config,
                    evicted,
                    decode_wrapped_key_backup(
                        evicted_backup.read_bytes(),
                        str(evicted_backup),
                    ),
                )
            raise

        if deletion_candidate is not None and any(
            obj.id == deletion_candidate
            and obj.object_type == OBJECT.OPAQUE
            and is_object_available_on_disk(key_dir, obj.id, obj.object_type)
            for obj in existing
        ):
            from yubihsm.exceptions import YubiHsmError

            try:
                delete_object(config, deletion_candidate, OBJECT.OPAQUE)
            except (YubiHsmError, RuntimeError) as error:
                print(
                    "Warning: could not delete the certificate of evicted "
                    f"key 0x{deletion_candidate:04x} ({error}).",
                    file=sys.stderr,
                )

        if after_key is not None:
            after_key(key_id)


def restore_all_keys(
    config: YubiHsmConfig,
    key_dir: Path,
    log_file: Path,
    *,
    is_ondemand: Callable[[int], bool],
    exportable_domain: str,
    ondemand_domain: str,
) -> None:
    """
    Bulk-restore every key backed up in a key directory.

    A manual disaster-recovery tool. Restores one key at a time in
    both domains and extracts the audit log after every key, so that a
    long restore cannot fill the HSM's audit log. Stops at the first
    key that fails.

    Args:
        config: Connector URL, authentication key, and password.
        key_dir: Directory to restore keys from.
        log_file: Audit log file to append entries to after each key.
        is_ondemand: Whether a numeric object ID is an on-demand object.
        exportable_domain: Domain(s) for restore-mode-only keys.
        ondemand_domain: Domain(s) searched for on-demand objects.

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure, if a key's wrapped backup is empty or
            not a regular file, or if no eviction candidate can be found
            while space is needed.
    """
    result = 0
    try:
        for path in sorted(key_dir.glob("*-asymmetric-key.yhw")):
            key_id = path.name.removesuffix("-asymmetric-key.yhw")
            key_result = 1
            try:
                ensure_keys_are_available(
                    config,
                    key_dir,
                    (key_id,),
                    is_ondemand=is_ondemand,
                    lookup_domains=f"{exportable_domain},{ondemand_domain}",
                )
                key_result = 0
            finally:
                result = 1
                extract_and_save_audit_log(
                    config,
                    log_file,
                    comment=(
                        "Function: ensure_key_is_available "
                        f"Result: {key_result}"
                    ),
                )
                result = key_result
    finally:
        extract_and_save_audit_log(
            config,
            log_file,
            comment=f"Function: restore_all_keys Result: {result}",
        )


def attest_key(config: YubiHsmConfig, key_id: str) -> bytes:
    """
    Return a certificate attesting a key's on-device origin, signed by
    the device attestation key 0.

    Args:
        config: Connector URL, authentication key, and password.
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

    def operation(session: AuthSession) -> bytes:
        certificate = AsymmetricKey(session, object_id).attest(0)
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
    from yubihsm.defs import ERROR
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

    _run_write_with_session(config, operation, ERROR.OBJECT_EXISTS)


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


class AuditLogNotAcknowledged(RuntimeError):
    """
    The audit log entries were written to the log file, but the device
    did not acknowledge them, so it returns them again on the next read.
    """


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
    comment: str,
) -> None:
    """
    Append a device's new audit log entries and a comment line to a log
    file, over one session opened when first needed and opened again
    after a connector restart.

    Args:
        config: Connector URL, authentication key, and password.
        log_file: Path to append the comment line and entries to.
        comment: Single-line comment recorded with the entries.

    Raises:
        OSError: If log_file's directory cannot be created or written.
        AuditLogNotAcknowledged: If the entries are written but the device
            does not take the acknowledgement.
    """
    from yubihsm.exceptions import YubiHsmConnectionError

    sessions: list[AuthSession] = []

    def run(operation: Callable[[AuthSession], T]) -> T:
        def attempt() -> T:
            if not sessions:
                sessions.append(connect_yubihsm_session(config))
            try:
                return operation(sessions[0])
            except YubiHsmConnectionError:
                with contextlib.suppress(Exception):
                    sessions.pop().close()
                raise

        return _retry_after_connector_restart(attempt)

    try:
        save_audit_log(
            lambda: run(lambda session: session.get_log_entries().entries),
            lambda number: run(lambda session: session.set_log_index(number)),
            log_file,
            comment,
        )
    finally:
        if sessions:
            sessions.pop().close()


def save_audit_log(
    read: Callable[[], Sequence[LogEntry]],
    acknowledge: Callable[[int], None],
    log_file: Path,
    comment: str,
) -> None:
    """
    Append the entries read returns and a comment line to a log file,
    then acknowledge them.

    A comment line is always written, and only entries appended to the log
    file are acknowledged to the device. An entry whose line log_file holds
    already, left on the device by an acknowledgement that failed, is not
    written again, and the file is synced before the acknowledgement.

    Args:
        read: Returns every entry the device retains, oldest first.
        acknowledge: Marks entries up to and including a number as saved.
        log_file: Path to append the comment line and entries to.
        comment: Single-line comment recorded with the entries.

    Raises:
        OSError: If log_file's directory cannot be created or written.
        AuditLogNotAcknowledged: If the entries are written but the device
            does not take the acknowledgement.
    """
    clean_comment = comment.replace("\n", "").replace("\r", "")
    entries_read = tuple(read())

    log_file.parent.mkdir(parents=True, exist_ok=True)
    written = _recent_log_lines(log_file)
    entries = tuple(
        entry
        for entry in entries_read
        if format_audit_log_entry(entry) not in written
    )
    with log_file.open("a") as handle:
        handle.write(f"# {round(time.time() * 1000)} {clean_comment}\n")
        for entry in entries:
            handle.write(format_audit_log_entry(entry) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    if entries_read:
        try:
            acknowledge(entries_read[-1].number)
        except Exception as error:
            raise AuditLogNotAcknowledged(
                f"wrote {len(entries)} audit log entries to {log_file} "
                f"but could not acknowledge them: {error}",
            ) from error
