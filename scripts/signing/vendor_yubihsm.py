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
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar

from .keymap import Keymapper
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


@dataclass(frozen=True, slots=True)
class LoadedKeyStatus:
    """
    Which object IDs currently have their asymmetric key, their
    certificate, or both, loaded on the HSM.
    """

    loaded_key_ids: frozenset[int]
    loaded_cert_ids: frozenset[int]
    fully_loaded_ids: frozenset[int]


def get_loaded_key_status(config: YubiHsmConfig) -> LoadedKeyStatus:
    """
    Report which object IDs currently have their key, cert, or both.

    Scans every object in the domains of the authentication key.

    Args:
        config: Connector URL, authentication key, and password.

    Returns:
        The sets of key/cert/fully-loaded object IDs.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from yubihsm.defs import OBJECT

    objects = list_restorable_objects(config, None)
    loaded_keys = {
        obj.id for obj in objects if obj.object_type == OBJECT.ASYMMETRIC_KEY
    }
    loaded_certs = {
        obj.id for obj in objects if obj.object_type == OBJECT.OPAQUE
    }
    return LoadedKeyStatus(
        loaded_key_ids=frozenset(loaded_keys),
        loaded_cert_ids=frozenset(loaded_certs),
        fully_loaded_ids=frozenset(loaded_keys & loaded_certs),
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


def _object_type_name(object_type: OBJECT) -> str:
    from yubihsm.defs import OBJECT

    return {OBJECT.ASYMMETRIC_KEY: "asymmetric-key", OBJECT.OPAQUE: "opaque"}[
        object_type
    ]


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


def import_certificate(
    config: YubiHsmConfig,
    *,
    key_id: str,
    domains: str,
    capabilities: str,
    certificate_pem: bytes,
) -> None:
    """
    Import an X.509 certificate as an opaque object.

    The certificate is stored as-is, not wrapped, since it carries no
    private key material.

    Args:
        config: Connector URL, authentication key, and password.
        key_id: The ID to give the imported object, e.g. "0x2000".
        domains: Domain(s) to assign the object to, e.g. "3".
        capabilities: Capabilities to give the object, e.g.
            "get-opaque".
        certificate_pem: The certificate, PEM-encoded.

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails, e.g. because an object with this ID
            already exists.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    from cryptography.x509 import load_pem_x509_certificate
    from yubihsm.defs import ERROR
    from yubihsm.objects import Opaque

    object_id = int(key_id, 16)
    domain_bits = parse_domains(domains)
    capability_flags = parse_capabilities(capabilities)
    certificate = load_pem_x509_certificate(certificate_pem)

    def operation(session: AuthSession) -> None:
        Opaque.put_certificate(
            session,
            object_id,
            "",
            domain_bits,
            capability_flags,
            certificate,
        )

    _run_write_with_session(config, operation, ERROR.OBJECT_EXISTS)


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


def _resolve_domain_and_capabilities(
    *,
    is_ondemand: bool,
    exportable_domain: str,
    ondemand_domain: str,
    opaque_capabilities: str,
) -> tuple[str, str]:
    """
    Choose the domain and capabilities to import a key ID's objects with.

    A key gets exportable_domain (plus ondemand_domain if it is on-demand)
    and the base capabilities with exportable-under-wrap appended.

    Returns:
        (domain, opaque_capabilities) to import with.
    """
    domain = (
        f"{exportable_domain},{ondemand_domain}"
        if is_ondemand
        else exportable_domain
    )
    return (
        domain,
        f"{opaque_capabilities},exportable-under-wrap",
    )


def ensure_keys_are_available(
    config: YubiHsmConfig,
    key_dir: Path,
    key_ids: Sequence[str],
    *,
    restore_mode: bool,
    is_ondemand: Callable[[int], bool],
    verify_key_ids: bool = True,
    exportable_domain: str,
    ondemand_domain: str,
    opaque_capabilities: str,
    after_key: Callable[[str], None] | None = None,
) -> None:
    """
    Ensure each of key_ids' asymmetric key and certificate are loaded
    onto the HSM, importing from disk (evicting other on-demand
    objects to make room if needed) whatever is not already present.

    Only objects that is_ondemand marks as on-demand are evicted, also
    among the objects outside key_ids in the searched domains.

    An object evicted to make room for a key or certificate that then
    fails to import is imported again from its backup before the error
    is raised. Evictions made for an object that did load stay.

    Args:
        config: Connector URL, authentication key, and password.
        key_dir: Directory backups are read from.
        key_ids: The "0x%04x"-style key IDs to ensure are available,
            e.g. "0x2000".
        restore_mode: If True, a key/cert missing its on-disk backup is
            skipped rather than treated as an error, unless that leaves
            nothing to load for the key. Every key_id, not just an
            on-demand one, is considered, and the domain search also
            covers exportable_domain.
        is_ondemand: True if an object ID may be freely evicted and
            reloaded, i.e. it was exported under wrap.
        verify_key_ids: If False, skip filtering key_ids down to the
            on-demand subset first, which restore_mode keeps whole.
        exportable_domain: Domain assigned to exportable keys/certs.
        ondemand_domain: Domain assigned to on-demand keys/certs, and
            searched for eviction candidates.
        opaque_capabilities: Base capabilities for imported
            certificates, before the exportable-under-wrap suffix.
        after_key: Called with each key ID once its key and certificate
            are loaded, unless both were loaded already.

    Returns:
        None.

    Raises:
        RuntimeError: If a key or cert cannot be found on disk outside
            restore_mode, if no eviction candidate can be found while
            space is needed, or if restore_mode leaves nothing to load
            for a key.
        yubihsm.exceptions.YubiHsmError: If the SDK session or an
            operation fails.
    """
    from yubihsm.defs import OBJECT

    if verify_key_ids:
        key_ids = [
            key_id
            for key_id in key_ids
            if is_ondemand(int(key_id, 16)) or restore_mode
        ]

    deletion_ineligible_keys = {int(key_id, 16) for key_id in key_ids}
    deletion_ineligible_certs = set(deletion_ineligible_keys)

    lookup_domain = ondemand_domain
    if restore_mode:
        lookup_domain = f"{exportable_domain},{ondemand_domain}"
    existing = list_restorable_objects(config, lookup_domain)
    middle_id = existing[len(existing) // 2].id if existing else 0

    for key_id in key_ids:
        object_id = int(key_id, 16)
        should_make_space = should_make_space_on_hsm(get_storage_info(config))
        deletion_candidate_key_id: int | None = None
        deletion_candidate_cert_id: int | None = None
        key_found = False
        cert_found = False
        prefer_lowest_id = object_id >= middle_id

        for obj in existing:
            if obj.id == object_id:
                if obj.object_type == OBJECT.ASYMMETRIC_KEY:
                    key_found = True
                elif obj.object_type == OBJECT.OPAQUE:
                    cert_found = True
                continue

            if not should_make_space:
                if key_found and cert_found:
                    break
                continue

            if (
                (
                    deletion_candidate_key_id is None
                    or deletion_candidate_cert_id is None
                )
                and is_object_available_on_disk(
                    key_dir,
                    obj.id,
                    obj.object_type,
                )
                and is_ondemand(obj.id)
            ):
                if (
                    obj.object_type == OBJECT.ASYMMETRIC_KEY
                    and obj.id not in deletion_ineligible_keys
                ):
                    if not prefer_lowest_id:
                        deletion_candidate_key_id = obj.id
                    elif deletion_candidate_key_id is None:
                        deletion_candidate_key_id = obj.id
                elif (
                    obj.object_type == OBJECT.OPAQUE
                    and obj.id not in deletion_ineligible_certs
                ):
                    if not prefer_lowest_id:
                        deletion_candidate_cert_id = obj.id
                    elif deletion_candidate_cert_id is None:
                        deletion_candidate_cert_id = obj.id

        if key_found and cert_found:
            continue

        key_missing_on_disk = False
        if not key_found:
            if not _is_nonempty_regular_file(
                key_dir / f"{key_id}-asymmetric-key.yhw",
            ):
                message = (
                    f"Wanted to load key {key_id} but could not find a "
                    "wrapped copy on disk"
                )
                if not restore_mode:
                    raise RuntimeError(message)
                print(message, file=sys.stderr)
                key_missing_on_disk = True
            if should_make_space and deletion_candidate_key_id is None:
                raise RuntimeError(
                    f"Could not find any on-demand key to delete to make "
                    f"room for {key_id}",
                )

        cert_missing_on_disk = False
        if not cert_found:
            if not is_object_available_on_disk(
                key_dir,
                object_id,
                OBJECT.OPAQUE,
            ):
                message = (
                    f"Wanted to load cert {key_id} but could not find it "
                    "on disk"
                )
                if not restore_mode:
                    raise RuntimeError(message)
                print(message, file=sys.stderr)
                cert_missing_on_disk = True
            if should_make_space and deletion_candidate_cert_id is None:
                raise RuntimeError(
                    f"Could not find any on-demand cert to delete to make "
                    f"room for {key_id}",
                )

        if (
            restore_mode
            and (key_found or key_missing_on_disk)
            and (cert_found or cert_missing_on_disk)
        ):
            raise RuntimeError(
                f"Failed to find any on-disk keys or certs for {key_id}",
            )

        domain, resolved_opaque_capabilities = _resolve_domain_and_capabilities(
            is_ondemand=is_ondemand(object_id),
            exportable_domain=exportable_domain,
            ondemand_domain=ondemand_domain,
            opaque_capabilities=opaque_capabilities,
        )

        if not key_found and not key_missing_on_disk:
            # Decode before evicting, so an unreadable backup fails with the
            # HSM still untouched.
            backup = key_dir / f"{key_id}-asymmetric-key.yhw"
            wrapped = decode_wrapped_key_backup(
                backup.read_bytes(),
                str(backup),
            )
            if deletion_candidate_key_id is not None:
                delete_object(
                    config,
                    deletion_candidate_key_id,
                    OBJECT.ASYMMETRIC_KEY,
                )
                deletion_ineligible_keys.add(deletion_candidate_key_id)
            try:
                import_wrapped_key(config, key_id, wrapped)
            except Exception:
                if deletion_candidate_key_id is not None:
                    evicted = f"0x{deletion_candidate_key_id:04x}"
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

        if not cert_found and not cert_missing_on_disk:
            certificate_pem = (key_dir / f"{key_id}.x509.pem").read_bytes()
            if deletion_candidate_cert_id is not None:
                delete_object(config, deletion_candidate_cert_id, OBJECT.OPAQUE)
                deletion_ineligible_certs.add(deletion_candidate_cert_id)
            try:
                import_certificate(
                    config,
                    key_id=key_id,
                    domains=domain,
                    capabilities=resolved_opaque_capabilities,
                    certificate_pem=certificate_pem,
                )
            except Exception:
                if deletion_candidate_cert_id is not None:
                    evicted = f"0x{deletion_candidate_cert_id:04x}"
                    evicted_domain, evicted_capabilities = (
                        _resolve_domain_and_capabilities(
                            is_ondemand=True,
                            exportable_domain=exportable_domain,
                            ondemand_domain=ondemand_domain,
                            opaque_capabilities=opaque_capabilities,
                        )
                    )
                    import_certificate(
                        config,
                        key_id=evicted,
                        domains=evicted_domain,
                        capabilities=evicted_capabilities,
                        certificate_pem=(
                            key_dir / f"{evicted}.x509.pem"
                        ).read_bytes(),
                    )
                raise

        if after_key is not None:
            after_key(key_id)


def _device_key_ids(
    keymapper: Keymapper,
    devices: Sequence[str],
) -> dict[str, frozenset[str]]:
    """
    Map each device to the key IDs of its per-device keys, the entries of
    the keymapper's device_specific_key_ids_map.

    Args:
        keymapper: The release's keymapper.
        devices: Device names to build entries for.

    Returns:
        Each requested device mapped to its set of per-device key IDs.

    Raises:
        RuntimeError: If a device has no per-device keys.
        ValueError: If the keymapper does not assign key IDs.
    """
    result = {device: keymapper.device_key_ids(device) for device in devices}
    for device, ids in result.items():
        if not ids:
            raise RuntimeError(f"The keymapper has no keys for {device}")
    return result


def populate_devices_with_loaded_keys_arrays(
    config: YubiHsmConfig,
    keymapper: Keymapper,
    devices: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """
    Partition devices by whether every key they need is already loaded.

    A device counts as loaded only if every per-device key ID the
    keymapper gives it has both its key and its certificate on the HSM.

    Args:
        config: Connector URL, authentication key, and password.
        keymapper: Keymapper giving each device's per-device key IDs.
        devices: Device names to partition.

    Returns:
        A (devices_with_loaded_keys, devices_without_loaded_keys) pair,
        each in the same order as devices.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    key_ids_by_device = _device_key_ids(keymapper, devices)
    fully_loaded = get_loaded_key_status(config).fully_loaded_ids

    with_loaded_keys: list[str] = []
    without_loaded_keys: list[str] = []
    for device in devices:
        key_ids = key_ids_by_device[device]
        if all(int(key_id, 16) in fully_loaded for key_id in key_ids):
            with_loaded_keys.append(device)
        else:
            without_loaded_keys.append(device)
    return tuple(with_loaded_keys), tuple(without_loaded_keys)


def ensure_all_keys_available_for_devices(
    config: YubiHsmConfig,
    keymapper: Keymapper,
    key_dir: Path,
    devices: Sequence[str],
    *,
    is_ondemand: Callable[[int], bool],
    exportable_domain: str,
    ondemand_domain: str,
    opaque_capabilities: str,
    after_key: Callable[[str], None] | None = None,
) -> None:
    """
    Ensure every per-device key the given devices need is loaded.

    It extracts no audit log.

    Args:
        config: Connector URL, authentication key, and password.
        keymapper: Keymapper giving each device's per-device key IDs.
        key_dir: Directory backups are read from.
        devices: Device names whose keys must be available.
        is_ondemand: Whether a numeric object ID is an on-demand object.
        exportable_domain: Domain(s) for restore-mode-only keys.
        ondemand_domain: Domain(s) searched for on-demand objects.
        opaque_capabilities: Capabilities to apply to imported certs.
        after_key: See ensure_keys_are_available().

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure.
    """
    key_ids_by_device = _device_key_ids(keymapper, devices)
    needed_keys: set[str] = set()
    for device in devices:
        needed_keys.update(key_ids_by_device[device])
    ensure_keys_are_available(
        config,
        key_dir,
        tuple(sorted(needed_keys)),
        restore_mode=False,
        is_ondemand=is_ondemand,
        verify_key_ids=False,
        exportable_domain=exportable_domain,
        ondemand_domain=ondemand_domain,
        opaque_capabilities=opaque_capabilities,
        after_key=after_key,
    )


def _restorable_key_ids_on_disk(key_dir: Path) -> tuple[str, ...]:
    """
    List the deduplicated key IDs backed up in a key directory.

    Args:
        key_dir: Directory to scan.

    Returns:
        Deduplicated key IDs found in key_dir, those of certificates first,
        then those of wrapped keys whose certificate is missing, each group
        sorted.
    """
    found: dict[str, None] = {}
    for pattern in ("*.x509.pem", "*-asymmetric-key.yhw"):
        for path in sorted(key_dir.glob(pattern)):
            name = path.name
            if name.endswith("-asymmetric-key.yhw"):
                key_id = name[: -len("-asymmetric-key.yhw")]
            else:
                key_id = name[: -len(".x509.pem")]
            found.setdefault(key_id)
    return tuple(found)


def restore_all_keys_and_certs(
    config: YubiHsmConfig,
    key_dir: Path,
    log_file: Path,
    *,
    is_ondemand: Callable[[int], bool],
    exportable_domain: str,
    ondemand_domain: str,
    opaque_capabilities: str,
) -> None:
    """
    Bulk-restore every key/cert backed up in a key directory.

    A manual disaster-recovery tool. Restores one key at a time in
    restore_mode and extracts the audit log after every key, so that a
    long restore cannot fill the HSM's audit log. Stops at the first
    key that fails.

    Args:
        config: Connector URL, authentication key, and password.
        key_dir: Directory to restore keys and certificates from.
        log_file: Audit log file to append entries to after each key.
        is_ondemand: Whether a numeric object ID is an on-demand object.
        exportable_domain: Domain(s) for restore-mode-only keys.
        ondemand_domain: Domain(s) searched for on-demand objects.
        opaque_capabilities: Capabilities to apply to imported certs.

    Returns:
        None.

    Raises:
        yubihsm.exceptions.YubiHsmError: If the SDK session or
            operation fails.
        RuntimeError: If a managed connector fails to restart after a
            connector-level failure, or if no eviction candidate can be
            found while space is needed.
    """
    result = 0
    try:
        for key_id in _restorable_key_ids_on_disk(key_dir):
            key_result = 1
            try:
                ensure_keys_are_available(
                    config,
                    key_dir,
                    (key_id,),
                    restore_mode=True,
                    is_ondemand=is_ondemand,
                    verify_key_ids=False,
                    exportable_domain=exportable_domain,
                    ondemand_domain=ondemand_domain,
                    opaque_capabilities=opaque_capabilities,
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
            comment=f"Function: restore_all_keys_and_certs Result: {result}",
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
