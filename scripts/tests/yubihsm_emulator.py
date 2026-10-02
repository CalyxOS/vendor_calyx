#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
A YubiHSM 2 emulated at the wire protocol, behind a stand-in for
yubihsm-connector, so that scripts using the yubihsm package run
unmodified against it over HTTP.
"""

from __future__ import annotations

import contextlib
import datetime
import gzip
import http.server
import os
import struct
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from yubihsm.defs import (
    ALGORITHM,
    AUDIT,
    CAPABILITY,
    COMMAND,
    ERROR,
    LIST_FILTER,
    OBJECT,
    OPTION,
    ORIGIN,
)
from yubihsm.objects import LABEL_LENGTH
from yubihsm.utils import password_to_key

LOG_SIZE = 62
DEFAULT_AUTHKEY_ID = 0x0001
DEFAULT_PASSWORD = "password"
_INFO_FORMAT = f"!QHHHBBBB{LABEL_LENGTH}sQ"
_PUT_FORMAT = f"!H{LABEL_LENGTH}sHQBQ"
_PUT_DATA_FORMAT = f"!H{LABEL_LENGTH}sHQB"
_INFO_LENGTH = struct.calcsize(_INFO_FORMAT)
_ATTESTATION_OID = "1.3.6.1.4.1.41482.4.{}"
_PAGE_SIZE = 126
_RSA_ALGORITHMS = {
    2048: ALGORITHM.RSA_2048,
    3072: ALGORITHM.RSA_3072,
    4096: ALGORITHM.RSA_4096,
}
_DIGEST_HASHES: dict[
    int,
    type[hashes.SHA256 | hashes.SHA384 | hashes.SHA512],
] = {
    32: hashes.SHA256,
    48: hashes.SHA384,
    64: hashes.SHA512,
}
_DIGEST_INFO_PREFIXES = {
    bytes.fromhex("3031300d060960864801650304020105000420"): 32,
    bytes.fromhex("3041300d060960864801650304020205000430"): 48,
    bytes.fromhex("3051300d060960864801650304020305000440"): 64,
}

_DELETE_CAPABILITY = {
    OBJECT.OPAQUE: CAPABILITY.DELETE_OPAQUE,
    OBJECT.AUTHENTICATION_KEY: CAPABILITY.DELETE_AUTHENTICATION_KEY,
    OBJECT.ASYMMETRIC_KEY: CAPABILITY.DELETE_ASYMMETRIC_KEY,
    OBJECT.WRAP_KEY: CAPABILITY.DELETE_WRAP_KEY,
}


class DeviceError(Exception):
    def __init__(self, code: ERROR) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class StoredObject:
    object_id: int
    object_type: OBJECT
    algorithm: ALGORITHM
    label: bytes
    domains: int
    capabilities: int
    delegated_capabilities: int
    data: bytes
    origin: ORIGIN = ORIGIN.IMPORTED
    sequence: int = 0

    def info(self) -> bytes:
        return struct.pack(
            _INFO_FORMAT,
            self.capabilities,
            self.object_id,
            len(self.data),
            self.domains,
            self.object_type,
            self.algorithm,
            self.sequence,
            self.origin,
            self.label,
            self.delegated_capabilities,
        )


@dataclass
class _Session:
    authkey: StoredObject
    key_enc: bytes
    key_mac: bytes
    key_rmac: bytes
    mac_chain: bytes
    authenticated: bool
    counter: int = 1
    context: bytes = b""


def _derive(key: bytes, kind: int, context: bytes, length: int = 0x80) -> bytes:
    data = b"\0" * 11 + struct.pack("!BBHB", kind, 0, length, 1) + context
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()[: length // 8]


def _cmac(key: bytes, *parts: bytes) -> bytes:
    mac = cmac.CMAC(algorithms.AES(key))
    for part in parts:
        mac.update(part)
    return mac.finalize()


def _iv(key: bytes, counter: int) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(counter.to_bytes(16, "big")) + encryptor.finalize()


def _response(command: int, data: bytes) -> bytes:
    return struct.pack("!BH", command | 0x80, len(data)) + data


def _error(code: ERROR) -> bytes:
    return struct.pack("!BHB", COMMAND.ERROR, 1, code)


def _self_signed(name: str, key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=36500))
        .sign(key, hashes.SHA256())
    )


class EmulatedYubiHsm:
    """
    One emulated YubiHSM 2, which RESET_DEVICE returns to its factory
    defaults.
    """

    def __init__(
        self,
        serial: int = 123456,
        *,
        total_records: int = 256,
        total_pages: int = 1024,
    ) -> None:
        self.serial = serial
        self.part_number = "YubiHSM2"
        self.total_records = total_records
        self.total_pages = total_pages
        self.failures: dict[int, list[ERROR]] = {}
        self.corrupt_signatures = False
        self.sessions_opened = 0
        self.history: list[tuple[float, int, tuple[int, int]]] = []
        self.version = (2, 4, 0)
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.attestation_key = rsa.generate_private_key(65537, 2048)
        self.attestation_certificate = _self_signed(
            f"YubiHSM Attestation ({serial})",
            self.attestation_key,
        )
        self.tick = 0
        self.resets = 0
        self.factory_reset()

    def factory_reset(self) -> None:
        self.objects: dict[tuple[int, OBJECT], StoredObject] = {}
        self.sessions: dict[int, _Session] = {}
        self.force_audit = AUDIT.OFF
        self.command_audit: dict[int, AUDIT] = {}
        self.log: list[tuple[int, bytes, bytes]] = []
        self.log_index = 0
        self.last_digest = b"\0" * 16
        self.log_number = 0
        enc, mac = password_to_key(DEFAULT_PASSWORD)
        self._store(
            StoredObject(
                DEFAULT_AUTHKEY_ID,
                OBJECT.AUTHENTICATION_KEY,
                ALGORITHM.AES128_YUBICO_AUTHENTICATION,
                b"DEFAULT AUTHKEY CHANGE THIS ASAP",
                0xFFFF,
                (1 << 64) - 1,
                (1 << 64) - 1,
                enc + mac,
            ),
        )
        self._append_log(0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0)

    def get(self, object_id: int, object_type: OBJECT) -> StoredObject | None:
        return self.objects.get((object_id, object_type))

    def fail_next(
        self,
        command: COMMAND,
        error: ERROR = ERROR.INVALID_DATA,
        times: int = 1,
    ) -> None:
        """Make the next `times` uses of a command fail with an error."""
        self.failures.setdefault(command, []).extend([error] * times)

    def audit(self, *commands: COMMAND) -> None:
        """Turn on the audit log entry for each command."""
        for command in commands:
            self.command_audit[command] = AUDIT.ON

    def put_authentication_key(
        self,
        object_id: int,
        password: str,
        *,
        domains: int = 0xFFFF,
        capabilities: int = (1 << 64) - 1,
        delegated_capabilities: int = (1 << 64) - 1,
    ) -> None:
        enc, mac = password_to_key(password)
        self._store(
            StoredObject(
                object_id,
                OBJECT.AUTHENTICATION_KEY,
                ALGORITHM.AES128_YUBICO_AUTHENTICATION,
                b"",
                domains,
                capabilities,
                delegated_capabilities,
                enc + mac,
            ),
        )

    def put_wrap_key(
        self,
        object_id: int,
        key: bytes | None = None,
        *,
        domains: int = 0xFFFF,
        capabilities: int = CAPABILITY.IMPORT_WRAPPED
        | CAPABILITY.EXPORT_WRAPPED,
        delegated_capabilities: int = (1 << 64) - 1,
    ) -> bytes:
        key = key or os.urandom(32)
        self._store(
            StoredObject(
                object_id,
                OBJECT.WRAP_KEY,
                ALGORITHM.AES256_CCM_WRAP,
                b"",
                domains,
                capabilities,
                delegated_capabilities,
                key,
            ),
        )
        return key

    def put_asymmetric_key(
        self,
        object_id: int,
        label: str = "",
        *,
        domains: int = 0xFFFF,
        capabilities: int = CAPABILITY.SIGN_PKCS
        | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        key: rsa.RSAPrivateKey | None = None,
    ) -> rsa.RSAPrivateKey:
        key = key or rsa.generate_private_key(65537, 2048)
        self._store(
            StoredObject(
                object_id,
                OBJECT.ASYMMETRIC_KEY,
                _RSA_ALGORITHMS[key.key_size],
                label.encode(),
                domains,
                capabilities,
                0,
                _private_der(key),
                ORIGIN.GENERATED,
            ),
        )
        return key

    def put_certificate(
        self,
        object_id: int,
        certificate: x509.Certificate,
        label: str = "",
        *,
        domains: int = 0xFFFF,
        capabilities: int = 0,
    ) -> None:
        self._store(
            StoredObject(
                object_id,
                OBJECT.OPAQUE,
                ALGORITHM.OPAQUE_X509_CERTIFICATE,
                label.encode(),
                domains,
                capabilities,
                0,
                certificate.public_bytes(serialization.Encoding.DER),
            ),
        )

    def wrapped(
        self,
        object_id: int,
        object_type: OBJECT,
        wrap_id: int,
    ) -> bytes:
        """Return an object as EXPORT_WRAPPED under a wrap key would."""
        wrap_key = self.objects[(wrap_id, OBJECT.WRAP_KEY)]
        obj = self.objects[(object_id, object_type)]
        nonce = os.urandom(13)
        return nonce + AESCCM(wrap_key.data, tag_length=16).encrypt(
            nonce,
            obj.info() + _wrap_payload(obj),
            None,
        )

    def unwrap(self, blob: bytes, wrap_id: int) -> tuple[int, OBJECT]:
        """Return the ID and type of the object a wrapped blob holds."""
        wrap_key = self.objects[(wrap_id, OBJECT.WRAP_KEY)]
        plain = AESCCM(wrap_key.data, tag_length=16).decrypt(
            blob[:13],
            blob[13:],
            None,
        )
        fields = struct.unpack(_INFO_FORMAT, plain[:_INFO_LENGTH])
        return fields[1], OBJECT(fields[4])

    def storage(self) -> tuple[int, int]:
        """Return the free record and page counts."""
        used_pages = sum(
            max(1, -(-len(obj.data) // _PAGE_SIZE))
            for obj in self.objects.values()
        )
        return (
            self.total_records - len(self.objects),
            self.total_pages - used_pages,
        )

    def unread_log(self) -> list[tuple[int, bytes, bytes]]:
        return [entry for entry in self.log if entry[0] > self.log_index]

    def _store(self, obj: StoredObject) -> None:
        self.objects[(obj.object_id, obj.object_type)] = obj

    def _append_log(
        self,
        command: int,
        length: int,
        session_key: int,
        target_key: int,
        second_key: int,
        result: int,
    ) -> None:
        self.log_number = (self.log_number + 1) & 0xFFFF
        self.tick += 1
        data = struct.pack(
            "!HBHHHHBL",
            self.log_number,
            command,
            length,
            session_key,
            target_key,
            second_key,
            result,
            self.tick,
        )
        self.last_digest = sha256(data + self.last_digest).digest()[:16]
        self.log.append((self.log_number, data, self.last_digest))
        self.log = self.log[-LOG_SIZE:]

    def _audited(self, command: int) -> bool:
        return self.command_audit.get(command, AUDIT.OFF) != AUDIT.OFF

    def transceive(self, message: bytes) -> bytes:
        try:
            command, length = struct.unpack("!BH", message[:3])
            payload = message[3 : 3 + length]
            if command == COMMAND.DEVICE_INFO:
                return _response(command, self._device_info(payload))
            if command == COMMAND.GET_DEVICE_PUBLIC_KEY:
                point = self.device_key.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                return _response(
                    command,
                    bytes([ALGORITHM.EC_P256_YUBICO_AUTHENTICATION])
                    + point[1:],
                )
            if command == COMMAND.CREATE_SESSION:
                return _response(command, self._create_session(payload))
            if command == COMMAND.AUTHENTICATE_SESSION:
                return self._authenticate_session(message)
            if command == COMMAND.SESSION_MESSAGE:
                return self._session_message(message)
            raise DeviceError(ERROR.INVALID_COMMAND)
        except DeviceError as error:
            return _error(error.code)
        except (KeyError, ValueError, IndexError, struct.error):
            return _error(ERROR.INVALID_DATA)

    def _device_info(self, payload: bytes) -> bytes:
        if payload == b"\x01":
            return self.part_number.encode()
        return struct.pack(
            "!BBBIBB",
            *self.version,
            self.serial,
            LOG_SIZE,
            len(self.unread_log()),
        ) + bytes(sorted(ALGORITHM))

    def _new_session_id(self) -> int:
        for sid in range(16):
            if sid not in self.sessions:
                return sid
        raise DeviceError(ERROR.SESSIONS_FULL)

    def _create_session(self, payload: bytes) -> bytes:
        (authkey_id,) = struct.unpack("!H", payload[:2])
        authkey = self.get(authkey_id, OBJECT.AUTHENTICATION_KEY)
        if authkey is None:
            raise DeviceError(ERROR.OBJECT_NOT_FOUND)
        sid = self._new_session_id()
        self.sessions_opened += 1
        if authkey.algorithm == ALGORITHM.AES128_YUBICO_AUTHENTICATION:
            if len(payload) != 10:
                raise DeviceError(ERROR.INVALID_DATA)
            card_challenge = os.urandom(8)
            context = payload[2:] + card_challenge
            key_enc, key_mac = authkey.data[:16], authkey.data[16:]
            session = _Session(
                authkey,
                _derive(key_enc, 0x04, context),
                _derive(key_mac, 0x06, context),
                _derive(key_mac, 0x07, context),
                b"\0" * 16,
                authenticated=False,
                context=context,
            )
            self.sessions[sid] = session
            return (
                bytes([sid])
                + card_challenge
                + _derive(session.key_mac, 0x00, context, 0x40)
            )
        epk_oce = payload[2:]
        authkey_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b"\x04" + authkey.data,
        )
        oce_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            epk_oce,
        )
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        epk_hsm = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        shsss = self.device_key.exchange(ec.ECDH(), authkey_public)
        shsee = ephemeral.exchange(ec.ECDH(), oce_public)
        shs = X963KDF(hashes.SHA256(), 64, b"\x3c\x88\x10").derive(
            shsee + shsss,
        )
        keys = [shs[i : i + 16] for i in range(0, 64, 16)]
        receipt = _cmac(keys[0], epk_hsm, epk_oce)
        self.sessions[sid] = _Session(
            authkey,
            keys[1],
            keys[2],
            keys[3],
            receipt,
            authenticated=True,
        )
        return bytes([sid]) + epk_hsm + receipt

    def _authenticate_session(self, message: bytes) -> bytes:
        sid = message[3]
        session = self.sessions.get(sid)
        if session is None or session.authenticated:
            raise DeviceError(ERROR.INVALID_SESSION)
        host_cryptogram = message[4:12]
        chain = _cmac(session.key_mac, b"\0" * 16, message[:-8])
        expected = _derive(session.key_mac, 0x01, session.context, 0x40)
        if host_cryptogram != expected or message[-8:] != chain[:8]:
            del self.sessions[sid]
            raise DeviceError(ERROR.AUTHENTICATION_FAILED)
        session.mac_chain = chain
        session.authenticated = True
        return _response(COMMAND.AUTHENTICATE_SESSION, b"")

    def _session_message(self, message: bytes) -> bytes:
        sid = message[3]
        session = self.sessions.get(sid)
        if session is None or not session.authenticated:
            raise DeviceError(ERROR.INVALID_SESSION)
        chain = _cmac(session.key_mac, session.mac_chain, message[:-8])
        if message[-8:] != chain[:8]:
            raise DeviceError(ERROR.AUTHENTICATION_FAILED)
        iv = _iv(session.key_enc, session.counter)
        decryptor = Cipher(
            algorithms.AES(session.key_enc),
            modes.CBC(iv),
        ).decryptor()
        inner = decryptor.update(message[4:-8]) + decryptor.finalize()
        command, length = struct.unpack("!BH", inner[:3])
        payload = inner[3 : 3 + length]

        target = (0xFFFF, 0xFFFF)
        try:
            pending = self.failures.get(command)
            if pending:
                raise DeviceError(pending.pop(0))
            data, target = self._dispatch(session, sid, command, payload)
            self.history.append((time.time(), command, target))
            reply = _response(command, data)
            result = command | 0x80
        except DeviceError as error:
            reply = _error(error.code)
            result = COMMAND.ERROR
        except (KeyError, ValueError, IndexError, struct.error):
            reply = _error(ERROR.INVALID_DATA)
            result = COMMAND.ERROR
        if self._audited(command) and not (
            result == COMMAND.ERROR and reply[3] == ERROR.LOG_FULL
        ):
            self._append_log(
                command,
                length,
                session.authkey.object_id,
                *target,
                result,
            )

        padded = reply + b"\x80"
        padded += b"\0" * (-len(padded) % 16)
        encryptor = Cipher(
            algorithms.AES(session.key_enc),
            modes.CBC(iv),
        ).encryptor()
        body = encryptor.update(padded) + encryptor.finalize()
        response = (
            struct.pack(
                "!BHB",
                COMMAND.SESSION_MESSAGE | 0x80,
                1 + len(body) + 8,
                sid,
            )
            + body
        )
        response += _cmac(session.key_rmac, chain, response)[:8]
        session.mac_chain = chain
        session.counter += 1
        if command == COMMAND.CLOSE_SESSION:
            self.sessions.pop(sid, None)
        if command == COMMAND.RESET_DEVICE and result != COMMAND.ERROR:
            self.resets += 1
            self.factory_reset()
        return response

    def _require(self, session: _Session, capability: CAPABILITY) -> None:
        if not session.authkey.capabilities & capability:
            raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)

    def _require_delegable(
        self,
        session: _Session,
        domains: int,
        *capabilities: int,
    ) -> None:
        if domains & ~session.authkey.domains:
            raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
        for capability in capabilities:
            if capability & ~session.authkey.delegated_capabilities:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)

    def _visible(
        self,
        session: _Session,
        object_id: int,
        object_type: OBJECT,
    ) -> StoredObject:
        obj = self.get(object_id, object_type)
        if obj is None or not obj.domains & session.authkey.domains:
            raise DeviceError(ERROR.OBJECT_NOT_FOUND)
        return obj

    def _new_object(self, session: _Session, obj: StoredObject) -> int:
        if obj.object_id == 0:
            obj.object_id = next(
                i
                for i in range(1, 0xFFFF)
                if (i, obj.object_type) not in self.objects
            )
        if self.get(obj.object_id, obj.object_type) is not None:
            raise DeviceError(ERROR.OBJECT_EXISTS)
        self._require_delegable(
            session,
            obj.domains,
            obj.capabilities,
            obj.delegated_capabilities,
        )
        self._store(obj)
        return obj.object_id

    def _dispatch(
        self,
        session: _Session,
        sid: int,
        command: int,
        payload: bytes,
    ) -> tuple[bytes, tuple[int, int]]:
        if (
            self.force_audit != AUDIT.OFF
            and self._audited(command)
            and len(self.unread_log()) >= LOG_SIZE
        ):
            raise DeviceError(ERROR.LOG_FULL)
        none = (0xFFFF, 0xFFFF)
        if command == COMMAND.CLOSE_SESSION:
            return b"", none
        if command == COMMAND.RESET_DEVICE:
            self._require(session, CAPABILITY.RESET_DEVICE)
            return b"", none
        if command == COMMAND.GET_PSEUDO_RANDOM:
            self._require(session, CAPABILITY.GET_PSEUDO_RANDOM)
            (length,) = struct.unpack("!H", payload)
            return os.urandom(length), none
        if command == COMMAND.SET_OPTION:
            self._require(session, CAPABILITY.SET_OPTION)
            self._set_option(payload)
            return b"", none
        if command == COMMAND.GET_OPTION:
            self._require(session, CAPABILITY.GET_OPTION)
            return self._get_option(payload), none
        if command == COMMAND.GET_LOG_ENTRIES:
            self._require(session, CAPABILITY.GET_LOG_ENTRIES)
            entries = self.unread_log()
            return (
                struct.pack("!HHB", 0, 0, len(entries))
                + b"".join(data + digest for _, data, digest in entries),
                none,
            )
        if command == COMMAND.SET_LOG_INDEX:
            self._require(session, CAPABILITY.GET_LOG_ENTRIES)
            (self.log_index,) = struct.unpack("!H", payload)
            return b"", none
        if command == COMMAND.LIST_OBJECTS:
            return self._list_objects(session, payload), none
        if command == COMMAND.GET_STORAGE_INFO:
            free_records, free_pages = self.storage()
            return (
                struct.pack(
                    "!5H",
                    self.total_records,
                    free_records,
                    self.total_pages,
                    free_pages,
                    _PAGE_SIZE,
                ),
                none,
            )
        if command == COMMAND.GET_PUBLIC_KEY:
            (object_id,) = struct.unpack("!H", payload[:2])
            obj = self._visible(session, object_id, OBJECT.ASYMMETRIC_KEY)
            public = _load_key(obj.data).public_key()
            size = public.key_size // 8
            return (
                bytes([obj.algorithm])
                + public.public_numbers().n.to_bytes(size, "big"),
                (object_id, 0xFFFF),
            )
        if command == COMMAND.SIGN_ATTESTATION_CERTIFICATE:
            self._require(session, CAPABILITY.SIGN_ATTESTATION_CERTIFICATE)
            object_id, attesting_id = struct.unpack("!HH", payload)
            self._visible(session, object_id, OBJECT.ASYMMETRIC_KEY)
            if attesting_id != 0:
                attesting = self._visible(
                    session,
                    attesting_id,
                    OBJECT.ASYMMETRIC_KEY,
                )
                if not attesting.capabilities & (
                    CAPABILITY.SIGN_ATTESTATION_CERTIFICATE
                ):
                    raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
                self._visible(session, attesting_id, OBJECT.OPAQUE)
            return (
                self.attest(object_id, attesting_id).public_bytes(
                    serialization.Encoding.DER,
                ),
                (object_id, attesting_id),
            )
        if command == COMMAND.GET_OBJECT_INFO:
            object_id, object_type = struct.unpack("!HB", payload)
            obj = self._visible(session, object_id, OBJECT(object_type))
            return obj.info(), (object_id, 0xFFFF)
        if command == COMMAND.DELETE_OBJECT:
            object_id, object_type = struct.unpack("!HB", payload)
            object_type = OBJECT(object_type)
            self._require(session, _DELETE_CAPABILITY[object_type])
            self._visible(session, object_id, object_type)
            del self.objects[(object_id, object_type)]
            return b"", (object_id, 0xFFFF)
        if command == COMMAND.GET_OPAQUE:
            self._require(session, CAPABILITY.GET_OPAQUE)
            (object_id,) = struct.unpack("!H", payload)
            if object_id == 0:
                return (
                    self.attestation_certificate.public_bytes(
                        serialization.Encoding.DER,
                    ),
                    (0, 0xFFFF),
                )
            return self._visible(session, object_id, OBJECT.OPAQUE).data, (
                object_id,
                0xFFFF,
            )
        if command == COMMAND.PUT_OPAQUE:
            self._require(session, CAPABILITY.PUT_OPAQUE)
            object_id, label, domains, capabilities, algorithm = struct.unpack(
                _PUT_DATA_FORMAT,
                payload[:53],
            )
            new_id = self._new_object(
                session,
                StoredObject(
                    object_id,
                    OBJECT.OPAQUE,
                    ALGORITHM(algorithm),
                    label,
                    domains,
                    capabilities,
                    0,
                    payload[53:],
                ),
            )
            return struct.pack("!H", new_id), (new_id, 0xFFFF)
        if command in (COMMAND.PUT_WRAP_KEY, COMMAND.PUT_AUTHENTICATION_KEY):
            needed = (
                CAPABILITY.PUT_WRAP_KEY
                if command == COMMAND.PUT_WRAP_KEY
                else CAPABILITY.PUT_AUTHENTICATION_KEY
            )
            self._require(session, needed)
            fields = struct.unpack(_PUT_FORMAT, payload[:61])
            object_id, label, domains, capabilities, algorithm, delegated = (
                fields
            )
            algorithm = ALGORITHM(algorithm)
            key = payload[61:]
            if command == COMMAND.PUT_WRAP_KEY:
                if len(key) != algorithm.to_key_size():
                    raise DeviceError(ERROR.INVALID_DATA)
                object_type = OBJECT.WRAP_KEY
            else:
                expected = {
                    ALGORITHM.AES128_YUBICO_AUTHENTICATION: 32,
                    ALGORITHM.EC_P256_YUBICO_AUTHENTICATION: 64,
                }.get(algorithm)
                if len(key) != expected:
                    raise DeviceError(ERROR.INVALID_DATA)
                object_type = OBJECT.AUTHENTICATION_KEY
            new_id = self._new_object(
                session,
                StoredObject(
                    object_id,
                    object_type,
                    algorithm,
                    label,
                    domains,
                    capabilities,
                    delegated,
                    key,
                ),
            )
            return struct.pack("!H", new_id), (new_id, 0xFFFF)
        if command == COMMAND.GENERATE_ASYMMETRIC_KEY:
            self._require(session, CAPABILITY.GENERATE_ASYMMETRIC_KEY)
            object_id, label, domains, capabilities, algorithm = struct.unpack(
                _PUT_DATA_FORMAT,
                payload,
            )
            sizes = {value: size for size, value in _RSA_ALGORITHMS.items()}
            if algorithm not in sizes:
                raise DeviceError(ERROR.INVALID_DATA)
            generated = _generated_rsa_key(sizes[algorithm])
            new_id = self._new_object(
                session,
                StoredObject(
                    object_id,
                    OBJECT.ASYMMETRIC_KEY,
                    ALGORITHM(algorithm),
                    label,
                    domains,
                    capabilities,
                    0,
                    _private_der(generated),
                    ORIGIN.GENERATED,
                ),
            )
            return struct.pack("!H", new_id), (new_id, 0xFFFF)
        if command == COMMAND.EXPORT_WRAPPED:
            self._require(session, CAPABILITY.EXPORT_WRAPPED)
            wrap_id, object_type, object_id = struct.unpack("!HBH", payload[:5])
            wrap_key = self._visible(session, wrap_id, OBJECT.WRAP_KEY)
            obj = self._visible(session, object_id, OBJECT(object_type))
            if not wrap_key.capabilities & CAPABILITY.EXPORT_WRAPPED:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            if not obj.capabilities & CAPABILITY.EXPORTABLE_UNDER_WRAP:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            if obj.capabilities & ~wrap_key.delegated_capabilities:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            nonce = os.urandom(13)
            sealed = AESCCM(wrap_key.data, tag_length=16).encrypt(
                nonce,
                obj.info() + _wrap_payload(obj),
                None,
            )
            return nonce + sealed, (wrap_id, object_id)
        if command == COMMAND.IMPORT_WRAPPED:
            self._require(session, CAPABILITY.IMPORT_WRAPPED)
            (wrap_id,) = struct.unpack("!H", payload[:2])
            wrap_key = self._visible(session, wrap_id, OBJECT.WRAP_KEY)
            if not wrap_key.capabilities & CAPABILITY.IMPORT_WRAPPED:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            try:
                plain = AESCCM(wrap_key.data, tag_length=16).decrypt(
                    payload[2:15],
                    payload[15:],
                    None,
                )
            except Exception:
                raise DeviceError(ERROR.INVALID_DATA) from None
            fields = struct.unpack(_INFO_FORMAT, plain[:_INFO_LENGTH])
            (
                capabilities,
                object_id,
                _,
                domains,
                object_type,
                algorithm,
                sequence,
                origin,
                label,
                delegated,
            ) = fields
            if capabilities & ~wrap_key.delegated_capabilities:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            obj = StoredObject(
                object_id,
                OBJECT(object_type),
                ALGORITHM(algorithm),
                label,
                domains,
                capabilities,
                delegated,
                _unwrap_payload(OBJECT(object_type), plain[_INFO_LENGTH:]),
                ORIGIN(origin | ORIGIN.IMPORTED_WRAPPED),
                sequence,
            )
            if self.get(object_id, obj.object_type) is not None:
                raise DeviceError(ERROR.OBJECT_EXISTS)
            self._store(obj)
            return struct.pack("!BH", object_type, object_id), (
                wrap_id,
                object_id,
            )
        if command == COMMAND.SIGN_PKCS1:
            self._require(session, CAPABILITY.SIGN_PKCS)
            (object_id,) = struct.unpack("!H", payload[:2])
            obj = self._visible(session, object_id, OBJECT.ASYMMETRIC_KEY)
            if not obj.capabilities & CAPABILITY.SIGN_PKCS:
                raise DeviceError(ERROR.INSUFFICIENT_PERMISSIONS)
            digest = payload[2:]
            for prefix, size in _DIGEST_INFO_PREFIXES.items():
                if len(digest) == len(prefix) + size and digest.startswith(
                    prefix,
                ):
                    digest = digest[len(prefix) :]
            if len(digest) not in _DIGEST_HASHES:
                raise DeviceError(ERROR.INVALID_DATA)
            signing_key = _load_key(obj.data)
            signature = signing_key.sign(
                digest,
                padding.PKCS1v15(),
                Prehashed(_DIGEST_HASHES[len(digest)]()),
            )
            if self.corrupt_signatures:
                signature = bytes(len(signature))
            return signature, (object_id, 0xFFFF)
        raise DeviceError(ERROR.INVALID_COMMAND)

    def _list_objects(self, session: _Session, payload: bytes) -> bytes:
        filters: dict[int, int] = {}
        label: bytes | None = None
        index = 0
        sizes: dict[int, int] = {
            LIST_FILTER.ID: 2,
            LIST_FILTER.TYPE: 1,
            LIST_FILTER.DOMAINS: 2,
            LIST_FILTER.CAPABILITIES: 8,
            LIST_FILTER.ALGORITHM: 1,
            LIST_FILTER.LABEL: LABEL_LENGTH,
        }
        while index < len(payload):
            kind = payload[index]
            size = sizes[kind]
            value = payload[index + 1 : index + 1 + size]
            if kind == LIST_FILTER.LABEL:
                label = value
            else:
                filters[kind] = int.from_bytes(value)
            index += 1 + size
        listed = b""
        for obj in sorted(
            self.objects.values(),
            key=lambda o: (o.object_id, o.object_type),
        ):
            if not obj.domains & session.authkey.domains:
                continue
            if (
                filters.get(LIST_FILTER.ID, obj.object_id) != obj.object_id
                or filters.get(LIST_FILTER.TYPE, obj.object_type)
                != obj.object_type
                or filters.get(LIST_FILTER.ALGORITHM, obj.algorithm)
                != obj.algorithm
                or not filters.get(LIST_FILTER.DOMAINS, 0xFFFF) & obj.domains
                or (
                    LIST_FILTER.CAPABILITIES in filters
                    and not filters[LIST_FILTER.CAPABILITIES] & obj.capabilities
                )
                or (
                    label is not None
                    and label.rstrip(b"\0") != obj.label.rstrip(b"\0")
                )
            ):
                continue
            listed += struct.pack(
                "!HBB",
                obj.object_id,
                obj.object_type,
                obj.sequence,
            )
        return listed

    def _get_option(self, payload: bytes) -> bytes:
        (option,) = struct.unpack("!B", payload)
        if option == OPTION.FORCE_AUDIT:
            return bytes([self.force_audit])
        if option == OPTION.COMMAND_AUDIT:
            return b"".join(
                bytes([command, self.command_audit.get(command, AUDIT.OFF)])
                for command in sorted(COMMAND)
                if command not in (COMMAND.ERROR,)
            )
        raise DeviceError(ERROR.INVALID_DATA)

    def _set_option(self, payload: bytes) -> None:
        option, length = struct.unpack("!BH", payload[:3])
        value = payload[3 : 3 + length]
        if option == OPTION.FORCE_AUDIT:
            if len(value) != 1:
                raise DeviceError(ERROR.INVALID_DATA)
            if self.force_audit == AUDIT.FIXED:
                raise DeviceError(ERROR.INVALID_DATA)
            self.force_audit = AUDIT(value[0])
        elif option == OPTION.COMMAND_AUDIT:
            if not value or len(value) % 2:
                raise DeviceError(ERROR.INVALID_DATA)
            pairs = [
                (value[i], AUDIT(value[i + 1])) for i in range(0, len(value), 2)
            ]
            for command, _ in pairs:
                if self.command_audit.get(command) == AUDIT.FIXED:
                    raise DeviceError(ERROR.INVALID_DATA)
            self.command_audit.update(pairs)
        else:
            raise DeviceError(ERROR.INVALID_DATA)

    def attest(self, object_id: int, attesting_id: int = 0) -> x509.Certificate:
        """Issue an attestation certificate for an asymmetric key as the
        device does, with the key's label as a DER UTF8String. A nonzero
        attesting_id signs with that asymmetric key, under the subject of
        the certificate stored with the same ID."""
        if attesting_id:
            signer = _load_key(
                self.objects[(attesting_id, OBJECT.ASYMMETRIC_KEY)].data,
            )
            issuer = stored_certificate(
                self.objects[(attesting_id, OBJECT.OPAQUE)],
            ).subject
        else:
            signer = self.attestation_key
            issuer = self.attestation_certificate.subject
        obj = self.objects[(object_id, OBJECT.ASYMMETRIC_KEY)]
        key = _load_key(obj.data)
        label = obj.label.rstrip(b"\0")

        def extension(index: int, value: bytes) -> x509.UnrecognizedExtension:
            return x509.UnrecognizedExtension(
                x509.ObjectIdentifier(_ATTESTATION_OID.format(index)),
                value,
            )

        def integer(value: int, size: int) -> bytes:
            return bytes([0x02, size]) + value.to_bytes(size, "big")

        now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            x509.NameOID.COMMON_NAME,
                            f"YubiHSM Attestation id:{object_id:#06x}",
                        ),
                    ],
                ),
            )
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(object_id)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=36500))
        )
        for index, value in (
            (1, bytes([0x04, 3, *self.version])),
            (2, integer(self.serial, 4)),
            (3, integer(obj.origin, 1)),
            (4, integer(obj.domains, 2)),
            (5, integer(obj.capabilities, 8)),
            (6, integer(object_id, 2)),
            (9, bytes([0x0C, len(label)]) + label),
        ):
            builder = builder.add_extension(extension(index, value), False)
        return builder.sign(signer, hashes.SHA256())


_KEY_POOL = Path(__file__).parent / "fixtures" / "rsa"
_key_pool_lock = threading.Lock()
_key_pool_used: dict[int, int] = {}


def _generated_rsa_key(bits: int) -> rsa.RSAPrivateKey:
    """
    Take the next unused fixtures/rsa/emulated-<bits>-<n>.pem, so that a
    test process gets distinct keys without paying for slow generation,
    and generate a key once the pool runs out.
    """
    with _key_pool_lock:
        index = _key_pool_used.get(bits, 0)
        pooled = _KEY_POOL / f"emulated-{bits}-{index}.pem"
        if pooled.is_file():
            _key_pool_used[bits] = index + 1
            key = serialization.load_pem_private_key(
                pooled.read_bytes(),
                None,
                unsafe_skip_rsa_key_validation=True,
            )
            assert isinstance(key, rsa.RSAPrivateKey)
            return key
    return rsa.generate_private_key(65537, bits)


def _load_key(data: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_der_private_key(
        data,
        None,
        unsafe_skip_rsa_key_validation=True,
    )
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def _private_der(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _wrap_payload(obj: StoredObject) -> bytes:
    if obj.object_type != OBJECT.ASYMMETRIC_KEY:
        return obj.data
    numbers = _load_key(obj.data).private_numbers()
    size = numbers.public_numbers.n.bit_length() // 16
    return numbers.p.to_bytes(size, "big") + numbers.q.to_bytes(size, "big")


def _unwrap_payload(object_type: OBJECT, data: bytes) -> bytes:
    if object_type != OBJECT.ASYMMETRIC_KEY:
        return data
    half = len(data) // 2
    p = int.from_bytes(data[:half], "big")
    q = int.from_bytes(data[half:], "big")
    e = 65537
    d = rsa.rsa_recover_private_exponent(e, p, q)
    numbers = rsa.RSAPrivateNumbers(
        p,
        q,
        d,
        rsa.rsa_crt_dmp1(d, p),
        rsa.rsa_crt_dmq1(d, q),
        rsa.rsa_crt_iqmp(p, q),
        rsa.RSAPublicNumbers(e, p * q),
    )
    return _private_der(numbers.private_key())


def stored_certificate(obj: StoredObject) -> x509.Certificate:
    data = obj.data
    try:
        data = gzip.decompress(data)
    except gzip.BadGzipFile:
        pass
    return x509.load_der_x509_certificate(data)


class Connector:
    """
    A stand-in for yubihsm-connector that forwards every request to the
    device currently plugged in.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.plugged: EmulatedYubiHsm | None = None
        self.lock = threading.Lock()

    @property
    def device(self) -> EmulatedYubiHsm:
        """The plugged-in device, for tests that expect one."""
        if self.plugged is None:
            raise RuntimeError("no emulated YubiHSM is plugged in")
        return self.plugged

    def plug(self, device: EmulatedYubiHsm | None) -> None:
        with self.lock:
            self.plugged = device


@contextlib.contextmanager
def serve_connector() -> Generator[Connector, None, None]:
    """Serve a Connector on a free local port for the duration."""
    connector: Connector

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?")[0] != "/connector/status":
                self.send_error(404)
                return
            with connector.lock:
                device = connector.plugged
            status = "OK" if device else "NO_DEVICE"
            serial = f"{device.serial:010d}" if device else "*"
            body = (
                f"status={status}\nserial={serial}\nversion=3.0.4\n"
                f"pid={os.getpid()}\naddress=127.0.0.1\n"
                f"port={server.server_address[1]}\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            with connector.lock:
                device = connector.plugged
                reply = device.transceive(body) if device else None
            if reply is None:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    connector = Connector(f"http://127.0.0.1:{server.server_address[1]}")
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield connector
    finally:
        server.shutdown()
        server.server_close()
