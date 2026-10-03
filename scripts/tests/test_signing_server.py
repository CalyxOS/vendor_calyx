#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import hashlib
import os
import socket
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from openssl_shim import generate_rsa_key, helper_env, write_openssl_pkcs11_shim
from signing import signing_server
from signing.signing_server import Message, SigningServer, request
from signing.vendor_yubihsm import YubiHsmConfig
from signing.yubihsm_session_service import YubiHsmSessionService
from software_rsa import rsa_key, verifies
from yubihsm.defs import COMMAND
from yubihsm_emulator import Connector, EmulatedYubiHsm

HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.server.py"
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420",
)


class _Handler:
    def __init__(self, response: Message | Exception) -> None:
        self.response = response
        self.requests: list[Message] = []
        self.closed = 0

    def handle(self, request: Message) -> Message:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed += 1


def test_request_reaches_the_handler_for_its_op(tmp_path: Path) -> None:
    handler = _Handler({"status": "ok", "value": 1})
    server = SigningServer(tmp_path / "s.sock", {"a": handler, "b": handler})
    with server:
        response = request(server.socket_path, "a", field="x")

    assert response == {"status": "ok", "value": 1}
    assert handler.requests == [{"op": "a", "field": "x"}]
    assert handler.closed == 1
    assert not server.socket_path.exists()


@pytest.mark.parametrize(
    "handler",
    [_Handler({"status": "unavailable"}), _Handler(RuntimeError("boom"))],
)
def test_request_without_an_ok_response_is_none(
    tmp_path: Path,
    handler: _Handler,
) -> None:
    server = SigningServer(tmp_path / "s.sock", {"a": handler})
    with server:
        assert request(server.socket_path, "a") is None
        assert request(server.socket_path, "unknown") is None


def test_request_without_a_server_is_none(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert request(tmp_path / "missing.sock", "a") is None
    assert "could not reach the signing server" in capsys.readouterr().err


def _service(
    yubihsm: Connector,
    audit_log_path: Path | None = None,
) -> YubiHsmSessionService:
    return YubiHsmSessionService(
        YubiHsmConfig(yubihsm.url, "0x0001", "password"),
        audit_log_path=audit_log_path,
    )


def _sign_request(key_id: int, digest: bytes) -> Message:
    return {
        "op": "yubihsm_sign_pkcs1",
        "key_id": key_id,
        "digest": base64.b64encode(digest).decode(),
    }


def test_sign_uses_one_session_and_verifies(yubihsm: Connector) -> None:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    service = _service(yubihsm)
    digest = hashlib.sha256(b"payload").digest()

    for _ in range(3):
        response = service.handle(_sign_request(0x2000, digest))
        rsa_key("service").public_key().verify(
            base64.b64decode(response["signature"]),
            b"payload",
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    assert yubihsm.device.sessions_opened == 1
    service.close()
    assert yubihsm.device.sessions == {}


def test_sign_reopens_an_expired_session(yubihsm: Connector) -> None:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    service = _service(yubihsm)
    sign = _sign_request(0x2000, hashlib.sha256(b"x").digest())
    service.handle(sign)
    yubihsm.device.drop_sessions()

    response = service.handle(sign)

    assert response["status"] == "ok"
    assert yubihsm.device.sessions_opened == 2


def test_sign_rejects_a_signature_that_does_not_verify(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    yubihsm.device.corrupt_signatures = True
    service = _service(yubihsm)

    with pytest.raises(InvalidSignature):
        service.handle(_sign_request(0x2000, hashlib.sha256(b"x").digest()))


def test_extract_audit_log_keeps_the_session_open(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    for comment in ("first", "second"):
        response = service.handle(
            {
                "op": "yubihsm_extract_audit_log",
                "log_path": str(log_path),
                "comment": comment,
            },
        )
        assert response == {"status": "ok"}

    assert yubihsm.device.sessions_opened == 1
    assert len(yubihsm.device.sessions) == 1
    assert yubihsm.device.unread_log() == []
    text = log_path.read_text()
    assert " first\n" in text and " second\n" in text


def test_extract_audit_log_retry_writes_the_entries_once(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    yubihsm.device.fail_next(COMMAND.SET_LOG_INDEX)
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    response = service.handle(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(log_path),
            "comment": "once",
        },
    )

    assert response == {"status": "ok"}
    assert yubihsm.device.sessions_opened == 2
    assert yubihsm.device.unread_log() == []
    assert len(log_path.read_text().splitlines()) == 2


INTERCEPTOR = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.py"


def _avb_input(message: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(message).digest()
    digest_info = SHA256_DIGEST_INFO_PREFIX + digest
    block = b"\x00\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\x00"
    return block + digest_info, digest


@pytest.fixture
def yubihsm_server(
    tmp_path: Path,
    yubihsm: Connector,
) -> Iterator[tuple[SigningServer, EmulatedYubiHsm]]:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("server-a"))
    yubihsm.device.put_asymmetric_key(0x2100, key=rsa_key("server-b"))
    service = _service(yubihsm, tmp_path / "audit.log")
    server = SigningServer(
        tmp_path / "s.sock",
        {
            "yubihsm_sign_pkcs1": service,
            "yubihsm_extract_audit_log": service,
        },
    )
    with server:
        yield server, yubihsm.device


def _without_signing_variables() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("YUBIHSM_", "KEY_ID", "SIGNING_SERVER"))
    }


def test_helper_signs_with_the_server_key_its_path_names(
    tmp_path: Path,
    yubihsm_server: tuple[SigningServer, EmulatedYubiHsm],
) -> None:
    server, _ = yubihsm_server
    data, digest = _avb_input(b"image")
    key_file = _public_key_file(tmp_path / "keys", "0x2100", "server-b")

    result = subprocess.run(
        [HELPER, "SHA256_RSA2048", key_file],
        env={
            **_without_signing_variables(),
            "SIGNING_SERVER_SOCKET": str(server.socket_path),
            "KEY_DIR": f"{tmp_path / 'keys'}/",
        },
        input=data,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert verifies(rsa_key("server-b"), result.stdout, digest)
    assert not verifies(rsa_key("server-a"), result.stdout, digest)


def _openssl_fallback_env(tmp_path: Path) -> tuple[dict[str, str], Path]:
    private_key = generate_rsa_key(tmp_path, 2048)
    environment = {
        **_without_signing_variables(),
        **helper_env(write_openssl_pkcs11_shim(tmp_path), private_key),
        "SIGNING_SERVER_SOCKET": str(tmp_path / "none.sock"),
    }
    return environment, private_key


def _load_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def test_helper_signs_through_openssl_without_a_server(tmp_path: Path) -> None:
    environment, private_key = _openssl_fallback_env(tmp_path)
    data, digest = _avb_input(b"image")

    result = subprocess.run(
        [HELPER, "SHA256_RSA2048", "keys/0x2000.pem"],
        env=environment,
        input=data,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert verifies(_load_private_key(private_key), result.stdout, digest)


def test_interceptor_appends_the_audit_log_through_the_server(
    tmp_path: Path,
    yubihsm_server: tuple[SigningServer, EmulatedYubiHsm],
) -> None:
    server, device = yubihsm_server
    device.audit(COMMAND.SIGN_PKCS1)
    request(
        server.socket_path,
        "yubihsm_sign_pkcs1",
        key_id=0x2000,
        digest=base64.b64encode(hashlib.sha256(b"x").digest()).decode(),
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    avbtool = bin_dir / "avbtool"
    avbtool.write_text("#!/bin/sh\nexit 0\n")
    avbtool.chmod(avbtool.stat().st_mode | stat.S_IXUSR)
    audit_log = tmp_path / "audit.log"

    result = subprocess.run(
        [INTERCEPTOR, "add_hash_footer", "--signing_helper", "helper"],
        env={
            **_without_signing_variables(),
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "SIGNING_COMMAND": "avbtool",
            "AUDIT_LOG_PATH": str(audit_log),
            "SIGNING_SERVER_SOCKET": str(server.socket_path),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    comment, *entries = audit_log.read_text().splitlines()
    assert comment.startswith("# ")
    assert "add_hash_footer" in comment
    assert entries[-1].split()[1:3] == ["cmd:", "0x47"]
    assert "tKey: 0x2000" in entries[-1]
    assert device.unread_log() == []


def _public_key_file(directory: Path, name: str, key_name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.pem"
    path.write_bytes(
        rsa_key(key_name)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    return path


def test_helper_refuses_a_signature_its_public_key_does_not_verify(
    tmp_path: Path,
    yubihsm_server: tuple[SigningServer, EmulatedYubiHsm],
) -> None:
    server, _ = yubihsm_server
    data, _ = _avb_input(b"image")
    key_file = _public_key_file(tmp_path / "keys", "0x2100", "server-a")

    result = subprocess.run(
        [HELPER, "SHA256_RSA2048", key_file],
        env={
            **_without_signing_variables(),
            "SIGNING_SERVER_SOCKET": str(server.socket_path),
            "KEY_DIR": f"{tmp_path / 'keys'}/",
        },
        input=data,
        capture_output=True,
    )

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"does not verify under the supplied public key" in result.stderr


def test_a_client_that_never_finishes_its_request_does_not_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(signing_server, "_REQUEST_TIMEOUT", 0.2)
    handler = _Handler({"status": "ok"})
    server = SigningServer(tmp_path / "s.sock", {"a": handler})
    with server:
        stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stalled.connect(str(server.socket_path))
        stalled.sendall(b"{")
        response = request(server.socket_path, "a")
        stalled.close()

    assert response == {"status": "ok"}


def test_extract_audit_log_reports_entries_it_could_not_acknowledge(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    yubihsm.device.fail_next(COMMAND.SET_LOG_INDEX, times=2)
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    response = service.handle(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(log_path),
            "comment": "once",
        },
    )

    assert response["status"] == "ok"
    assert "could not acknowledge" in response["unacknowledged"]
    assert len(log_path.read_text().splitlines()) == 2


def test_extract_audit_log_refuses_another_log(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    service = _service(yubihsm, tmp_path / "audit.log")

    response = service.handle(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(tmp_path / "elsewhere.log"),
            "comment": "comment",
        },
    )

    assert response == {"status": "unavailable"}
    assert not (tmp_path / "elsewhere.log").exists()
