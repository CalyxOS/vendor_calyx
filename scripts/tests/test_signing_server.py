#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import hashlib
import os
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, install_executable, yubihsm_config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signing import signing_server
from signing.signing_server import Message, SigningServer, request
from signing.yubihsm_session_service import YubiHsmSessionService
from software_rsa import avb_input, der_public_key, rsa_key, verifies
from yubihsm.defs import COMMAND
from yubihsm_emulator import Connector, EmulatedYubiHsm

HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.py"


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
    server = SigningServer(tmp_path / "s.sock")
    server.add_service(
        {"a": handler.handle, "b": handler.handle},
        handler.close,
    )
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
    server = SigningServer(tmp_path / "s.sock")
    server.add_service({"a": handler.handle})
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
        yubihsm_config(yubihsm),
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
        response = service.sign(_sign_request(0x2000, digest))
        assert verifies(
            rsa_key("service"),
            base64.b64decode(response["signature"]),
            digest,
        )

    assert yubihsm.device.sessions_opened == 1
    service.close()
    assert yubihsm.device.sessions == {}


def test_sign_reopens_an_expired_session(yubihsm: Connector) -> None:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    service = _service(yubihsm)
    sign = _sign_request(0x2000, hashlib.sha256(b"x").digest())
    service.sign(sign)
    yubihsm.device.sessions.clear()

    response = service.sign(sign)

    assert response["status"] == "ok"
    assert yubihsm.device.sessions_opened == 2


def test_sign_leaves_the_signature_check_to_the_helper(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    yubihsm.device.corrupt_signatures = True
    service = _service(yubihsm)

    response = service.sign(
        _sign_request(0x2000, hashlib.sha256(b"x").digest()),
    )

    assert response["status"] == "ok"
    assert COMMAND.GET_PUBLIC_KEY not in [
        command for command, _ in yubihsm.device.history
    ]


def test_extract_audit_log_keeps_the_session_open(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    for comment in ("first", "second"):
        response = service.extract_audit_log(
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


def test_extract_audit_log_counts_entries_on_the_open_connection(
    monkeypatch: pytest.MonkeyPatch,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    from yubihsm.core import YubiHsm

    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("service"))
    yubihsm.device.audit(COMMAND.SIGN_PKCS1)
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)
    service.sign(_sign_request(0x2000, hashlib.sha256(b"x").digest()))

    def refuse(url: str | None = None) -> YubiHsm:
        raise AssertionError("the service connected again")

    monkeypatch.setattr(YubiHsm, "connect", staticmethod(refuse))
    response = service.extract_audit_log(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(log_path),
            "comment": "signed",
        },
    )

    assert response == {"status": "ok"}
    assert "tKey: 0x2000" in log_path.read_text()
    assert yubihsm.device.unread_log() == []


def test_extract_audit_log_leaves_an_empty_log_unread(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    yubihsm.device.log_index = yubihsm.device.log[-1][0]
    yubihsm.device.fail_next(COMMAND.GET_LOG_ENTRIES, times=2)
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    response = service.extract_audit_log(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(log_path),
            "comment": "empty",
        },
    )

    assert response == {"status": "ok"}
    assert len(yubihsm.device.failures[COMMAND.GET_LOG_ENTRIES]) == 2
    assert log_path.read_text().endswith(" empty\n")


@pytest.mark.parametrize(("failures", "acknowledged"), ((1, True), (2, False)))
def test_extract_audit_log_retry_writes_the_entries_once(
    yubihsm: Connector,
    tmp_path: Path,
    failures: int,
    acknowledged: bool,
) -> None:
    yubihsm.device.fail_next(COMMAND.SET_LOG_INDEX, times=failures)
    log_path = tmp_path / "audit.log"
    service = _service(yubihsm, log_path)

    response = service.extract_audit_log(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(log_path),
            "comment": "once",
        },
    )

    assert len(log_path.read_text().splitlines()) == 2
    if acknowledged:
        assert response == {"status": "ok"}
        assert yubihsm.device.sessions_opened == 2
        assert yubihsm.device.unread_log() == []
    else:
        assert response["status"] == "ok"
        assert "could not acknowledge" in response["unacknowledged"]


PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.py"
INTERCEPTOR = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.py"


def _avb_input(message: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(message).digest()
    return avb_input(digest), digest


@pytest.fixture
def yubihsm_server(
    tmp_path: Path,
    yubihsm: Connector,
) -> Iterator[tuple[SigningServer, EmulatedYubiHsm]]:
    yubihsm.device.put_asymmetric_key(0x2000, key=rsa_key("server-a"))
    yubihsm.device.put_asymmetric_key(0x2100, key=rsa_key("server-b"))
    service = _service(yubihsm, tmp_path / "audit.log")
    server = SigningServer(tmp_path / "s.sock")
    server.add_service(
        {
            "yubihsm_sign_pkcs1": service.sign,
            "yubihsm_extract_audit_log": service.extract_audit_log,
        },
        service.close,
    )
    with server:
        yield server, yubihsm.device


def _without_signing_variables() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("YUBIHSM_", "SIGNING_SERVER"))
    }


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


@pytest.mark.parametrize(
    ("key_name", "verified"),
    (("server-b", True), ("server-a", False)),
)
def test_helper_checks_the_server_signature_against_its_key(
    tmp_path: Path,
    yubihsm_server: tuple[SigningServer, EmulatedYubiHsm],
    key_name: str,
    verified: bool,
) -> None:
    server, _ = yubihsm_server
    data, digest = _avb_input(b"image")
    key_file = _public_key_file(tmp_path / "keys", "0x2100", key_name)

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

    if verified:
        assert result.returncode == 0, result.stderr
        assert verifies(rsa_key("server-b"), result.stdout, digest)
        assert not verifies(rsa_key("server-a"), result.stdout, digest)
    else:
        assert result.returncode != 0
        assert result.stdout == b""
        assert b"does not verify under the supplied public key" in result.stderr


def _softhsm_fallback(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> tuple[rsa.RSAPublicKey, dict[str, str]]:
    environment, public_der = softhsm_rsa_key
    public_key = der_public_key(public_der)
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "0x2000.pem").write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    return public_key, {
        **_without_signing_variables(),
        **environment,
        "SIGNING_SERVER_SOCKET": str(tmp_path / "none.sock"),
        "KEY_DIR": "keys/",
    }


def test_helper_falls_back_to_pkcs11_without_a_server(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    public_key, environment = _softhsm_fallback(tmp_path, softhsm_rsa_key)
    data, digest = _avb_input(b"image")

    result = subprocess.run(
        [HELPER, "SHA256_RSA2048", "keys/0x2000.pem"],
        cwd=tmp_path,
        env=environment,
        input=data,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert verifies(public_key, result.stdout, digest)


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
    install_executable(bin_dir / "avbtool", "#!/bin/sh\nexit 0\n")
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


@pytest.mark.parametrize(
    ("key_name", "verified"),
    (("server-a", True), ("server-b", False)),
)
def test_payload_signer_checks_the_server_signature_against_its_key(
    tmp_path: Path,
    yubihsm_server: tuple[SigningServer, EmulatedYubiHsm],
    key_name: str,
    verified: bool,
) -> None:
    server, _ = yubihsm_server
    digest = hashlib.sha256(b"payload").digest()
    (tmp_path / "hash.bin").write_bytes(digest)
    signature = tmp_path / "sig.bin"
    _public_key_file(tmp_path / "keys", "0x2000", key_name)

    result = subprocess.run(
        [
            PAYLOAD_SIGNER,
            "-in",
            tmp_path / "hash.bin",
            "-out",
            signature,
            "-inkey",
            tmp_path / "keys" / "0x2000",
        ],
        env={
            **_without_signing_variables(),
            "SIGNING_SERVER_SOCKET": str(server.socket_path),
            "KEY_DIR": f"{tmp_path / 'keys'}/",
            "DEBUG_PAYLOAD_SIGNER": "yes",
        },
        capture_output=True,
    )

    if verified:
        assert result.returncode == 0, result.stderr
        assert verifies(rsa_key("server-a"), signature.read_bytes(), digest)
        assert not verifies(rsa_key("server-b"), signature.read_bytes(), digest)
    else:
        assert result.returncode != 0
        assert not signature.exists()
        assert b"does not verify under the supplied public key" in result.stderr


def test_payload_signer_falls_back_to_pkcs11_without_a_server(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    public_key, environment = _softhsm_fallback(tmp_path, softhsm_rsa_key)
    digest = hashlib.sha256(b"payload").digest()
    (tmp_path / "hash.bin").write_bytes(digest)

    result = subprocess.run(
        [
            PAYLOAD_SIGNER,
            "-in",
            "hash.bin",
            "-out",
            "sig.bin",
            "-inkey",
            "keys/0x2000",
        ],
        cwd=tmp_path,
        env={**environment, "PYTHONSAFEPATH": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert verifies(public_key, (tmp_path / "sig.bin").read_bytes(), digest)


class _NestedHandler:
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def handle(self, message: Message) -> Message:
        inner = request(self.socket_path, "inner")
        return {"status": "ok", "inner": inner}


def test_a_handler_can_send_requests_to_another_handler(tmp_path: Path) -> None:
    socket_path = tmp_path / "s.sock"
    inner = _Handler({"status": "ok", "value": 7})
    server = SigningServer(socket_path)
    server.add_service({"outer": _NestedHandler(socket_path).handle})
    server.add_service({"inner": inner.handle})

    responses: list[Message | None] = []
    with server:
        caller = threading.Thread(
            target=lambda: responses.append(request(socket_path, "outer")),
            daemon=True,
        )
        caller.start()
        caller.join(timeout=10)
        assert not caller.is_alive(), "the nested request deadlocked"

    assert responses == [
        {"status": "ok", "inner": {"status": "ok", "value": 7}},
    ]


def test_operations_of_one_service_run_one_at_a_time(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    ran: list[str] = []

    def first(message: Message) -> Message:
        started.set()
        release.wait(timeout=10)
        ran.append("first")
        return {"status": "ok"}

    def second(message: Message) -> Message:
        ran.append("second")
        return {"status": "ok"}

    server = SigningServer(tmp_path / "s.sock")
    server.add_service({"first": first, "second": second})
    with server:
        callers = [
            threading.Thread(
                target=request,
                args=(server.socket_path, op),
                daemon=True,
            )
            for op in ("first", "second")
        ]
        callers[0].start()
        assert started.wait(timeout=10)
        callers[1].start()
        callers[1].join(timeout=0.2)
        release.set()
        for caller in callers:
            caller.join(timeout=10)

    assert ran == ["first", "second"]


def test_a_client_that_never_finishes_its_request_does_not_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(signing_server, "_REQUEST_TIMEOUT", 0.2)
    handler = _Handler({"status": "ok"})
    server = SigningServer(tmp_path / "s.sock")
    server.add_service({"a": handler.handle})
    with server:
        stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stalled.connect(str(server.socket_path))
        stalled.sendall(b"{")
        response = request(server.socket_path, "a")
        stalled.close()

    assert response == {"status": "ok"}


def test_extract_audit_log_refuses_another_log(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    service = _service(yubihsm, tmp_path / "audit.log")

    response = service.extract_audit_log(
        {
            "op": "yubihsm_extract_audit_log",
            "log_path": str(tmp_path / "elsewhere.log"),
            "comment": "comment",
        },
    )

    assert response == {"status": "unavailable"}
    assert not (tmp_path / "elsewhere.log").exists()
