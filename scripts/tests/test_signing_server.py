#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from signing import signing_server
from signing.signing_server import Message, SigningServer, request


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
