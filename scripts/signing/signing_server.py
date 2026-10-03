#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
A Unix-socket server that keeps signing state alive for a whole release.

Each request is one JSON object naming an operation in "op", and each
connection carries one request and one JSON response. Each connection is
handled on a thread of its own by the handler registered for the
operation, and each handler serializes its own requests, so that a
request one handler is working on can itself send requests to another,
as apksigner does from inside the batch process. A response whose
"status" is not "ok" tells the caller to do the work itself.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

Message = dict[str, Any]


class Handler(Protocol):
    """
    Serves the requests for one or more operations.
    """

    def handle(self, request: Message, /) -> Message:
        """
        Answer one request.

        Args:
            request: The decoded request, with its operation in "op".

        Returns:
            The response to send back.
        """
        ...


class SigningServer:
    """
    Serve registered operations over a Unix socket for the lifetime of a
    with block. Every handler's close(), when it has one, is called on
    exit.
    """

    def __init__(
        self,
        socket_path: Path,
        handlers: Mapping[str, Handler],
    ) -> None:
        """
        Prepare a server for the given operations.

        Args:
            socket_path: Where to bind the socket (mode 0600).
            handlers: Operation name to an object with a handle(request)
                method returning the response, and optionally close().
        """
        self.socket_path = socket_path
        self.handlers = dict(handlers)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._stopping = False

    def __enter__(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(0o600)
            listener.listen()
        except OSError:
            listener.close()
            raise
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def __exit__(self, *exc_info: object) -> None:
        self._stopping = True
        assert self._listener is not None
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        assert self._thread is not None
        deadline = time.monotonic() + _STOP_TIMEOUT
        self._thread.join(timeout=_STOP_TIMEOUT)
        with self._workers_lock:
            workers = list(self._workers)
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        try:
            for handler in dict.fromkeys(self.handlers.values()):
                close = getattr(handler, "close", None)
                if close is not None:
                    close()
        finally:
            self.socket_path.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stopping:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            worker = threading.Thread(
                target=self._serve_connection,
                args=(connection,),
                daemon=True,
            )
            with self._workers_lock:
                self._workers.add(worker)
            worker.start()

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            with connection:
                connection.settimeout(_REQUEST_TIMEOUT)
                try:
                    raw = _receive_all(connection)
                except OSError:
                    return
                response = self._respond(raw)
                try:
                    connection.sendall(json.dumps(response).encode())
                except OSError:
                    pass
        finally:
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def _respond(self, raw: bytes) -> Message:
        try:
            request: Message = json.loads(raw)
            handler = self.handlers.get(request["op"])
            if handler is None:
                return {"status": "unavailable"}
            return handler.handle(request)
        except Exception as error:
            print(
                f"Warning: signing server request failed ({error}).",
                file=sys.stderr,
            )
            return {"status": "error", "message": str(error)}


_REQUEST_TIMEOUT = 30.0
_RESPONSE_TIMEOUT = 900.0
_STOP_TIMEOUT = 10.0


def _receive_all(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while chunk := connection.recv(65536):
        chunks.append(chunk)
    return b"".join(chunks)


def request(socket_path: Path, op: str, **fields: object) -> Message | None:
    """
    Send one request to a SigningServer.

    Args:
        socket_path: The server's Unix socket.
        op: The operation to run.
        **fields: The operation's JSON-serializable arguments.

    Returns:
        The response, or None if the server could not be reached or did
        not answer "ok".
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path))
            connection.settimeout(_RESPONSE_TIMEOUT)
            connection.sendall(json.dumps({"op": op, **fields}).encode())
            connection.shutdown(socket.SHUT_WR)
            response: Message = json.loads(_receive_all(connection))
    except (OSError, ValueError) as error:
        print(
            f"Warning: could not reach the signing server ({error}).",
            file=sys.stderr,
        )
        return None
    if response.get("status") != "ok":
        return None
    return response
