#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Keep one "apksigner batch" process alive for a whole release, so that
signing an APK does not start a JVM of its own.

"apksigner batch" (a CalyxOS apksig patch) reads NUL-delimited commands
from stdin, each prefixed by its argument count, runs them in one
process, and terminates each command's stdout and stderr with
"\\0RETURN:<code>\\0". An argument count of 0 ends the session.
"""

from __future__ import annotations

import base64
import os
import re
import selectors
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .signing_server import Message, request

_RETURN_MARKER = re.compile(rb"\0RETURN:(\d+)\0")
_IDLE_TIMEOUT = 600.0
_STOP_TIMEOUT = 10.0


class BatchProcess:
    def __init__(
        self,
        *,
        cwd: Path,
        env: Mapping[str, str],
    ) -> None:
        self.process = subprocess.Popen(
            [
                "java",
                "-Xmx4096m",
                f"-Djava.library.path={cwd / 'lib64'}",
                "-jar",
                str(cwd / "framework" / "apksigner.jar"),
                "batch",
            ],
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run(
        self,
        args: Sequence[str],
    ) -> tuple[int, bytes, bytes] | None:
        """
        Send one command and collect its output up to the RETURN markers.

        Returns:
            (code, stdout, stderr), or None if the process exited or went
            quiet for _IDLE_TIMEOUT seconds before both markers arrived.
        """
        request = b"".join(
            item.encode() + b"\0" for item in (str(len(args)), *args)
        )
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(request)
            self.process.stdin.flush()
        except OSError:
            return None

        assert self.process.stdout is not None
        assert self.process.stderr is not None
        stdout = self.process.stdout.fileno()
        stderr = self.process.stderr.fileno()
        buffers = {stdout: b"", stderr: b""}
        codes: dict[int, int] = {}
        with selectors.DefaultSelector() as selector:
            for fd in buffers:
                selector.register(fd, selectors.EVENT_READ)
            while len(codes) < len(buffers):
                events = selector.select(timeout=_IDLE_TIMEOUT)
                if not events:
                    return None
                for key, _ in events:
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        return None
                    buffers[key.fd] += chunk
                    match = _RETURN_MARKER.search(buffers[key.fd])
                    if match:
                        codes[key.fd] = int(match.group(1))
                        buffers[key.fd] = buffers[key.fd][: match.start()]
                        selector.unregister(key.fd)
        return codes[stdout], buffers[stdout], buffers[stderr]

    def stop(self) -> None:
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(b"0\0")
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.process.wait(timeout=_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()


class ApksignerBatch:
    """
    SigningServer service for the "apksigner" operation, running each
    command in one long-lived "apksigner batch" process.
    """

    def __init__(
        self,
        *,
        cwd: Path,
        env: Mapping[str, str],
    ) -> None:
        self.cwd = cwd
        self.env = env
        self.process: BatchProcess | None = None
        self._process_completed_a_command = False
        self._fresh_failures = 0
        self._disabled = False

    def handle(self, request: Message) -> Message:
        args = [str(item) for item in request["args"]]
        if self._disabled:
            return {"status": "unavailable"}
        if (
            Path(request["cwd"]) != self.cwd
            or not args
            or any(not a for a in args)
        ):
            return {"status": "unavailable"}

        if self.process is None:
            self.process = BatchProcess(cwd=self.cwd, env=self.env)
            self._process_completed_a_command = False

        result = self.process.run(args)
        if result is None:
            if not self._process_completed_a_command:
                self._disabled = True
                print(
                    "Warning: apksigner batch did not complete a command, "
                    "signing each APK with its own apksigner process "
                    "instead.",
                    file=sys.stderr,
                )
            self.close()
            return {"status": "unavailable"}

        code, stdout, stderr = result
        if code == 0:
            self._process_completed_a_command = True
            self._fresh_failures = 0
        else:
            if not self._process_completed_a_command:
                self._fresh_failures += 1
            if self._fresh_failures >= 2:
                self._disabled = True
                print(
                    "Warning: two apksigner batch processes failed their "
                    "first command, signing each APK with its own "
                    "apksigner process instead.",
                    file=sys.stderr,
                )
            self.close()
        return {
            "status": "ok",
            "code": code,
            "stdout": base64.b64encode(stdout).decode(),
            "stderr": base64.b64encode(stderr).decode(),
        }

    def close(self) -> None:
        process, self.process = self.process, None
        if process is not None:
            process.stop()


def run_in_batch(
    socket_path: Path,
    args: Sequence[str],
    *,
    cwd: Path,
) -> tuple[int, bytes, bytes] | None:
    """
    Ask a SigningServer's ApksignerBatch to run one apksigner command.

    Args:
        socket_path: The server's Unix socket.
        args: apksigner's own arguments, e.g. "sign ...".
        cwd: The caller's working directory, which must match the
            server's for relative paths to mean the same thing.

    Returns:
        (code, stdout, stderr), or None if batch mode is unavailable and
        the caller should run the command itself.
    """
    response = request(
        socket_path,
        "apksigner",
        args=list(args),
        cwd=str(cwd),
    )
    if response is None:
        return None
    return (
        int(response["code"]),
        base64.b64decode(response["stdout"]),
        base64.b64decode(response["stderr"]),
    )
