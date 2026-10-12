#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Local yubihsm-connector process lifecycle management.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def _process_is_alive(pid: int) -> bool:
    """
    Return whether a process with a given PID currently exists.

    A child of the calling process is reaped first, and an exited process
    another process has not reaped yet counts as gone, since
    ``kill(pid, 0)`` reports such a zombie as alive.

    Args:
        pid: Process ID to probe.

    Returns:
        Whether the process exists and has not exited.
    """
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    return stat.rpartition(")")[2].split()[:1] != ["Z"]


@dataclass(frozen=True, slots=True)
class YubiHsmConnectorConfig:
    """
    Settings needed to manage a local ``yubihsm-connector`` process.
    """

    connector_url: str
    pid_file: Path
    binary: str = "yubihsm-connector"


class YubiHsmConnector:
    """
    Local ``yubihsm-connector`` process lifecycle.

    A USB-mode connector URL (``yhusb://...``) is never managed.
    """

    def __init__(self, config: YubiHsmConnectorConfig) -> None:
        """
        Store the configuration used for every lifecycle operation.

        Args:
            config: Connector URL, PID file path, and managed binary.

        Returns:
            None.
        """
        self._config = config
        self._process: subprocess.Popen[bytes] | None = None

    def _managed(self) -> bool:
        """
        Return whether this configuration is one this instance manages.

        Returns:
            False for USB-mode connectors, and True otherwise.
        """
        return not self._config.connector_url.startswith("yhusb://")

    def is_running(self) -> bool:
        """
        Return whether a matching ``yubihsm-connector`` process is running.

        A process matches when its command line, as
        ``pgrep -a -f yubihsm-connector`` prints it, is the configured
        binary or ``yubihsm-connector``, alone or followed by arguments.
        The calling process never matches.

        Returns:
            Whether a matching process was found.

        Raises:
            OSError: If ``pgrep`` cannot be executed.
        """
        result = subprocess.run(
            ["pgrep", "-a", "-f", "yubihsm-connector"],
            check=False,
            capture_output=True,
            text=True,
        )
        candidates = (self._config.binary, "yubihsm-connector")
        own_pid = os.getpid()
        for line in result.stdout.splitlines():
            pid_text, _, command = line.partition(" ")
            if not pid_text.isdigit() or int(pid_text) == own_pid:
                continue
            if any(
                command == candidate or command.startswith(f"{candidate} ")
                for candidate in candidates
            ):
                return True
        return False

    def start(self) -> None:
        """
        Start the connector only if one is not already running.

        Returns:
            None.

        Raises:
            OSError: If the connector binary cannot be executed.
            RuntimeError: If a previously started connector cannot be
                stopped before starting a new one.
        """
        self._start_or_restart(start_only=True)

    def restart(self) -> None:
        """
        Stop any connector the PID file names and start a new one.

        Returns:
            None.

        Raises:
            OSError: If the connector binary cannot be executed.
            RuntimeError: If the existing connector cannot be stopped.
        """
        self._start_or_restart(start_only=False)

    def _start_or_restart(self, *, start_only: bool) -> None:
        """
        Start the connector, stopping a running one first unless
        start_only is set.

        Args:
            start_only: Whether to skip stopping an already-running
                connector instead of restarting it.

        Returns:
            None.
        """
        if not self._managed():
            return
        if start_only and self.is_running():
            return
        self.stop()
        process = subprocess.Popen(
            [self._config.binary],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._config.pid_file.write_text(f"{process.pid}\n")
        self._process = process

    def wait_until_listening(self, timeout: float = 10.0) -> None:
        """
        Wait until the connector this instance started accepts connections
        on the host and port of the connector URL.

        Args:
            timeout: Seconds to wait before giving up.

        Returns:
            None.

        Raises:
            RuntimeError: If the connector exits, or does not listen within
                timeout seconds.
        """
        if not self._managed() or self._process is None:
            return
        url = urlsplit(self._config.connector_url)
        if url.hostname is None:
            return
        address = (
            url.hostname,
            url.port or (443 if url.scheme == "https" else 80),
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                socket.create_connection(address, timeout=1).close()
            except OSError:
                pass
            else:
                return
            if self._process.poll() is not None:
                raise RuntimeError("yubihsm-connector exited after starting.")
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "yubihsm-connector did not listen on "
                    f"{url.hostname}:{address[1]} after starting.",
                )
            time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the connector the PID file names, and remove the PID file.

        Returns:
            None.

        Raises:
            RuntimeError: If the process does not exit after being sent
                SIGTERM.
        """
        if not self._managed():
            return
        if not self._config.pid_file.exists():
            return
        pid = int(self._config.pid_file.read_text().strip())
        held_process = self._process if self._process_pid() == pid else None
        if _process_is_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if held_process is not None:
                # Reap our own child so a same-process restart does not
                # leave it as a zombie that still answers kill(pid, 0).
                try:
                    held_process.wait(timeout=10)
                except subprocess.TimeoutExpired as error:
                    raise RuntimeError(
                        "Could not kill existing yubihsm-connector.",
                    ) from error
            else:
                for _ in range(200):
                    if not _process_is_alive(pid):
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError(
                        "Could not kill existing yubihsm-connector.",
                    )
        self._process = None
        self._config.pid_file.unlink()

    def _process_pid(self) -> int | None:
        """
        Return the PID of a process this instance started, if it holds one.

        Returns:
            The held process's PID, or None if this instance did not
            start a still-tracked process.
        """
        return None if self._process is None else self._process.pid
