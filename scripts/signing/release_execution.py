#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Run the AOSP release tools of a release and checksum their outputs.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Generator, Sequence
from pathlib import Path
from types import FrameType
from typing import BinaryIO

_QUOTE_BRIDGE = r'printf "%q " "$@"'


@contextlib.contextmanager
def exit_on_signals() -> Generator[None, None, None]:
    """
    Raise SystemExit(128 + signal number) for a SIGTERM or SIGHUP inside
    the with block, so that the cleanup around it runs. A signal the
    process ignores stays ignored.
    """

    def exit_on_signal(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    previous_handlers = {
        signum: signal.signal(signum, exit_on_signal)
        for signum in (signal.SIGTERM, signal.SIGHUP)
        if signal.getsignal(signum) != signal.SIG_IGN
    }
    try:
        yield
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def render_release_tool(argv: Sequence[str]) -> str:
    """
    Render one release-tool invocation as a shell command line, each
    argument quoted.

    Args:
        argv: Complete executable and argument vector to render.

    Returns:
        The quoted, space-joined command line followed by a blank line,
        with no leading "Running:" text.

    Raises:
        subprocess.CalledProcessError: If bash cannot be executed.
    """
    completed = subprocess.run(
        ["bash", "-c", _QUOTE_BRIDGE, "quote-bridge", *argv],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.removesuffix(" ") + "\n\n"


def run_release_tool(argv: Sequence[str]) -> int:
    """
    Print one release-tool invocation to stderr and run it.

    Args:
        argv: Complete executable and argument vector to run.

    Returns:
        The invoked process's exit status, or 127 when it cannot start,
        as a shell reports a command it cannot run.
    """
    print("Running:", shlex.join(argv), file=sys.stderr)
    try:
        return subprocess.run(argv).returncode
    except OSError as error:
        print(f"{argv[0]}: {error.strerror}", file=sys.stderr)
        return 127


def format_sha256sum(path: str) -> str:
    """
    Render one file's checksum in sha256sum(1)'s own output format.

    Args:
        path: Filename to hash and print exactly as given, as `sha256sum`
            prints its argument rather than a resolved path.

    Returns:
        "<hex digest><two spaces><path>\\n", matching a `sha256sum`
        invocation run against the same file from the same directory.
    """
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"{digest.hexdigest()}  {path}\n"


_TRANSCRIPT_STOP_TIMEOUT = 10.0


class Transcript:
    """
    Copy everything written to file descriptors 1 and 2 into a log file,
    so that the output of child processes lands in the log too.
    """

    def __init__(self) -> None:
        self._log: BinaryIO | None = None
        self._lock = threading.Lock()
        self._streams: list[tuple[int, int, threading.Thread]] = []

    def start(self, path: Path) -> None:
        """
        Start copying standard output and standard error into path.

        Args:
            path: Log file, created or truncated.

        Returns:
            None.
        """
        sys.stdout.flush()
        sys.stderr.flush()
        self._log = open(path, "wb")
        for fd in (1, 2):
            saved = os.dup(fd)
            read_end, write_end = os.pipe()
            os.dup2(write_end, fd)
            os.close(write_end)
            thread = threading.Thread(
                target=self._copy,
                args=(read_end, saved, self._log),
                daemon=True,
            )
            thread.start()
            self._streams.append((fd, saved, thread))

    def _copy(self, read_end: int, saved: int, log: BinaryIO) -> None:
        terminal = True
        logging = True
        with os.fdopen(read_end, "rb", buffering=0) as stream:
            while chunk := stream.read(65536):
                if terminal:
                    try:
                        unwritten = memoryview(chunk)
                        while unwritten:
                            unwritten = unwritten[os.write(saved, unwritten) :]
                    except OSError:
                        terminal = False
                if logging:
                    with self._lock:
                        try:
                            log.write(chunk)
                            log.flush()
                        except OSError:
                            logging = False

    def stop(self) -> None:
        """
        Restore standard output and standard error, and wait up to ten
        seconds in all for the output already written to reach the log. A
        child still running with the old descriptors keeps writing to the
        terminal and the log until the release exits.

        Returns:
            None.
        """
        if self._log is None:
            return
        sys.stdout.flush()
        sys.stderr.flush()
        for fd, saved, _thread in self._streams:
            os.dup2(saved, fd)
        deadline = time.monotonic() + _TRANSCRIPT_STOP_TIMEOUT
        draining = False
        for _fd, saved, thread in self._streams:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                draining = True
            else:
                os.close(saved)
        self._streams.clear()
        if not draining:
            try:
                self._log.close()
            except OSError:
                pass
        self._log = None
