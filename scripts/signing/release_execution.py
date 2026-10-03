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
import shlex
import signal
import subprocess
import sys
from collections.abc import Generator, Sequence
from pathlib import Path
from types import FrameType

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
