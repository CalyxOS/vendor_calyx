#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Run the AOSP release tools of a release and checksum their outputs.
"""

from __future__ import annotations

import hashlib
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path


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
