#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Writing files so that a reader never sees one half written.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def write_file_atomically(path: Path, data: bytes) -> None:
    """
    Write a file through a synced temporary file renamed over it, so that
    an interrupted write never leaves a partial file under its name.

    Args:
        path: File to write.
        data: Its new contents.

    Returns:
        None.

    Raises:
        OSError: If the file cannot be written.
    """
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
