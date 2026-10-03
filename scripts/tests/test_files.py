#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
from pathlib import Path

import pytest
from signing.files import write_file_atomically


def test_write_file_atomically_replaces_the_file_and_leaves_nothing_else(
    tmp_path: Path,
) -> None:
    target = tmp_path / "output.bin"
    target.write_bytes(b"old")

    write_file_atomically(target, b"new")

    assert target.read_bytes() == b"new"
    assert [path.name for path in tmp_path.iterdir()] == [target.name]


def test_write_file_atomically_leaves_no_partial_file_when_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A failed write leaves nothing at the destination, so that a partial
    file is never taken for complete output.
    """
    destination = tmp_path / "output.bin"

    def failing_fsync(fd: int) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(os, "fsync", failing_fsync)

    with pytest.raises(OSError, match="simulated disk failure"):
        write_file_atomically(destination, b"output bytes")

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []
