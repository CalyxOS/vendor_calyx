#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
TEST_METADATA = Path(__file__).parent / "fixtures" / "metadata.py"


@pytest.fixture(scope="session")
def aosp_top() -> Path:
    top = REPO_ROOT.parents[1]
    required = (
        top / "development" / "tools" / "make_key",
        top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        pytest.skip(f"the Android tree lacks {', '.join(missing)}")
    return top


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def default_signal_dispositions() -> None:
    """
    Give a child the default SIGINT, SIGHUP and SIGTERM handling, which a
    test run under nohup or in the background hands down as ignored.
    """
    for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, signal.SIG_DFL)


def run(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=process_env,
        input=input_text,
        check=check,
        text=True,
        capture_output=True,
        preexec_fn=default_signal_dispositions,
    )


def run_bytes(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=process_env,
        input=input_data,
        check=check,
        capture_output=True,
        preexec_fn=default_signal_dispositions,
    )
