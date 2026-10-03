#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import traceback
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

import pytest
from yubihsm_emulator import Connector, EmulatedYubiHsm, serve_connector

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
TEST_METADATA = Path(__file__).parent / "fixtures" / "metadata.py"
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def yubihsm() -> Iterator[Connector]:
    """An emulated YubiHSM 2 behind a local yubihsm-connector stand-in."""
    with serve_connector() as connector:
        connector.plug(EmulatedYubiHsm())
        yield connector


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


def _show_warning(
    message: Warning | str,
    category: type[Warning],
    filename: str,
    lineno: int,
    file: TextIO | None = None,
    line: str | None = None,
) -> None:
    sys.stderr.write(
        warnings.formatwarning(message, category, filename, lineno, line),
    )


def _run_signing_cli(
    args: list[str | Path],
    cwd: Path | None,
    env: dict[str, str] | None,
    input_data: bytes | None,
    check: bool,
) -> subprocess.CompletedProcess[bytes]:
    from signing import cli

    argv = [str(arg) for arg in args]
    environment = {**os.environ, **(env or {})}
    saved_environment = dict(os.environ)
    saved_cwd = os.getcwd()
    saved_streams = (sys.stdin, sys.stdout, sys.stderr)
    saved_fds = {fd: os.dup(fd) for fd in (0, 1, 2)}
    with (
        tempfile.TemporaryFile() as stdin,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        stdin.write(input_data or b"")
        stdin.seek(0)
        for stream in saved_streams[1:]:
            stream.flush()
        for fd, file in ((0, stdin), (1, stdout), (2, stderr)):
            os.dup2(file.fileno(), fd)
        sys.stdin = open(0, closefd=False)
        sys.stdout = open(1, "w", closefd=False)
        sys.stderr = open(2, "w", closefd=False)
        os.environ.clear()
        os.environ.update(environment)
        try:
            if cwd is not None:
                os.chdir(cwd)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("default")
                    warnings.showwarning = _show_warning
                    returncode = cli.main(argv)
            except SystemExit as error:
                if error.code is None or isinstance(error.code, int):
                    returncode = error.code or 0
                else:
                    print(error.code, file=sys.stderr)
                    returncode = 1
            except Exception:
                traceback.print_exc()
                returncode = 1
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            sys.stdin, sys.stdout, sys.stderr = saved_streams
            for fd, saved in saved_fds.items():
                os.dup2(saved, fd)
                os.close(saved)
            os.environ.clear()
            os.environ.update(saved_environment)
            os.chdir(saved_cwd)
        stdout.seek(0)
        stderr.seek(0)
        result = subprocess.CompletedProcess(
            ["python3", "-m", "signing", *argv],
            returncode,
            stdout.read(),
            stderr.read(),
        )
    if check:
        result.check_returncode()
    return result


def run_cli(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Run `python3 -m signing ARGS` in this process, as run() runs a command.
    """
    result = _run_signing_cli(
        args,
        cwd,
        env,
        None if input_text is None else input_text.encode(),
        check,
    )
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        result.stdout.decode(),
        result.stderr.decode(),
    )
