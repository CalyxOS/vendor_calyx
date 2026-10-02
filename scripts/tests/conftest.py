#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TextIO, TypeVar

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


@pytest.fixture(autouse=True)
def fake_pkcs11_modules(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    from signing import sign_environment

    directory = tmp_path_factory.mktemp("pkcs11-modules")
    modules: dict[str, Path] = {}
    for vendor in ("yubihsm", "softhsm"):
        module = directory / f"{vendor}_pkcs11.so"
        module.touch()
        modules[vendor] = module
    for vendor, module in modules.items():
        monkeypatch.setattr(
            sign_environment.VENDORS[vendor],
            "find_pkcs11_module",
            _find_module_at(module),
        )
    return modules


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


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_until(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def aosp_jar_command(aosp_top: Path, jar_name: str) -> list[str]:
    host = aosp_top / "out" / "host" / "linux-x86"
    java = (
        aosp_top / "prebuilts" / "jdk" / "jdk21" / "linux-x86" / "bin" / "java"
    )
    jar = host / "framework" / jar_name
    missing = [str(path) for path in (java, jar) if not path.is_file()]
    if missing:
        pytest.skip(f"the Android tree lacks {', '.join(missing)}")
    return [
        str(java),
        f"-Djava.library.path={host / 'lib64'}",
        "-jar",
        str(jar),
    ]


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
    replace_env: bool,
) -> subprocess.CompletedProcess[bytes]:
    from signing import cli

    argv = [str(arg) for arg in args]
    environment = (
        dict(env or {}) if replace_env else {**os.environ, **(env or {})}
    )
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
    replace_env: bool = False,
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
        replace_env,
    )
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        result.stdout.decode(),
        result.stderr.decode(),
    )


def run_cli_bytes(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
    check: bool = True,
    replace_env: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """
    Run `python3 -m signing ARGS` in this process, as run_bytes() runs a
    command.
    """
    return _run_signing_cli(args, cwd, env, input_data, check, replace_env)


SOFTHSM_MODULE = Path("/usr/lib/pkcs11/libsofthsm2.so")
SOFTHSM_TOKEN_LABEL = "softhsm-rsa-key-test"
SOFTHSM_SO_PIN = "12345678"
SOFTHSM_USER_PIN = "123456"
SOFTHSM_KEY_ID = "0x2000"


@pytest.fixture
def softhsm_rsa_key(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """
    A SoftHSM2 token holding an RSA-2048 keypair, plus the environment
    the PKCS#11 helpers need to reach it.
    """
    missing = [
        executable
        for executable in ("softhsm2-util", "pkcs11-tool")
        if shutil.which(executable) is None
    ]
    if not SOFTHSM_MODULE.is_file():
        missing.append(str(SOFTHSM_MODULE))
    if missing:
        pytest.skip(
            f"SoftHSM test dependencies are missing: {', '.join(missing)}",
        )

    token_directory = tmp_path / "tokens"
    token_directory.mkdir()
    softhsm_config = tmp_path / "softhsm2.conf"
    softhsm_config.write_text(
        f"""directories.tokendir = {token_directory}
objectstore.backend = file
log.level = WARNING
slots.removable = true
slots.mechanisms = ALL
library.reset_on_fork = false
""",
    )
    environment = {
        "SOFTHSM2_CONF": str(softhsm_config),
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_TOOL_BIN": str(shutil.which("pkcs11-tool")),
        "PKCS11_TOKEN_LABEL": SOFTHSM_TOKEN_LABEL,
        "PKCS11_PIN": SOFTHSM_USER_PIN,
    }
    initialized = run(
        [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            SOFTHSM_TOKEN_LABEL,
            "--so-pin",
            SOFTHSM_SO_PIN,
            "--pin",
            SOFTHSM_USER_PIN,
        ],
        env=environment,
        check=False,
    )
    assert initialized.returncode == 0, initialized.stderr
    generated = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            SOFTHSM_TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--keypairgen",
            "--key-type",
            "rsa:2048",
            "--id",
            SOFTHSM_KEY_ID.removeprefix("0x"),
            "--label",
            "apksigner-key",
        ],
        env=environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr

    public_key = tmp_path / "public.der"
    exported = run_bytes(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            SOFTHSM_TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--read-object",
            "--type",
            "pubkey",
            "--id",
            SOFTHSM_KEY_ID.removeprefix("0x"),
        ],
        env=environment,
    )
    public_key.write_bytes(exported.stdout)
    return environment, public_key


T = TypeVar("T")


def stub(value: T) -> Callable[..., T]:
    """
    Return a callable that ignores its arguments and returns value.

    Args:
        value: What every call returns.

    Returns:
        The callable.
    """

    def stubbed(*args: object, **kwargs: object) -> T:
        return value

    return stubbed


def _find_module_at(module: Path) -> Callable[[object], str | None]:
    def find_pkcs11_module(self: object) -> str | None:
        return str(module) if module.exists() else None

    return find_pkcs11_module
