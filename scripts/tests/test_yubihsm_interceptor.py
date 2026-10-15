#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import importlib.util
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import SCRIPTS_DIR, install_executable, run, stub, yubihsm_config
from signing.signing_server import SigningServer
from signing.yubihsm_session_service import YubiHsmSessionService
from yubihsm.defs import COMMAND
from yubihsm_emulator import Connector

INTERCEPTOR = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.py"


def _load_interceptor() -> ModuleType:
    """
    Import the interceptor as a library, for tests that need to
    monkeypatch its internals. Its filename has dots, so it cannot be
    imported by name.
    """
    spec = importlib.util.spec_from_file_location(
        "yubihsm_python_interceptor",
        INTERCEPTOR,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_script(path: Path, body: str) -> Path:
    return install_executable(path, f"#!/bin/sh\n{body}\n")


def path_prepending(directory: Path) -> dict[str, str]:
    """
    Put a directory of stand-in commands first on PATH, since the
    interceptor classifies SIGNING_COMMAND by its bare name.
    """
    return {"PATH": f"{directory}:{os.environ.get('PATH', '')}"}


def _audit_environment(
    tmp_path: Path,
    bin_dir: Path,
    command: str,
    yubihsm: Connector,
    **extra: str,
) -> dict[str, str]:
    return {
        "SIGNING_COMMAND": command,
        "YUBIHSM_SIGNING_CACHE": "",
        "YUBIHSM_LOCKFILE": "",
        "DRY_RUN": "",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "AUDIT_LOG_PATH": str(tmp_path / "audit.log"),
        "YUBIHSM_CONNECTOR": yubihsm.url,
        **path_prepending(bin_dir),
        **extra,
    }


@pytest.mark.parametrize(
    ("command", "args", "logged"),
    [
        ("avbtool", ["add_hash_footer", "--signing_helper", "x"], True),
        ("avbtool", ["info_image", "--image", "x"], False),
        ("java", ["-jar", "/p/apksigner.jar", "sign", "--out", "o", "i"], True),
        ("java", ["-jar", "/p/signapk.jar", "o", "i"], True),
        ("java", ["-jar", "/p/other.jar"], False),
    ],
)
def test_signing_commands_append_to_the_audit_log(
    tmp_path: Path,
    command: str,
    args: list[str],
    logged: bool,
    yubihsm: Connector,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    make_script(bin_dir / command, "exit 0\n")

    result = run(
        [INTERCEPTOR, *args],
        env=_audit_environment(tmp_path, bin_dir, command, yubihsm),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    audit_log = tmp_path / "audit.log"
    if not logged:
        assert not audit_log.exists()
        return
    (number, _, digest), *_ = yubihsm.device.log
    comment, entry = audit_log.read_text().splitlines()
    assert comment.endswith(f" {command} {' '.join(args)} # Result: 0")
    assert entry.startswith(f"{number:>5} ")
    assert entry.endswith("hash: " + digest.hex())
    assert yubihsm.device.unread_log() == []


def test_dry_run_writes_no_audit_log(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    make_script(bin_dir / "avbtool", "exit 0\n")

    result = run(
        [INTERCEPTOR, "add_hash_footer", "--signing_helper", "x"],
        env=_audit_environment(
            tmp_path,
            bin_dir,
            "avbtool",
            yubihsm,
            DRY_RUN="y",
        ),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "audit.log").exists()


@pytest.mark.parametrize(
    ("min_sdk_version", "added"),
    [
        ("30", ["--v1-signing-enabled=false", "--v2-signing-enabled=false"]),
        ("26", ["--v1-signing-enabled=false"]),
        ("20", []),
    ],
)
def test_apksigner_skips_signature_schemes_below_min_sdk_version(
    tmp_path: Path,
    min_sdk_version: str,
    added: list[str],
    yubihsm: Connector,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    received = tmp_path / "received"
    make_script(bin_dir / "java", f'printf "%s\\n" "$@" > "{received}"\n')
    args = ["-jar", "apksigner.jar", "sign", "--min-sdk-version"]

    result = run(
        [INTERCEPTOR, *args, min_sdk_version],
        env=_audit_environment(tmp_path, bin_dir, "java", yubihsm, DRY_RUN="y"),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert received.read_text().splitlines() == [
        *args,
        min_sdk_version,
        *added,
    ]


def test_relays_output_and_exit_code(tmp_path: Path) -> None:
    make_script(
        tmp_path / "avbtool",
        'echo "to stdout"\necho "to stderr" >&2\nexit 3\n',
    )
    result = run(
        [INTERCEPTOR, "info_image"],
        env={
            "SIGNING_COMMAND": "avbtool",
            "DRY_RUN": "y",
            **path_prepending(tmp_path),
        },
        check=False,
    )
    assert result.returncode == 3
    assert "to stdout" in result.stdout
    assert "to stderr" in result.stderr


def test_apksigner_without_signing_cache_leaves_cwd_alone(
    tmp_path: Path,
) -> None:
    unsigned = tmp_path / "unsigned.apk"
    unsigned.write_bytes(b"unsigned content")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runs = tmp_path / "runs"
    make_script(
        bin_dir / "java",
        r"""
echo run >> "$RUNS"
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--out" ]; then out="$arg"; fi
  prev="$arg"
done
printf %s "freshly signed" > "$out"
""",
    )
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    environment = dict(os.environ)
    environment.pop("YUBIHSM_SIGNING_CACHE", None)

    for name in ("out1.apk", "out2.apk"):
        result = subprocess.run(
            [
                INTERCEPTOR,
                "-jar",
                "apksigner.jar",
                "sign",
                "--kms-key-alias",
                "0x2000",
                "--out",
                str(tmp_path / name),
                str(unsigned),
            ],
            cwd=cwd,
            env={
                **environment,
                "SIGNING_COMMAND": "java",
                "DRY_RUN": "y",
                "RUNS": str(runs),
                **path_prepending(bin_dir),
            },
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    assert runs.read_text().splitlines() == ["run", "run"]
    assert list(cwd.iterdir()) == []


def test_retries_after_connector_failure(tmp_path: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    connector_binary = make_script(
        tmp_path / "fake-yubihsm-connector",
        f'exec "{sys.executable}" -c "import socket, time; '
        f"listener = socket.create_server(('127.0.0.1', {port})); "
        'time.sleep(300)"\n',
    )
    call_count_file = tmp_path / "call-count"
    make_script(
        tmp_path / "avbtool",
        f"""
count_file="{call_count_file}"
count=0
[ -f "$count_file" ] && count=$(cat "$count_file")
count=$((count + 1))
echo "$count" > "$count_file"
if [ "$count" -eq 1 ]; then
  echo "Connector operation failed: simulated" >&2
  exit 1
fi
echo "signed on try $count"
""",
    )
    pid_file = tmp_path / "connector.pid"
    result = run(
        [INTERCEPTOR, "--signing_helper", "x"],
        env={
            "SIGNING_COMMAND": "avbtool",
            "YUBIHSM_CONNECTOR_PIDFILE": str(pid_file),
            "YUBIHSM_CONNECTOR_BIN": str(connector_binary),
            "YUBIHSM_CONNECTOR": f"http://127.0.0.1:{port}",
            "DRY_RUN": "y",
            **path_prepending(tmp_path),
        },
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "signed on try 2" in result.stdout
    assert call_count_file.read_text().strip() == "2"

    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError):
            pass


def test_extracts_the_audit_log_when_the_connector_restart_fails(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    make_script(
        bin_dir / "avbtool",
        'echo "Connector operation failed: simulated" >&2\nexit 1\n',
    )

    result = run(
        [INTERCEPTOR, "add_hash_footer", "--signing_helper", "x"],
        env=_audit_environment(
            tmp_path,
            bin_dir,
            "avbtool",
            yubihsm,
            YUBIHSM_CONNECTOR_PIDFILE=str(tmp_path / "connector.pid"),
            YUBIHSM_CONNECTOR_BIN=str(tmp_path / "missing-connector"),
        ),
        check=False,
    )

    assert result.returncode == 1
    assert "could not restart the YubiHSM connector" in result.stderr
    assert "Traceback" not in result.stderr
    comment, *_ = (tmp_path / "audit.log").read_text().splitlines()
    assert comment.endswith("# Result: 1")


def test_holds_lockfile_while_the_command_runs(tmp_path: Path) -> None:
    lockfile = tmp_path / "yubihsm.lock"
    make_script(
        tmp_path / "avbtool",
        'if flock -n "$YUBIHSM_LOCKFILE" true; then echo unlocked; '
        "else echo locked; fi\n",
    )
    result = run(
        [INTERCEPTOR, "info_image"],
        env={
            "SIGNING_COMMAND": "avbtool",
            "YUBIHSM_LOCKFILE": str(lockfile),
            "DRY_RUN": "y",
            **path_prepending(tmp_path),
        },
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "locked\n"
    assert run(["flock", "-n", lockfile, "true"], check=False).returncode == 0


def test_retries_a_failed_audit_log_extraction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    interceptor = _load_interceptor()
    yubihsm.device.fail_next(COMMAND.GET_LOG_ENTRIES)
    monkeypatch.setattr(interceptor.time, "sleep", stub(None))
    make_script(tmp_path / "avbtool", "exit 0\n")
    audit_log = tmp_path / "audit.log"
    for name, value in {
        "SIGNING_COMMAND": "avbtool",
        "AUDIT_LOG_PATH": str(audit_log),
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "YUBIHSM_CONNECTOR": yubihsm.url,
        **path_prepending(tmp_path),
    }.items():
        monkeypatch.setenv(name, value)
    for name in (
        "DRY_RUN",
        "YUBIHSM_LOCKFILE",
        "YUBIHSM_SIGNING_CACHE",
    ):
        monkeypatch.delenv(name, raising=False)

    status = interceptor.main(["--signing_helper", "x"])

    assert status == 0
    (_, _, digest), *_ = yubihsm.device.log
    comment, entry = audit_log.read_text().splitlines()
    assert comment.endswith(
        " avbtool --signing_helper x # Result: 0 Try (log): 2",
    )
    assert entry.endswith("hash: " + digest.hex())


def test_signing_cache_failures_fall_back_to_running_the_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    interceptor = _load_interceptor()

    def fail(args: list[str]) -> None:
        raise OSError("cache unavailable")

    monkeypatch.setattr(interceptor, "from_cache", fail)
    monkeypatch.setattr(interceptor, "to_cache", fail)
    ran = tmp_path / "ran"
    make_script(tmp_path / "java", f'touch "{ran}"\n')
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    for name, value in {
        "SIGNING_COMMAND": "java",
        "DRY_RUN": "y",
        "YUBIHSM_SIGNING_CACHE": str(cache_dir),
        **path_prepending(tmp_path),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("YUBIHSM_LOCKFILE", raising=False)

    status = interceptor.main(
        ["-jar", "apksigner.jar", "sign", "--out", "o.apk", "i.apk"],
    )

    assert status == 0
    assert ran.exists()


@pytest.mark.parametrize(
    "argument",
    (
        "",
        "plain-0x2000.pem",
        "a b",
        "it's",
        "~home",
        "a~b",
        "#tag",
        "a,b=c",
        "$HOME",
        "line\nbreak",
        "tab\there",
        "\x1b\x01\x7f",
        "é",
        "a=~b",
        "--out=~/x",
        "x:~",
        "\x85",
        "\u2028",
    ),
)
def test_audit_comment_quotes_as_printf_q(argument: str) -> None:
    interceptor = _load_interceptor()
    bash = run(["bash", "-c", 'printf "%q" "$1"', "printf-q", argument])

    assert interceptor.printf_q(argument) == bash.stdout


@pytest.mark.parametrize(
    ("through_server", "failures"),
    ((True, 2), (False, 1)),
    ids=("server", "own"),
)
def test_retries_an_unacknowledged_extraction_without_writing_it_twice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
    through_server: bool,
    failures: int,
) -> None:
    interceptor = _load_interceptor()
    monkeypatch.setattr(interceptor.time, "sleep", stub(None))
    yubihsm.device.fail_next(COMMAND.SET_LOG_INDEX, times=failures)
    make_script(tmp_path / "avbtool", "exit 0\n")
    audit_log = tmp_path / "audit.log"
    service = YubiHsmSessionService(
        yubihsm_config(yubihsm),
        audit_log_path=audit_log,
    )
    server = SigningServer(tmp_path / "s.sock")
    server.add_service(
        {"yubihsm_extract_audit_log": service.extract_audit_log},
        service.close,
    )
    environment = _audit_environment(tmp_path, tmp_path, "avbtool", yubihsm)
    if through_server:
        environment["SIGNING_SERVER_SOCKET"] = str(server.socket_path)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    with server:
        status = interceptor.main(["add_hash_footer", "--signing_helper", "x"])

    assert status == 0
    (_, _, digest), *_ = yubihsm.device.log
    lines = audit_log.read_text().splitlines()
    entries = [line for line in lines if not line.startswith("#")]
    assert len(entries) == 1
    assert entries[0].endswith("hash: " + digest.hex())
    assert lines[-1].endswith("# Result: 0 Try (log): 2")
