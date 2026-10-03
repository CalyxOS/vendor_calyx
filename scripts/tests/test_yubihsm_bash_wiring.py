#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from yubihsm_emulator import Connector


def run_yubihsm_functions(
    body: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Source vendor.yubihsm.include.sh's function definitions and run body.

    Args:
        body: Bash statements to execute after sourcing the include file.
        env: Additional environment variables for the subprocess.

    Returns:
        The Bash subprocess result.
    """
    program = r"""
source "$1" || exit $?
eval "$2"
"""
    return run(
        [
            "bash",
            "-c",
            program,
            "yubihsm-wiring-test",
            SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.include.sh",
            body,
        ],
        env=env,
    )


@pytest.fixture
def fake_yubihsm_connector_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "fake-yubihsm-connector"
    binary.write_text("#!/bin/sh\nsleep 300\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def test_connector_start_stop_via_python_when_flagged(
    fake_yubihsm_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    result = run_yubihsm_functions(
        rf"""
export YUBIHSM_PYTHON_TOOLS=y
export YUBIHSM_CONNECTOR_BIN={fake_yubihsm_connector_binary}
maybe_start_yubihsm_connector {pid_file}
[ -e {pid_file} ] || {{ echo "no pidfile after start" >&2; exit 1; }}
pid=$(cat {pid_file})
kill -0 "$pid" || {{ echo "connector not running after start" >&2; exit 1; }}
printf '%s\n' "$pid"
maybe_stop_yubihsm_connector
if [ -e {pid_file} ]; then
  echo "pidfile still present after stop" >&2
  exit 1
fi
if kill -0 "$pid" 2>/dev/null; then
  echo "connector still running after stop" >&2
  exit 1
fi
echo OK
""",
        env={"PYTHONPATH": str(SCRIPTS_DIR)},
    )

    lines = result.stdout.splitlines()
    assert lines[-1] == "OK", result.stderr


def test_connector_restart_via_python_starts_beside_another_connector(
    fake_yubihsm_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    result = run_yubihsm_functions(
        rf"""
export YUBIHSM_PYTHON_TOOLS=y
export YUBIHSM_CONNECTOR_BIN={fake_yubihsm_connector_binary}
{fake_yubihsm_connector_binary} >/dev/null 2>&1 &
other=$!
maybe_start_or_restart_yubihsm_connector {pid_file}
status=$?
pid=$(cat {pid_file} 2>/dev/null || true)
maybe_stop_yubihsm_connector
pkill -P "$other"
kill "$other"
distinct=$([ -n "$pid" ] && [ "$pid" != "$other" ] && echo distinct)
printf 'status=%s other=%s\n' "$status" "$distinct"
""",
        env={"PYTHONPATH": str(SCRIPTS_DIR)},
    )

    assert result.stdout.splitlines()[-1] == "status=0 other=distinct", (
        result.stderr
    )


def test_pkcs11_tool_runs_the_configured_binary_after_sourcing_twice(
    tmp_path: Path,
) -> None:
    record = tmp_path / "args"
    tool = tmp_path / "pkcs11-tool"
    tool.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {record}\nexit 3\n')
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    result = run_yubihsm_functions(
        r"""
source "$1"
status=0
"$PKCS11_TOOL_BIN" --module /usr/lib/softhsm/libsofthsm2.so -L || status=$?
printf 'exit=%s\n' "$status"
""",
        env={"PKCS11_TOOL_BIN": str(tool)},
    )

    assert result.stdout.splitlines() == ["exit=3"], result.stderr
    assert record.read_text().splitlines() == [
        "--module",
        "/usr/lib/softhsm/libsofthsm2.so",
        "-L",
    ]


def test_connector_start_stop_via_bash_when_not_flagged(
    fake_yubihsm_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    result = run_yubihsm_functions(
        rf"""
export YUBIHSM_CONNECTOR_BIN={fake_yubihsm_connector_binary}
maybe_start_yubihsm_connector {pid_file}
[ -e {pid_file} ] || {{ echo "no pidfile after start" >&2; exit 1; }}
pid=$(cat {pid_file})
kill -0 "$pid" || {{ echo "connector not running after start" >&2; exit 1; }}
maybe_stop_yubihsm_connector
if [ -e {pid_file} ]; then
  echo "pidfile still present after stop" >&2
  exit 1
fi
if kill -0 "$pid" 2>/dev/null; then
  echo "connector still running after stop" >&2
  exit 1
fi
echo OK
""",
    )

    lines = result.stdout.splitlines()
    assert lines[-1] == "OK", result.stderr


def test_extract_logs_via_python_when_flagged(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "audit.log"
    bash_only = tmp_path / "bash-only"
    bash_only.mkdir()
    audit_script = bash_only / "vendor.yubihsm.audit.logs.py"
    audit_script.write_text("#!/bin/sh\nexit 7\n")
    audit_script.chmod(0o755)
    environment = {
        "PYTHONPATH": str(SCRIPTS_DIR),
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
    }
    run_yubihsm_functions(
        rf"""
_our_path={bash_only}
export YUBIHSM_PYTHON_TOOLS=y
export AUDIT_LOG_PATH={log_path}
extract_logs "bash wiring test"
""",
        env=environment,
    )

    contents = log_path.read_text()
    assert "bash wiring test" in contents
    assert "hash: " + yubihsm.device.log[0][2].hex() in contents
    assert yubihsm.device.unread_log() == []
