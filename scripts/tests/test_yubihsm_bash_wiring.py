#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from yubihsm.defs import OBJECT
from yubihsm_emulator import Connector, EmulatedYubiHsm


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


def _hsm_environment(
    tmp_path: Path,
    yubihsm: Connector,
    **extra: str,
) -> dict[str, str]:
    return {
        "PYTHONPATH": str(SCRIPTS_DIR),
        "YUBIHSM_PYTHON_TOOLS": "y",
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "YUBIHSM_EXPORTABLE_DOMAIN": "1",
        "YUBIHSM_ONDEMAND_DOMAIN": "3",
        "YUBIHSM_UNEXPORTABLE_DOMAIN": "2",
        "YUBIHSM_KEY_CAPABILITIES": "sign-pkcs",
        "YUBIHSM_OPAQUE_CAPABILITIES": "get-opaque",
        "AUDIT_LOG_PATH": str(tmp_path / "audit.log"),
        **extra,
    }


@pytest.mark.parametrize(
    ("free_records", "succeeds", "message"),
    [
        (100, True, None),
        (1, False, "Failed to make enough space"),
    ],
)
def test_limit_ondemand_objects_fails_when_it_cannot_make_space(
    tmp_path: Path,
    yubihsm: Connector,
    free_records: int,
    succeeds: bool,
    message: str | None,
) -> None:
    device = yubihsm.device
    device.total_records = len(device.objects) + free_records
    result = run_yubihsm_functions(
        r"""
status=0
limit_ondemand_objects || status=$?
printf 'exit=%s\n' "$status"
""",
        env=_hsm_environment(
            tmp_path,
            yubihsm,
            KEY_DIR=str(tmp_path),
        ),
    )

    assert (result.stdout.strip() == "exit=0") is succeeds, result.stderr
    if message is not None:
        assert message in result.stderr


def test_limit_ondemand_objects_evicts_backed_up_ondemand_object(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    device.put_wrap_key(0x0010)
    device.put_asymmetric_key(0x2100, domains=0b1)
    device.put_asymmetric_key(0x2000, domains=0b100)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    for key_id in (0x2000, 0x2100):
        (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
            base64.b64encode(
                device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, 0x0010),
            ),
        )
    device.total_records = len(device.objects) + 4
    result = run_yubihsm_functions(
        r"""
limit_ondemand_objects
""",
        env=_hsm_environment(tmp_path, yubihsm, KEY_DIR=str(key_dir)),
    )

    assert result.returncode == 0, result.stderr
    assert device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is None
    assert device.get(0x2100, OBJECT.ASYMMETRIC_KEY) is not None
    audit_log = (tmp_path / "audit.log").read_text()
    assert "delete-object --object-id 0x2000 " in audit_log
    assert "limit-ondemand-objects" not in audit_log


def _key_with_certificate(device: EmulatedYubiHsm, key_id: int) -> None:
    key = device.put_asymmetric_key(key_id)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "key")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    device.put_certificate(
        key_id,
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()),
    )


def test_populate_loaded_keys_fails_when_the_hsm_is_unreachable(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    _key_with_certificate(yubihsm.device, 0x2000)
    yubihsm.plug(None)
    result = run_yubihsm_functions(
        r"""
declare -g -A fully_loaded_keys_map=()
status=0
populate_loaded_keys || status=$?
printf 'exit=%s\n' "$status"
printf 'count=%s\n' "${#fully_loaded_keys_map[@]}"
""",
        env=_hsm_environment(tmp_path, yubihsm),
    )

    assert result.stdout.splitlines()[0] != "exit=0"
    assert result.stdout.splitlines()[1] == "count=0"
    assert "503" in result.stderr


def test_read_yubihsm_deviceinfo_via_python_when_flagged(
    yubihsm: Connector,
) -> None:
    environment = {
        "PYTHONPATH": str(SCRIPTS_DIR),
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
    }
    result = run_yubihsm_functions(
        r"""
export YUBIHSM_PYTHON_TOOLS=y
read_yubihsm_deviceinfo
printf '%s\n' "$yubihsm_serial" "$yubihsm_partnumber" "$yubihsm_id"
""",
        env=environment,
    )

    lines = result.stdout.strip().splitlines()
    assert lines == ["123456", "YubiHSM2", "YubiHSM2-123456"], result.stderr


def test_populate_loaded_keys_via_python_when_flagged(
    yubihsm: Connector,
) -> None:
    _key_with_certificate(yubihsm.device, 0x2000)
    environment = {
        "PYTHONPATH": str(SCRIPTS_DIR),
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
    }
    result = run_yubihsm_functions(
        r"""
export YUBIHSM_PYTHON_TOOLS=y
declare -g -A fully_loaded_keys_map=()
populate_loaded_keys
if [ -n "${fully_loaded_keys_map[0x2000]:-}" ]; then
  echo OK
else
  echo "0x2000 not marked fully loaded" >&2
  exit 1
fi
""",
        env=environment,
    )

    assert result.stdout.strip().splitlines()[-1] == "OK", result.stderr


def test_limit_ondemand_objects_deletes_nothing_under_dry_run(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    device.put_wrap_key(0x0010)
    device.put_asymmetric_key(0x2000, domains=0b100)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "0x2000-asymmetric-key.yhw").write_bytes(
        base64.b64encode(device.wrapped(0x2000, OBJECT.ASYMMETRIC_KEY, 0x0010)),
    )
    device.total_records = len(device.objects) + 1
    result = run_yubihsm_functions(
        r"""
status=0
limit_ondemand_objects || status=$?
printf 'exit=%s\n' "$status"
""",
        env=_hsm_environment(
            tmp_path,
            yubihsm,
            DRY_RUN="y",
            KEY_DIR=str(key_dir),
        ),
    )

    assert device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is not None
    assert "yubihsm -a delete-object --object-id 0x2000" in result.stderr
