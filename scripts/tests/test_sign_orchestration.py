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


def run_sign_functions(
    body: str,
    *,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Load sign.sh's function definitions without running its main() and run
    body. sign.sh derives sign_scriptpath from $0, which resolves to cwd
    here, so release.sh and generate_delta.sh in cwd stand in for the
    scripts next to sign.sh.
    """
    program = r"""
source <(sed '/^err=0$/,$d' "$1")
source "$3"
eval "$2"
"""
    return run(
        [
            "bash",
            "-c",
            program,
            "sign-function-test",
            SCRIPTS_DIR / "sign.sh",
            body,
            SCRIPTS_DIR / "common.include.sh",
        ],
        input_text=input_text,
        cwd=cwd,
        env=env,
    )


def test_sign_planner_selects_latest_build_per_device() -> None:
    result = run_sign_functions(
        r"""
target_files=(
  calyx_bramble-target_files-2026081400.zip
  calyx_redfin-target_files-2026081300.zip
  calyx_bramble-target_files-2026081500.zip
  calyx_redfin-target_files-2026081600.zip
)
gather_latest_device_builds
printf 'bramble=%s\n' "${device_to_next_build[bramble]}"
printf 'redfin=%s\n' "${device_to_next_build[redfin]}"
printf 'ordered=%s\n' "${next_builds_sorted[*]}"
""",
    )

    assert result.stdout.splitlines() == [
        "bramble=2026081500",
        "redfin=2026081600",
        "ordered=2026081500 2026081600",
    ]


def test_sign_planner_filters_requested_build_numbers() -> None:
    result = run_sign_functions(
        r"""
target_files=(
  calyx_bramble-target_files-2026081400.zip
  calyx_bramble-target_files-2026081500.zip
  calyx_redfin-target_files-2026081600.zip
)
BUILD_NUMBER='2026081400 2026081600'
gather_device_builds_to_sign
printf 'bramble=%s\n' "${device_to_next_build[bramble]}"
printf 'redfin=%s\n' "${device_to_next_build[redfin]}"
""",
    )

    assert result.stdout.splitlines() == [
        "bramble=2026081400",
        "redfin=2026081600",
    ]


def test_sign_planner_partitions_devices_and_applies_rollback_target() -> None:
    result = run_sign_functions(
        r"""
all_devices=(bramble redfin)
device_to_next_build[bramble]=2026081500
device_to_next_build[redfin]=2026081500
device_to_prev_build[bramble]=2026081400
device_to_prev_build[redfin]=2026081300
AVB_ROLLBACK_INDEX_OVERRIDE=42
populate_devices_with_loaded_keys_arrays() {
  devices_with_loaded_keys+=(bramble)
  devices_without_loaded_keys+=(redfin)
}
sort_and_separate_devices_by_key_availability
printf 'loaded-sign=%s\n' "${sign_pairs_with_loaded_keys[*]}"
printf 'missing-sign=%s\n' "${sign_pairs_without_loaded_keys[*]}"
printf 'loaded-delta=%s\n' "${incremental_triples_with_loaded_keys[*]}"
printf 'missing-delta=%s\n' "${incremental_triples_without_loaded_keys[*]}"
""",
    )

    assert result.stdout.splitlines() == [
        "loaded-sign=bramble,2026081500,2026081501",
        "missing-sign=redfin,2026081500,2026081501",
        "loaded-delta=bramble,2026081400,2026081500",
        "missing-delta=redfin,2026081300,2026081500",
    ]


def test_gather_signable_devices_propagates_python_failure() -> None:
    """
    A planner command that fails must fail the step instead of yielding
    an empty, successful result.
    """
    result = run_sign_functions(
        r"""
python3() { return 7; }
USE_PYTHON_SIGN_PLANNING=y
devices=(bramble)
all_devices=(bramble redfin)
status=0
gather_signable_devices_from_metadata || status=$?
printf 'exit=%s\n' "$status"
printf 'devices=%s\n' "${signable_devices[*]:-<empty>}"
""",
    )

    assert result.stdout.splitlines() == [
        "exit=7",
        "devices=<empty>",
    ]


def test_sort_and_separate_devices_propagates_python_failure() -> None:
    result = run_sign_functions(
        r"""
python3() { return 9; }
USE_PYTHON_SIGN_PLANNING=y
all_devices=(bramble redfin)
device_to_next_build[bramble]=2026081500
device_to_next_build[redfin]=2026081500
populate_devices_with_loaded_keys_arrays() {
  devices_with_loaded_keys+=(bramble)
  devices_without_loaded_keys+=(redfin)
}
status=0
sort_and_separate_devices_by_key_availability || status=$?
printf 'exit=%s\n' "$status"
printf 'loaded-sign=%s\n' "${sign_pairs_with_loaded_keys[*]:-<empty>}"
""",
    )

    assert result.stdout.splitlines() == [
        "exit=9",
        "loaded-sign=<empty>",
    ]


def test_confirm_auto_answers_yes_when_sign_assume_yes_is_set() -> None:
    result = run_sign_functions(
        r"""
SIGN_ASSUME_YES=y
status=0
confirm "Test prompt?" || status=$?
printf 'exit=%s\n' "$status"
""",
    )

    assert result.stdout.splitlines()[-1] == "exit=0"
    assert "auto-answered by SIGN_ASSUME_YES=y" in result.stdout


def test_try_fails_fast_under_sign_assume_yes_instead_of_retrying() -> None:
    """
    Under SIGN_ASSUME_YES a failing step must surface instead of being
    retried forever.
    """
    result = run_sign_functions(
        r"""
SIGN_ASSUME_YES=y
call_count_file=$(mktemp)
always_fails() {
  count=$(cat "$call_count_file" 2>/dev/null || echo 0)
  count=$((count + 1))
  echo "$count" > "$call_count_file"
  return 1
}
status=0
try always_fails || status=$?
printf 'exit=%s\n' "$status"
printf 'calls=%s\n' "$(cat "$call_count_file")"
rm -f "$call_count_file"
""",
    )

    assert result.stdout.splitlines() == ["exit=1", "calls=1"]
    assert "not retrying" in result.stderr


@pytest.mark.parametrize(
    ("function", "item"),
    (("sign_builds", "bramble,1,1"), ("generate_incrementals", "bramble,1,2")),
)
def test_sign_execution_returns_1_whatever_parallel_reports(
    tmp_path: Path,
    function: str,
    item: str,
) -> None:
    result = run_sign_functions(
        f"""
NUM_SIGN_JOBS=2
NUM_INCREMENTAL_JOBS=2
parallel() {{ return 9; }}
status=0
{function} '{item}' || status=$?
printf 'exit=%s\\n' "$status"
""",
        env={"TMPDIR": str(tmp_path)},
    )

    assert result.stdout.splitlines()[-1] == "exit=1"
    assert "failed for 9 devices." in result.stderr


def test_sign_execution_loads_missing_keys_between_device_groups() -> None:
    result = run_sign_functions(
        r"""
no_sign=n
no_incremental=n
sign_pairs_with_loaded_keys=('bramble,2,2')
incremental_triples_with_loaded_keys=('bramble,1,2')
devices_without_loaded_keys=(redfin)
sign_pairs_without_loaded_keys=('redfin,2,2')
incremental_triples_without_loaded_keys=('redfin,1,2')
sign_builds() { printf 'sign %s\n' "$*"; }
generate_incrementals() { printf 'delta %s\n' "$*"; }
ensure_all_keys_available_for_devices() { printf 'load %s\n' "$*"; }
upload_logs() { :; }
try() { "$@"; }
do_or_show
""",
    )

    assert result.stdout.splitlines() == [
        "sign bramble,2,2",
        "delta bramble,1,2",
        "load redfin",
        "sign redfin,2,2",
        "delta redfin,1,2",
    ]


FAKE_RELEASE_SH = """\
#!/bin/sh
set -e
[ -e "keys/$1" ]
mkdir -p "out/release-$1-$BUILD_NUMBER"
printf '%s' "signed-$1" > "out/release-$1-$BUILD_NUMBER/output.bin"
"""

FAKE_GENERATE_DELTA_SH = """\
#!/bin/sh
set -e
[ -e "keys/$1" ]
printf '%s' "delta-$1" > "archive/release-$1-$3/$1-incremental-$2-$3.zip"
"""


def test_do_or_show_loads_missing_keys_before_signing_through_python(
    tmp_path: Path,
) -> None:
    for name, content in (
        ("release.sh", FAKE_RELEASE_SH),
        ("generate_delta.sh", FAKE_GENERATE_DELTA_SH),
    ):
        tool = tmp_path / name
        tool.write_text(content)
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "bramble").touch()
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    result = run_sign_functions(
        r"""
USE_PYTHON_SIGN_EXECUTION=y
NUM_SIGN_JOBS=2
NUM_INCREMENTAL_JOBS=2
no_sign=n
no_incremental=n
sign_pairs_with_loaded_keys=('bramble,2,2')
incremental_triples_with_loaded_keys=('bramble,1,2')
devices_without_loaded_keys=(redfin)
sign_pairs_without_loaded_keys=('redfin,2,2')
incremental_triples_without_loaded_keys=('redfin,1,2')
ensure_all_keys_available_for_devices() { touch "${@/#/keys/}"; }
SKIP_LOG_UPLOAD=true
do_or_show
""",
        cwd=tmp_path,
        env={
            "TMPDIR": str(tmp_path / "tmp"),
            "PYTHONPATH": str(SCRIPTS_DIR),
        },
    )

    assert result.returncode == 0, result.stderr
    archive = tmp_path / "archive"
    assert {
        str(path.relative_to(archive)): path.read_text()
        for path in archive.rglob("*")
        if path.is_file()
    } == {
        "release-bramble-2/output.bin": "signed-bramble",
        "release-bramble-2/bramble-incremental-1-2.zip": "delta-bramble",
        "release-redfin-2/output.bin": "signed-redfin",
        "release-redfin-2/redfin-incremental-1-2.zip": "delta-redfin",
    }


@pytest.mark.parametrize("parallel_status", (0, 1), ids=("success", "failure"))
def test_sign_cleanup_removes_every_temporary_directory(
    tmp_path: Path,
    parallel_status: int,
) -> None:
    result = run_sign_functions(
        f"""
TMPDIR=$(mktemp -d -p "$ORIGINAL_TMPDIR" signing_tmp.XXXXXXXX)
export TMPDIR
STATEDIR=
SKIP_LOG_UPLOAD=true
NUM_SIGN_JOBS=2
NUM_INCREMENTAL_JOBS=2
parallel() {{ return {parallel_status}; }}
sign_builds 'bramble,1,1' || true
generate_incrementals 'bramble,1,2' || true
sign_cleanup
""",
        env={"TMPDIR": str(tmp_path)},
    )

    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


def test_confirm_fails_promptly_on_closed_stdin_instead_of_spinning() -> None:
    result = run_sign_functions(
        r"""
status=0
confirm "Test prompt?" || status=$?
printf 'exit=%s\n' "$status"
""",
        input_text="",
    )

    assert result.stdout.strip().endswith("exit=1")


def test_ask_variable_fails_promptly_on_closed_stdin_instead_of_spinning() -> (
    None
):
    result = run_sign_functions(
        r"""
status=0
ask_variable SOME_VAR "" n y || status=$?
printf 'exit=%s\n' "$status"
""",
        input_text="",
    )

    assert result.stdout.splitlines()[-1] == "exit=1"


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ('ask_variable SOME_VAR "3" n y', "exit=0 value=3"),
        ('ask_variable SOME_VAR "dflt" n n', "exit=0 value=dflt"),
        ('ask_variable SOME_VAR "" n n', "exit=0 value="),
    ],
)
def test_ask_variable_takes_the_default_on_closed_stdin(
    call: str,
    expected: str,
) -> None:
    result = run_sign_functions(
        f"""
status=0
{call} || status=$?
printf 'exit=%s value=%s\\n' "$status" "${{SOME_VAR:-}}"
""",
        input_text="",
    )

    assert result.stdout.splitlines()[-1] == expected


def test_confirm_accepts_an_answer_without_a_trailing_newline() -> None:
    result = run_sign_functions(
        r"""
status=0
confirm "Test prompt?" || status=$?
printf 'exit=%s\n' "$status"
""",
        input_text="y",
    )

    assert result.stdout.strip().endswith("exit=0")


@pytest.mark.parametrize("python", (False, True), ids=("bash", "python"))
def test_sign_planning_skips_names_without_a_numeric_build(
    tmp_path: Path,
    python: bool,
) -> None:
    for name in (
        "calyx_bramble-target_files-latest.zip",
        "calyx_redfin-target_files-2026081500.zip",
    ):
        (tmp_path / name).touch()
    for device, build in (("bramble", "latest"), ("redfin", "2026080100")):
        archived = tmp_path / "archive" / f"release-{device}-{build}"
        archived.mkdir(parents=True)
        (archived / f"{device}-target_files-{build}.zip").touch()
    body = r"""
find_target_files
gather_latest_device_builds
find_prev_signed_device_builds
for device in "${!device_to_next_build[@]}"; do
  printf 'next %s=%s\n' "$device" "${device_to_next_build[$device]}"
done
for device in "${!device_to_prev_build[@]}"; do
  printf 'prev %s=%s\n' "$device" "${device_to_prev_build[$device]}"
done
"""
    env = {"PYTHONPATH": str(SCRIPTS_DIR)}
    if python:
        env["USE_PYTHON_SIGN_PLANNING"] = "y"
    result = run_sign_functions(body, cwd=tmp_path, env=env)

    assert result.returncode == 0, result.stderr
    assert "integer expression expected" not in result.stderr
    assert sorted(result.stdout.splitlines()) == [
        "next redfin=2026081500",
        "prev redfin=2026080100",
    ]


def test_use_python_sign_execution_signs_without_gnu_parallel(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "release.sh"
    tool.write_text(FAKE_RELEASE_SH)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "bramble").touch()
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    body = r"""
NUM_SIGN_JOBS=2
parallel() { echo "parallel: command not found" >&2; return 127; }
status=0
sign_builds 'bramble,2,2' || status=$?
printf 'exit=%s\n' "$status"
"""
    results = {
        flag: run_sign_functions(
            body,
            cwd=tmp_path,
            env={
                "TMPDIR": str(tmp_path / "tmp"),
                "PYTHONPATH": str(SCRIPTS_DIR),
                "USE_PYTHON_SIGN_EXECUTION": flag,
            },
        )
        for flag in ("", "y")
    }

    assert results[""].stdout.splitlines()[-1] == "exit=1"
    assert results["y"].stdout.splitlines()[-1] == "exit=0"
    signed = tmp_path / "archive" / "release-bramble-2" / "output.bin"
    assert signed.read_text() == "signed-bramble"


def test_use_python_sign_orchestration_reports_its_vendor_limit(
    tmp_path: Path,
) -> None:
    """
    The Python orchestrator supports only the softhsm and yubihsm
    vendors and says so, where sign.sh looks for a vendor include.
    """
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    work = tmp_path / "work"
    (work / "logs").mkdir(parents=True)
    (work / "logs" / "upload.py").write_text("#!/bin/sh\n")
    (work / "tmp").mkdir()
    (work / "calyx_bramble-target_files-2026081500.zip").touch()

    results = {
        flag: run(
            ["timeout", "60", SCRIPTS_DIR / "sign.sh"],
            cwd=work,
            env={
                "TMPDIR": str(work / "tmp"),
                "DEVICES_FILE": str(devices),
                "SIGN_ASSUME_YES": "y",
                "SKIP_LOG_UPLOAD": "true",
                "PKCS11_VENDOR": "acme",
                "BUILD_NUMBER": "2026081500",
                "USE_PYTHON_SIGN_ORCHESTRATION": flag,
            },
            input_text="",
            check=False,
        )
        for flag in ("", "y")
    }

    assert results[""].returncode != 0
    assert results["y"].returncode == 1
    assert "Could not find PKCS#11 vendor include script for 'acme'" in (
        results[""].stderr
    )
    assert (
        "PKCS11_VENDOR='acme' is not supported by the Python orchestrator. "
        "Unset USE_PYTHON_SIGN_ORCHESTRATION"
    ) in results["y"].stderr


def test_provisioning_try_fails_fast_under_sign_assume_yes() -> None:
    program = r"""
eval "$(sed -n '/^try() {/,/^}/p' "$1")"
source "$2"
SIGN_ASSUME_YES=y
no_recover=
calls=0
always_fails() { calls=$((calls + 1)); return 1; }
status=0
try always_fails || status=$?
printf 'exit=%s calls=%s\n' "$status" "$calls"
"""
    result = run(
        [
            "bash",
            "-c",
            program,
            "provision-try-test",
            SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.provision.sh",
            SCRIPTS_DIR / "common.include.sh",
        ],
        check=False,
    )

    assert result.stdout.splitlines() == ["exit=1 calls=1"], result.stderr
    assert "not retrying" in result.stderr
