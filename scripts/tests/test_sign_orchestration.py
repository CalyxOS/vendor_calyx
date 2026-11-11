#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

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
