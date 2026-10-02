#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_cli_bytes


def run_sign_functions(
    body: str,
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    program = r"""
source <(sed '/^err=0$/,$d' "$1")
eval "$2"
"""
    result = run(
        [
            "bash",
            "-c",
            program,
            "sign-planning-parity-test",
            SCRIPTS_DIR / "sign.sh",
            body,
        ],
        cwd=cwd,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result


def run_python_planner(
    subcommand: str,
    *args: str,
    cwd: Path | None = None,
) -> list[str]:
    result = run_cli_bytes(
        [subcommand, *args],
        cwd=cwd,
        env={"PATH": "/usr/bin:/bin"},
        replace_env=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    fields = result.stdout.decode().split("\0")
    assert fields[-1] == ""
    return fields[:-1]


def _pairs(fields: list[str]) -> dict[str, str]:
    return dict(zip(fields[::2], fields[1::2], strict=True))


def _bash_lines(stdout: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in stdout.splitlines())


def test_gather_signable_devices_matches_bash() -> None:
    bash_result = run_sign_functions(
        """
devices=(redfin bramble unknown_device)
all_devices=(bramble redfin barbet)
gather_signable_devices_from_metadata
printf '%s\\n' "${signable_devices[*]}"
""",
    )

    python_fields = run_python_planner(
        "gather-signable-devices",
        "--devices",
        "redfin",
        "bramble",
        "unknown_device",
        "--all-devices",
        "bramble",
        "redfin",
        "barbet",
    )

    assert bash_result.stdout.split() == python_fields == ["bramble", "redfin"]


@pytest.mark.parametrize(
    ("target_files", "build_numbers"),
    (
        (
            (
                "calyx_bramble-target_files-2026081400.zip",
                "calyx_redfin-target_files-2026081300.zip",
                "calyx_bramble-target_files-2026081500.zip",
                "calyx_redfin-target_files-2026081600.zip",
                "calyx_barbet-target_files-2026081200.zip",
            ),
            None,
        ),
        (
            (
                "calyx_bramble-target_files-2026081400.zip",
                "calyx_bramble-target_files-2026081500.zip",
                "calyx_redfin-target_files-2026081600.zip",
                "calyx_redfin-target_files-2026081700.zip",
            ),
            (2026081400, 2026081700),
        ),
        (
            (
                "calyx_bramble-target_files-2026081400.zip",
                "calyx_redfin-target_files-2026081600.zip",
            ),
            (),
        ),
        ((), None),
        (
            ("calyx_bramble-target_files-2026081400.zip",),
            ("2026081400,", "eng"),
        ),
    ),
    ids=("gather-latest", "gather-to-sign", "blank", "empty", "non-numeric"),
)
def test_gather_builds_matches_bash(
    target_files: tuple[str, ...],
    build_numbers: tuple[int | str, ...] | None,
) -> None:
    files_literal = " ".join(target_files)
    numbers = [str(b) for b in build_numbers or ()]
    function = (
        "gather_latest_device_builds"
        if build_numbers is None
        else "gather_device_builds_to_sign"
    )
    bash_result = run_sign_functions(
        f"""
target_files=({files_literal})
BUILD_NUMBER='{" ".join(numbers) or " "}'
{function}
for device in "${{!device_to_next_build[@]}}"; do
  printf '%s=%s\\n' "$device" "${{device_to_next_build[$device]}}"
done
""",
    )

    python_fields = run_python_planner(
        "gather-device-builds",
        "--target-files",
        *target_files,
        *(() if build_numbers is None else ("--build-numbers", *numbers)),
    )

    assert _bash_lines(bash_result.stdout) == _pairs(python_fields)


@pytest.mark.parametrize(
    "avb_rollback_index_override",
    (None, 42),
    ids=("no-rollback", "rollback"),
)
def test_partition_by_key_availability_matches_bash(
    avb_rollback_index_override: str | None,
) -> None:
    rollback_line = (
        f"AVB_ROLLBACK_INDEX_OVERRIDE={avb_rollback_index_override}"
        if avb_rollback_index_override is not None
        else ""
    )
    bash_result = run_sign_functions(
        f"""
all_devices=(bramble barbet redfin)
device_to_next_build[bramble]=2026081500
device_to_next_build[barbet]=2026081500
device_to_next_build[redfin]=2026081500
device_to_prev_build[bramble]=2026081400
device_to_prev_build[redfin]=2026081300
device_to_preexisting_build[barbet]=2026081500
device_to_preexisting_build[redfin]=2026081500
{rollback_line}
populate_devices_with_loaded_keys_arrays() {{
  devices_with_loaded_keys+=(bramble barbet)
  devices_without_loaded_keys+=(redfin)
}}
sort_and_separate_devices_by_key_availability
printf 'sign_with=%s\\n' "${{sign_pairs_with_loaded_keys[*]}}"
printf 'sign_without=%s\\n' "${{sign_pairs_without_loaded_keys[*]}}"
printf 'incr_with=%s\\n' "${{incremental_triples_with_loaded_keys[*]}}"
printf 'incr_without=%s\\n' "${{incremental_triples_without_loaded_keys[*]}}"
""",
    )

    rollback_args = (
        ["--avb-rollback-index-override", avb_rollback_index_override]
        if avb_rollback_index_override is not None
        else []
    )
    python_fields = run_python_planner(
        "partition-signing-plan",
        "--devices-with-loaded-keys",
        "bramble",
        "barbet",
        "--devices-without-loaded-keys",
        "redfin",
        "--device-next-build=bramble=2026081500",
        "--device-next-build=barbet=2026081500",
        "--device-next-build=redfin=2026081500",
        "--device-prev-build=bramble=2026081400",
        "--device-prev-build=redfin=2026081300",
        "--device-preexisting-build=barbet=2026081500",
        "--device-preexisting-build=redfin=2026081500",
        *rollback_args,
    )

    python_buckets: dict[str, set[str]] = {
        "sign_with": set(),
        "sign_without": set(),
        "incr_with": set(),
        "incr_without": set(),
    }
    for bucket, value in zip(
        python_fields[::2],
        python_fields[1::2],
        strict=True,
    ):
        python_buckets[bucket].add(value)
    bash_buckets = {
        bucket: set(value.split())
        for bucket, value in _bash_lines(bash_result.stdout).items()
    }
    assert bash_buckets == python_buckets


def _make_archive_tree(root: Path) -> None:
    for name, target_files_name in (
        ("release-bramble-2026081300", "bramble-target_files-2026081300.zip"),
        ("release-bramble-2026081400", "bramble-target_files-2026081400.zip"),
        ("release-redfin-2026081200", "redfin-target_files-2026081200.zip"),
        ("release-redfin-2026081500", "redfin-target_files-2026081500.zip"),
        ("release-barbet-2026081100", None),
    ):
        directory = root / "archive" / name
        directory.mkdir(parents=True)
        if target_files_name:
            (directory / target_files_name).touch()


@pytest.mark.parametrize(
    ("prev_build_number", "bramble_prev_build"),
    [
        ("", "2026081400"),
        ("2026081300", "2026081300"),
        ("2026081300,", None),
    ],
)
def test_find_prev_signed_device_builds_matches_bash(
    tmp_path: Path,
    prev_build_number: str,
    bramble_prev_build: str | None,
) -> None:
    _make_archive_tree(tmp_path)

    bash_result = run_sign_functions(
        f"PREV_BUILD_NUMBER={shlex.quote(prev_build_number)}\n"
        + """
BUILD_NUMBER='2026081500'
device_to_next_build[bramble]=2026081500
device_to_next_build[redfin]=2026081500
device_to_next_build[barbet]=2026081500
find_prev_signed_device_builds
for device in "${!device_to_prev_build[@]}"; do
  printf 'prev:%s=%s\\n' "$device" "${device_to_prev_build[$device]}"
done
for device in "${!device_to_preexisting_build[@]}"; do
  printf 'preexisting:%s=%s\\n' "$device" \
    "${device_to_preexisting_build[$device]}"
done
printf 'sorted=%s\\n' "${prev_builds_sorted[*]}"
""",
        cwd=tmp_path,
    )

    python_fields = run_python_planner(
        "find-prev-builds",
        "--archive-dirs",
        *sorted(p.name for p in (tmp_path / "archive").iterdir()),
        "--device-next-build=bramble=2026081500",
        "--device-next-build=redfin=2026081500",
        "--device-next-build=barbet=2026081500",
        "--build-numbers",
        "2026081500",
        *(
            ["--prev-build-numbers", *prev_build_number.split()]
            if prev_build_number
            else []
        ),
        cwd=tmp_path,
    )

    python_lines: list[str] = []
    sorted_builds: list[str] = []
    fields = iter(python_fields)
    for tag in fields:
        if tag == "sorted":
            sorted_builds.append(next(fields))
        else:
            python_lines.append(f"{tag}:{next(fields)}={next(fields)}")
    python_lines.append(f"sorted={' '.join(sorted_builds)}")

    assert sorted(bash_result.stdout.splitlines()) == sorted(python_lines)
    assert [
        line for line in python_lines if line.startswith("prev:bramble=")
    ] == ([f"prev:bramble={bramble_prev_build}"] if bramble_prev_build else [])
    assert "preexisting:redfin=2026081500" in python_lines
    assert not any("barbet" in line for line in python_lines)
