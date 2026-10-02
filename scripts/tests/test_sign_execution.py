#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import (
    SCRIPTS_DIR,
    default_signal_dispositions,
    process_alive,
    run,
    run_cli,
    wait_until,
)

FAKE_RELEASE_TOOL = """\
#!/bin/bash
set -e
device="$1"
for fail_device in $FAIL_DEVICES; do
  if [ "$device" = "$fail_device" ]; then
    exit 23
  fi
done
out_build=$BUILD_NUMBER
if [ -n "${AVB_ROLLBACK_INDEX_OVERRIDE:-}" ]; then
  out_build=$((10#$BUILD_NUMBER + 1))
fi
mkdir -p "out/release-$device-$out_build"
printf '%s' "signed-$device-$out_build" \
  > "out/release-$device-$out_build/output.bin"
"""

FAKE_CONCURRENCY_RELEASE_TOOL = """\
#!/bin/sh
set -e
device="$1"
(
  flock -x 200
  count=$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)
  count=$((count + 1))
  echo "$count" > "$COUNTER_FILE"
  max=$(cat "$MAX_FILE" 2>/dev/null || echo 0)
  if [ "$count" -gt "$max" ]; then echo "$count" > "$MAX_FILE"; fi
) 200>"$COUNTER_LOCK"
sleep 0.3
(
  flock -x 200
  count=$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)
  count=$((count - 1))
  echo "$count" > "$COUNTER_FILE"
) 200>"$COUNTER_LOCK"
mkdir -p "out/release-$device-$BUILD_NUMBER"
printf ok > "out/release-$device-$BUILD_NUMBER/output.bin"
"""

FAKE_SLOW_RELEASE_TOOL = """\
#!/bin/sh
sleep 30 &
echo $! > "$CHILD_PIDFILE"
wait
"""

FAKE_GENERATE_DELTA_TOOL = """\
#!/bin/sh
set -e
device="$1"
old="$2"
new="$3"
for fail_device in $FAIL_DEVICES; do
  if [ "$device" = "$fail_device" ]; then
    exit 23
  fi
done
mkdir -p "incrementals"
printf '%s' "delta-$device-$old-$new" > "incrementals/$device-$old-$new.bin"
"""


def _install_tool(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_sign_builds(
    root: Path,
    pairs: list[str],
    *,
    release_tool: str = FAKE_RELEASE_TOOL,
    jobs: int = 2,
    environment: dict[str, str] | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    release_script = root / "release.sh"
    _install_tool(release_script, release_tool)
    archive_dir = root / "archive"
    archive_dir.mkdir(exist_ok=True)
    original_tmpdir = root / "tmp"
    original_tmpdir.mkdir(exist_ok=True)
    return run_cli(
        [
            "sign-builds",
            "--jobs",
            str(jobs),
            "--release-script",
            release_script,
            "--archive-dir",
            archive_dir,
            "--original-tmpdir",
            original_tmpdir,
            "--pairs",
            *pairs,
        ],
        cwd=root,
        env=environment,
        check=check,
    )


def run_generate_incrementals(
    root: Path,
    triples: list[str],
    *,
    generate_delta_tool: str = FAKE_GENERATE_DELTA_TOOL,
    jobs: int = 2,
    environment: dict[str, str] | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    generate_delta_script = root / "generate_delta.sh"
    _install_tool(generate_delta_script, generate_delta_tool)
    original_tmpdir = root / "tmp"
    original_tmpdir.mkdir(exist_ok=True)
    return run_cli(
        [
            "generate-incrementals",
            "--jobs",
            str(jobs),
            "--generate-delta-script",
            generate_delta_script,
            "--original-tmpdir",
            original_tmpdir,
            "--triples",
            *triples,
        ],
        cwd=root,
        env=environment,
        check=check,
    )


def test_sign_builds_moves_successful_devices_into_archive(
    tmp_path: Path,
) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100", "redfin,200,200", "raven,300,300"],
    )

    assert result.returncode == 0, result.stderr
    for device, target_build in (
        ("bramble", 100),
        ("redfin", 200),
        ("raven", 300),
    ):
        output = (
            tmp_path
            / "archive"
            / f"release-{device}-{target_build}"
            / "output.bin"
        )
        assert output.read_text() == f"signed-{device}-{target_build}"
    assert list((tmp_path / "tmp").iterdir()) == []


def test_sign_builds_gives_its_jobs_no_standard_input(tmp_path: Path) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100"],
        release_tool="""\
#!/bin/sh
[ "$(readlink /proc/$$/fd/0)" = /dev/null ] || exit 1
mkdir -p "out/release-$1-$BUILD_NUMBER"
printf ok > "out/release-$1-$BUILD_NUMBER/output.bin"
""",
    )

    assert result.returncode == 0, result.stderr


def test_sign_builds_moves_using_target_build_not_build(
    tmp_path: Path,
) -> None:
    """
    The mv step must key off the third (target_build) field, not the
    second (build) field, because AVB_ROLLBACK_INDEX_OVERRIDE makes
    release.sh (and this fake double, mirroring it) bump its output
    directory by one.
    """
    result = run_sign_builds(
        tmp_path,
        ["raven,300,301"],
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
    )

    assert result.returncode == 0, result.stderr
    output = tmp_path / "archive" / "release-raven-301" / "output.bin"
    assert output.read_text() == "signed-raven-301"


def test_generate_incrementals_keeps_zero_padded_build_numbers(
    tmp_path: Path,
) -> None:
    result = run_generate_incrementals(tmp_path, ["bramble,0041,0042"])

    assert result.returncode == 0, result.stderr
    delta = tmp_path / "incrementals" / "bramble-0041-0042.bin"
    assert delta.read_text() == "delta-bramble-0041-0042"


def test_sign_builds_partial_failure_completes_other_devices(
    tmp_path: Path,
) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100", "redfin,200,200", "raven,300,300"],
        environment={"FAIL_DEVICES": "redfin raven"},
    )

    assert result.returncode == 1
    assert "Signing failed for 2 devices." in result.stderr
    assert (
        "You can run this script again to sign the devices that failed."
        in result.stderr
    )
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()
    assert not (tmp_path / "archive" / "release-redfin-200").exists()
    assert not (tmp_path / "archive" / "release-raven-300").exists()
    assert list((tmp_path / "tmp").iterdir()) == []


def test_sign_builds_archives_jobs_whose_output_is_not_utf8(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    _install_tool(
        release_script,
        FAKE_RELEASE_TOOL.replace(
            'device="$1"\n',
            "device=\"$1\"\nprintf '\\377 not utf-8\\n'\n",
            1,
        ),
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    result = subprocess.run(
        [
            "python3",
            "-m",
            "signing",
            "sign-builds",
            "--jobs",
            "2",
            "--release-script",
            str(release_script),
            "--archive-dir",
            "archive",
            "--original-tmpdir",
            "tmp",
            "--pairs",
            "bramble,100,100",
            "redfin,200,200",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR), "LC_ALL": "C"},
        capture_output=True,
        timeout=30,
        check=False,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == 0, result.stderr
    assert b"bramble,100,100\t\xff not utf-8\n" in result.stdout
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()
    assert (tmp_path / "archive" / "release-redfin-200").is_dir()


def test_sign_builds_counts_a_job_that_cannot_start_as_failed(
    tmp_path: Path,
) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100"],
        release_tool="not a script\n",
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "Signing failed for 1 devices." in result.stderr


def test_sign_builds_counts_a_failed_move_as_a_failed_device(
    tmp_path: Path,
) -> None:
    (tmp_path / "archive" / "release-redfin-200").mkdir(parents=True)

    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100", "redfin,200,200", "raven,300,300"],
    )

    assert result.returncode == 1
    assert "Signing failed for 1 devices." in result.stderr
    assert "redfin,200,200\tDestination path" in result.stdout
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()
    assert (tmp_path / "archive" / "release-raven-300").is_dir()


def test_sign_builds_leaves_no_partial_release_in_the_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from signing import sign_execution

    release_script = tmp_path / "release.sh"
    release_script.write_text(FAKE_RELEASE_TOOL)
    release_script.chmod(0o755)
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    def move_part_way(source: str, destination: str) -> None:
        Path(destination).mkdir()
        (Path(destination) / "output.bin").write_text("partial")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(shutil, "move", move_part_way)
    monkeypatch.chdir(tmp_path)

    status = sign_execution.sign_builds(
        [("bramble", 100, 100)],
        release_script=release_script,
        archive_dir=Path("archive"),
        jobs=1,
        original_tmpdir=tmp_path / "tmp",
    )

    assert status == 1
    assert [path.name for path in (tmp_path / "archive").iterdir()] == [
        ".release-bramble-100.partial",
    ]


def test_sign_builds_respects_job_concurrency_ceiling(tmp_path: Path) -> None:
    counter_lock = tmp_path / "counter.lock"
    counter_file = tmp_path / "counter"
    max_file = tmp_path / "max"

    result = run_sign_builds(
        tmp_path,
        [f"device{i},{i},{i}" for i in range(4)],
        release_tool=FAKE_CONCURRENCY_RELEASE_TOOL,
        jobs=2,
        environment={
            "COUNTER_LOCK": str(counter_lock),
            "COUNTER_FILE": str(counter_file),
            "MAX_FILE": str(max_file),
        },
    )

    assert result.returncode == 0, result.stderr
    observed_max = int(max_file.read_text().strip())
    assert 1 <= observed_max <= 2


def test_sign_builds_waits_for_a_job_that_closes_its_output(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    _install_tool(
        release_script,
        "#!/bin/sh\n"
        "exec > /dev/null 2>&1\n"
        "sleep 0.5\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    result = subprocess.run(
        [
            "python3",
            "-m",
            "signing",
            "sign-builds",
            "--jobs",
            "1",
            "--release-script",
            str(release_script),
            "--archive-dir",
            "archive",
            "--original-tmpdir",
            "tmp",
            "--pairs",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()


def test_sign_builds_reads_output_written_after_a_job_exits(
    tmp_path: Path,
) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100"],
        release_tool=(
            "#!/bin/sh\n"
            "(sleep 0.5; echo late) &\n"
            'mkdir -p "out/release-$1-$BUILD_NUMBER"\n'
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "bramble,100,100\tlate\n" in result.stdout
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()


def test_sign_builds_tags_stderr_and_an_unterminated_last_line(
    tmp_path: Path,
) -> None:
    result = run_sign_builds(
        tmp_path,
        ["bramble,100,100"],
        release_tool=(
            "#!/bin/sh\n"
            "echo to-stderr >&2\n"
            'mkdir -p "out/release-$1-$BUILD_NUMBER"\n'
            "printf tail\n"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "bramble,100,100\tto-stderr\n" in result.stdout
    assert result.stdout.endswith("bramble,100,100\ttail\n")


def test_sign_builds_sigterm_terminates_jobs_but_not_the_caller(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    _install_tool(release_script, FAKE_SLOW_RELEASE_TOOL)
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()
    pidfile = tmp_path / "child.pid"
    caller = r"""
python3 -m signing sign-builds --jobs 1 --release-script "$1" \
  --archive-dir "$2" --original-tmpdir "$3" --pairs bramble,100,100 &
cli=$!
while [ ! -s "$CHILD_PIDFILE" ]; do sleep 0.05; done
kill -TERM "$cli"
status=0
wait "$cli" || status=$?
echo "caller survived, cli exited $status"
"""

    result = subprocess.run(
        [
            "bash",
            "-c",
            caller,
            "bash",
            str(release_script),
            str(archive_dir),
            str(original_tmpdir),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "CHILD_PIDFILE": str(pidfile),
        },
        capture_output=True,
        text=True,
        timeout=30,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    )

    assert "caller survived, cli exited 143" in result.stdout, result.stderr
    grandchild_pid = int(pidfile.read_text().strip())
    assert wait_until(
        lambda: not process_alive(grandchild_pid),
        timeout=5,
    ), "the release job's child process was not terminated"
    assert list(original_tmpdir.iterdir()) == []


def test_generate_incrementals_writes_deltas_and_aggregates_failures(
    tmp_path: Path,
) -> None:
    result = run_generate_incrementals(
        tmp_path,
        ["bramble,100,200", "redfin,150,"],
        environment={"FAIL_DEVICES": "redfin"},
    )

    assert result.returncode == 1
    assert "Generating incrementals failed for 1 devices." in result.stderr
    assert (
        "You can run this script again to generate incrementals for the "
        "devices that failed." in result.stderr
    )
    delta = tmp_path / "incrementals" / "bramble-100-200.bin"
    assert delta.read_text() == "delta-bramble-100-200"
    assert not (tmp_path / "incrementals" / "redfin-150-.bin").exists()
    assert list((tmp_path / "tmp").iterdir()) == []


def _require_parallel() -> None:
    if shutil.which("parallel") is None:
        pytest.skip("GNU parallel not installed")


_SIGN_SH_FUNCTION = r"""
source <(sed '/^err=0$/,$d' "$1")
source "$2"
shift 2
"$@"
"""


def run_sign_sh_function(
    root: Path,
    function: str,
    items: list[str],
    *,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    """
    Call sign.sh's own function with sign_scriptpath pointing at root,
    which sign.sh derives from $0, so that root's fake release.sh and
    generate_delta.sh stand in for the scripts next to sign.sh.
    """
    return run(
        [
            "bash",
            "-c",
            _SIGN_SH_FUNCTION,
            root / "sign.sh",
            SCRIPTS_DIR / "sign.sh",
            SCRIPTS_DIR / "common.include.sh",
            function,
            *items,
        ],
        cwd=root,
        env={
            "TMPDIR": str(root / "tmp"),
            "NUM_SIGN_JOBS": "2",
            "NUM_INCREMENTAL_JOBS": "2",
            **environment,
        },
        check=False,
    )


def _tree_manifest(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for directory in ("archive", "incrementals", "tmp")
        if (root / directory).is_dir()
        for path in (root / directory).rglob("*")
        if path.is_file()
    }


def _failure_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if "failed" in line]


@pytest.mark.parametrize("fail_devices", ("", "redfin"))
def test_sign_builds_python_matches_sign_sh(
    tmp_path: Path,
    fail_devices: str,
) -> None:
    _require_parallel()
    pairs = ["bramble,100,100", "redfin,200,200"]
    environment = {"FAIL_DEVICES": fail_devices}

    results: dict[str, subprocess.CompletedProcess[str]] = {}
    manifests: dict[str, dict[str, bytes]] = {}
    for label in ("bash", "python"):
        root = tmp_path / label
        root.mkdir()
        if label == "bash":
            _install_tool(root / "release.sh", FAKE_RELEASE_TOOL)
            (root / "archive").mkdir()
            (root / "tmp").mkdir()
            results[label] = run_sign_sh_function(
                root,
                "sign_builds",
                pairs,
                environment=environment,
            )
        else:
            results[label] = run_sign_builds(
                root,
                pairs,
                environment=environment,
            )
        (root / "release.sh").unlink()
        manifests[label] = _tree_manifest(root)
        manifests[label]["tmp-entries"] = str(
            len(list((root / "tmp").iterdir())),
        ).encode()

    assert results["python"].returncode == results["bash"].returncode
    assert results["bash"].returncode == (1 if fail_devices else 0)
    assert manifests["python"] == manifests["bash"]
    assert (
        manifests["bash"]["archive/release-bramble-100/output.bin"]
        == b"signed-bramble-100"
    )
    assert _failure_lines(results["python"].stderr) == _failure_lines(
        results["bash"].stderr,
    )


def test_generate_incrementals_python_matches_sign_sh(tmp_path: Path) -> None:
    _require_parallel()
    triples = ["bramble,100,200", "redfin,150,250"]
    environment = {"FAIL_DEVICES": "redfin"}

    results: dict[str, subprocess.CompletedProcess[str]] = {}
    manifests: dict[str, dict[str, bytes]] = {}
    for label in ("bash", "python"):
        root = tmp_path / label
        root.mkdir()
        if label == "bash":
            _install_tool(root / "generate_delta.sh", FAKE_GENERATE_DELTA_TOOL)
            (root / "tmp").mkdir()
            results[label] = run_sign_sh_function(
                root,
                "generate_incrementals",
                triples,
                environment=environment,
            )
        else:
            results[label] = run_generate_incrementals(
                root,
                triples,
                environment=environment,
            )
        manifests[label] = _tree_manifest(root)

    assert results["python"].returncode == results["bash"].returncode == 1
    assert manifests["python"] == manifests["bash"]
    assert manifests["bash"] == {
        "incrementals/bramble-100-200.bin": b"delta-bramble-100-200",
    }
    assert _failure_lines(results["python"].stderr) == _failure_lines(
        results["bash"].stderr,
    )


@pytest.mark.parametrize("jobs", ("0", "50%", "+1"))
def test_sign_builds_takes_only_a_positive_job_count(
    tmp_path: Path,
    jobs: str,
) -> None:
    result = run_cli(
        ["sign-builds", "--jobs", jobs, "--pairs", "bramble,1,1"],
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 2
    assert f"must be a positive number, not {jobs!r}" in result.stderr
