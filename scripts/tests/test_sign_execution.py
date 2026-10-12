#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import (
    SCRIPTS_DIR,
    default_signal_dispositions,
    install_executable,
    process_alive,
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
  out_build=$((BUILD_NUMBER + 1))
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


SIGN_BUILDS = """
import sys
from pathlib import Path
from signing.sign_execution import sign_builds
release, archive, tmpdir, jobs, *pairs = sys.argv[1:]
raise SystemExit(sign_builds(
    [
        (d, int(b), int(t))
        for d, b, t in (p.split(",") for p in pairs)
    ],
    release_script=Path(release),
    archive_dir=Path(archive),
    jobs=int(jobs),
    original_tmpdir=Path(tmpdir),
))
"""

GENERATE_INCREMENTALS = """
import sys
from pathlib import Path
from signing.sign_execution import generate_incrementals
script, tmpdir, jobs, *triples = sys.argv[1:]
raise SystemExit(generate_incrementals(
    [
        (d, int(old), int(new))
        for d, old, new in (t.split(",") for t in triples)
    ],
    generate_delta_script=Path(script),
    jobs=int(jobs),
    original_tmpdir=Path(tmpdir),
))
"""


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
    install_executable(release_script, release_tool)
    archive_dir = root / "archive"
    archive_dir.mkdir(exist_ok=True)
    original_tmpdir = root / "tmp"
    original_tmpdir.mkdir(exist_ok=True)
    return subprocess.run(
        [
            sys.executable,
            "-c",
            SIGN_BUILDS,
            release_script,
            archive_dir,
            original_tmpdir,
            str(jobs),
            *pairs,
        ],
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            **(environment or {}),
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
        preexec_fn=default_signal_dispositions,
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
    install_executable(generate_delta_script, generate_delta_tool)
    original_tmpdir = root / "tmp"
    original_tmpdir.mkdir(exist_ok=True)
    return subprocess.run(
        [
            sys.executable,
            "-c",
            GENERATE_INCREMENTALS,
            generate_delta_script,
            original_tmpdir,
            str(jobs),
            *triples,
        ],
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            **(environment or {}),
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
        preexec_fn=default_signal_dispositions,
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
    install_executable(
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
            sys.executable,
            "-c",
            SIGN_BUILDS,
            str(release_script),
            "archive",
            "tmp",
            "2",
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


def test_sign_builds_starts_its_jobs_from_the_given_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from signing import sign_execution

    release_script = tmp_path / "release.sh"
    release_script.write_text(
        "#!/bin/sh\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n'
        'printf %s "$MARKER" > "out/release-$1-$BUILD_NUMBER/marker"\n',
    )
    release_script.chmod(0o755)
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MARKER", raising=False)

    status = sign_execution.sign_builds(
        [("bramble", 100, 100)],
        release_script=release_script,
        archive_dir=Path("archive"),
        jobs=1,
        original_tmpdir=tmp_path / "tmp",
        environment={**os.environ, "MARKER": "given"},
    )

    assert status == 0
    marker = tmp_path / "archive" / "release-bramble-100" / "marker"
    assert marker.read_text() == "given"


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
    install_executable(
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
            sys.executable,
            "-c",
            SIGN_BUILDS,
            str(release_script),
            "archive",
            "tmp",
            "1",
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
    install_executable(release_script, FAKE_SLOW_RELEASE_TOOL)
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()
    pidfile = tmp_path / "child.pid"
    caller = r"""
python3 -c "$SIGN_BUILDS" "$1" "$2" "$3" 1 bramble,100,100 &
cli=$!
while [ ! -s "$CHILD_PIDFILE" ]; do sleep 0.05; done
kill -TERM "$cli"
status=0
wait "$cli" || status=$?
echo "caller survived, cli exited $status"
"""

    result, _ = _run_in_session(
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
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    assert "caller survived, cli exited 143" in result.stdout, result.stderr
    grandchild_pid = int(pidfile.read_text().strip())
    assert wait_until(
        lambda: not process_alive(grandchild_pid),
        timeout=5,
    ), "the release job's child process was not terminated"
    assert list(original_tmpdir.iterdir()) == []


def test_sign_builds_runs_on_through_a_hangup_it_ignores(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        'echo started > "$STARTED.$1"\n'
        "sleep 1\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()
    caller = r"""
set -m
trap '' HUP
python3 -c "$SIGN_BUILDS" "$1" "$2" "$3" 3 \
  bramble,100,100 redfin,100,100 oriole,100,100 &
cli=$!
for device in bramble redfin oriole; do
  while [ ! -s "$STARTED.$device" ]; do sleep 0.05; done
done
kill -HUP -- "-$cli"
status=0
wait "$cli" || status=$?
echo "cli exited $status"
"""

    result, _ = _run_in_session(
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
            "STARTED": str(tmp_path / "started"),
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    assert "cli exited 0" in result.stdout, result.stderr
    assert sorted(path.name for path in archive_dir.iterdir()) == [
        "release-bramble-100",
        "release-oriole-100",
        "release-redfin-100",
    ]


def test_sign_builds_removes_its_tmpdir_through_an_interrupt(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        '#!/bin/sh\nmkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    script = """
import os, shutil, signal, sys
from pathlib import Path
from signing import sign_execution
remove = shutil.rmtree
def interrupted(path, *args, **kwargs):
    if Path(path).name.startswith("sign_tmp."):
        os.kill(os.getpid(), signal.SIGINT)
    remove(path, *args, **kwargs)
shutil.rmtree = interrupted
try:
    sign_execution.sign_builds(
        [("bramble", 100, 100)],
        release_script=Path(sys.argv[1]),
        archive_dir=Path("archive"),
        jobs=1,
        original_tmpdir=Path("tmp"),
    )
except KeyboardInterrupt:
    print("interrupted")
"""

    result = subprocess.run(
        [sys.executable, "-c", script, release_script],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        preexec_fn=default_signal_dispositions,
    )

    assert "interrupted" in result.stdout, result.stderr
    assert list((tmp_path / "tmp").iterdir()) == []


def test_sign_builds_hands_its_jobs_an_ignored_hangup(tmp_path: Path) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        'grep SigIgn /proc/$$/status > "$IGNORED.$1"\n'
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()

    result, _ = _run_in_session(
        [
            "bash",
            "-c",
            'trap \'\' HUP\nexec python3 -c "$SIGN_BUILDS" "$@"',
            "bash",
            str(release_script),
            str(archive_dir),
            str(original_tmpdir),
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "IGNORED": str(tmp_path / "ignored"),
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    assert result.returncode == 0, result.stderr
    ignored = (tmp_path / "ignored.bramble").read_text().split()[1]
    assert int(ignored, 16) & 1 << (signal.SIGHUP - 1)


def test_exit_on_signals_leaves_an_ignored_signal_ignored() -> None:
    from signing.release_execution import exit_on_signals

    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        with exit_on_signals():
            assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, previous)


def test_generate_incrementals_writes_deltas_and_aggregates_failures(
    tmp_path: Path,
) -> None:
    result = run_generate_incrementals(
        tmp_path,
        ["bramble,100,200", "redfin,150,200"],
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
    assert not (tmp_path / "incrementals" / "redfin-150-200.bin").exists()
    assert list((tmp_path / "tmp").iterdir()) == []


def test_sign_builds_waits_for_its_jobs_after_its_output_breaks(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        "echo first\n"
        "sleep 0.5\n"
        "echo second\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            SIGN_BUILDS,
            str(release_script),
            "archive",
            "tmp",
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    ) as cli:
        assert cli.stdout is not None
        assert cli.stderr is not None
        cli.stdout.readline()
        cli.stdout.readline()
        cli.stdout.close()
        try:
            status = cli.wait(timeout=30)
        except subprocess.TimeoutExpired:
            subprocess.run(["pkill", "-KILL", "-s", str(cli.pid)], check=False)
            raise
        stderr = cli.stderr.read()

    assert status == 0, stderr
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()


SIGNALLED_JOB = f"""#!{sys.executable}
import os, signal, sys, time
device = sys.argv[1]
def note(signum, frame):
    with open(os.environ["TERMED"] + "." + device, "a") as termed:
        termed.write("term\\n")
signal.signal(signal.SIGTERM, note)
with open(os.environ["STARTED"] + "." + device, "w") as started:
    started.write("started\\n")
for _ in range(int(os.environ["TENTHS"])):
    time.sleep(0.1)
os.makedirs(
    "out/release-" + device + "-" + os.environ["BUILD_NUMBER"],
    exist_ok=True,
)
with open(os.environ["FINISHED"] + "." + device, "w") as finished:
    finished.write("finished\\n")
"""

SHELL_SIGNALLED_JOB = """#!/bin/sh
trap 'echo term >> "$TERMED.$1"' TERM
echo started > "$STARTED.$1"
i=0
while [ "$i" -lt "$TENTHS" ]; do sleep 0.1; i=$((i + 1)); done
mkdir -p "out/release-$1-$BUILD_NUMBER"
echo finished > "$FINISHED.$1"
"""

SIGNALLING_CALLER = r"""
send() {
  case "$1" in
    group-*) kill -"$(echo "${1#group-}" | tr a-z A-Z)" -- "-$cli" ;;
    *) kill -"$(echo "$1" | tr a-z A-Z)" "$cli" ;;
  esac
}
wait_for() {
  for device in bramble redfin; do
    while [ ! -s "$1.$device" ]; do sleep 0.05; done
  done
}
set -m
if [ -n "$IGNORED" ]; then
  trap '' "$IGNORED"
fi
python3 -c "$SIGN_BUILDS" "$1" "$2" "$3" 2 bramble,100,100 redfin,100,100 \
  2> "$CLI_STDERR" &
cli=$!
wait_for "$STARTED"
send "$FIRST"
if [ -n "$SECOND" ]; then
  wait_for "$TERMED"
  send "$SECOND"
fi
code=0
wait "$cli" || code=$?
echo "cli exited $code"
cat "$CLI_STDERR" >&2
if [ "$FIRST" = group-kill ]; then
  wait_for "$FINISHED"
fi
"""


def _run_in_session(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float = 60,
) -> tuple[subprocess.CompletedProcess[str], int]:
    """
    Run args in a session of its own, and kill every process of that
    session when it times out.

    Returns:
        The result and the session ID.
    """
    with subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["pkill", "-KILL", "-s", str(process.pid)],
                check=False,
            )
            raise
    result = subprocess.CompletedProcess(
        args,
        process.returncode,
        stdout,
        stderr,
    )
    return result, process.pid


def _run_signalling_caller(
    tmp_path: Path,
    environment: dict[str, str],
    job: str = SIGNALLED_JOB,
    timeout: float = 60,
) -> tuple[subprocess.CompletedProcess[str], int]:
    """
    Run SIGNALLING_CALLER through _run_in_session() against a stand-in
    for release.sh.

    Returns:
        The caller's result and its session ID.
    """
    release_script = tmp_path / "release.sh"
    install_executable(release_script, job)
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()
    args = [
        "bash",
        "-c",
        SIGNALLING_CALLER,
        "bash",
        str(release_script),
        str(archive_dir),
        str(original_tmpdir),
    ]
    env = {
        **os.environ,
        "PYTHONPATH": str(SCRIPTS_DIR),
        "STARTED": str(tmp_path / "started"),
        "TERMED": str(tmp_path / "termed"),
        "FINISHED": str(tmp_path / "finished"),
        "CLI_STDERR": str(tmp_path / "cli-stderr"),
        "SIGN_BUILDS": SIGN_BUILDS,
        **environment,
    }
    return _run_in_session(args, cwd=tmp_path, env=env, timeout=timeout)


@pytest.mark.parametrize(
    ("ignored", "first", "second", "killed", "status"),
    (
        ("", "group-int", "", False, 130),
        ("", "group-int", "group-int", True, 130),
        ("", "int", "int", True, 130),
        ("", "term", "term", True, 143),
        ("", "hup", "hup", False, 129),
        ("", "hup", "int", True, 129),
        ("", "group-hup", "", False, 129),
        ("", "group-hup", "group-hup", False, 129),
        ("", "group-term", "group-int", True, 143),
        ("TERM", "int", "", False, 130),
        ("TERM", "int", "int", True, 130),
    ),
)
def test_sign_builds_stops_its_jobs_on_signals(
    tmp_path: Path,
    ignored: str,
    first: str,
    second: str,
    killed: bool,
    status: int,
) -> None:
    result, _ = _run_signalling_caller(
        tmp_path,
        {"IGNORED": ignored, "FIRST": first, "SECOND": second, "TENTHS": "80"},
    )

    assert f"cli exited {status}" in result.stdout, result.stderr
    for device in ("bramble", "redfin"):
        termed = (tmp_path / f"termed.{device}").read_text()
        assert termed == "term\n", device
        assert (tmp_path / f"finished.{device}").exists() is not killed


def _live_in_session(session: int) -> bool:
    """Return whether a process of the session is alive, zombies aside."""
    states = subprocess.run(
        ["ps", "-o", "stat=", "-s", str(session)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    return any(not state.startswith("Z") for state in states)


def test_sign_builds_stops_a_shell_job_when_sigterm_is_ignored(
    tmp_path: Path,
) -> None:
    result, _ = _run_signalling_caller(
        tmp_path,
        {"IGNORED": "TERM", "FIRST": "int", "SECOND": "", "TENTHS": "30"},
        SHELL_SIGNALLED_JOB,
    )

    assert "cli exited 130" in result.stdout, result.stderr
    for device in ("bramble", "redfin"):
        assert (tmp_path / f"termed.{device}").exists(), device
        assert (tmp_path / f"finished.{device}").exists(), device


def test_sign_builds_starts_no_job_after_a_signal(tmp_path: Path) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        "trap 'exit 1' TERM\n"
        'echo started > "$STARTED.$1"\n'
        "i=0\n"
        'while [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    caller = r"""
set -m
python3 -c "$SIGN_BUILDS" "$1" archive tmp 1 bramble,100,100 redfin,100,100 &
cli=$!
while [ ! -s "$STARTED.bramble" ]; do sleep 0.05; done
kill -TERM "$cli"
status=0
wait "$cli" || status=$?
echo "cli exited $status"
"""

    result, _ = _run_in_session(
        ["bash", "-c", caller, "bash", str(release_script)],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "STARTED": str(tmp_path / "started"),
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    assert "cli exited 143" in result.stdout, result.stderr
    assert not (tmp_path / "started.redfin").exists()


def test_sign_builds_stops_its_jobs_on_an_error(tmp_path: Path) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        'if [ "$1" = redfin ]; then\n'
        "  trap 'head -c 300000 /dev/zero | tr \\\\0 x; "
        'echo; echo cleaned > "$CLEANED"; exit 1\' TERM\n'
        '  echo started > "$STARTED"\n'
        "  i=0\n"
        '  while [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done\n'
        "fi\n"
        'while [ ! -s "$STARTED" ]; do sleep 0.05; done\n'
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    script = (
        """
import shutil
def broken_move(*args, **kwargs):
    raise RuntimeError("archive bug")
shutil.move = broken_move
"""
        + SIGN_BUILDS
    )

    result, _ = _run_in_session(
        [
            sys.executable,
            "-c",
            script,
            str(release_script),
            "archive",
            "tmp",
            "2",
            "bramble,100,100",
            "redfin,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "STARTED": str(tmp_path / "started"),
            "CLEANED": str(tmp_path / "cleaned"),
        },
    )

    assert "RuntimeError: archive bug" in result.stderr, result.stderr
    assert (tmp_path / "cleaned").read_text() == "cleaned\n"


@pytest.mark.parametrize("private", (True, False), ids=("private", "shared"))
def test_sign_builds_stops_its_jobs_while_stdout_is_not_read(
    tmp_path: Path,
    private: bool,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        "trap 'echo term > \"$TERMED\"; exit 1' TERM\n"
        "head -c 200000 /dev/zero | tr '\\0' x\n"
        "echo\n"
        'echo started > "$STARTED"\n'
        "i=0\n"
        'while [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    script = (
        SIGN_BUILDS
        if private
        else (
            "import os\n"
            "_open = os.open\n"
            "def no_proc(path, *args, **kwargs):\n"
            "    if str(path).startswith('/proc/self/fd/'):\n"
            "        raise PermissionError(13, 'Permission denied', path)\n"
            "    return _open(path, *args, **kwargs)\n"
            "os.open = no_proc\n" + SIGN_BUILDS
        )
    )

    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(release_script),
            "archive",
            "tmp",
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "STARTED": str(tmp_path / "started"),
            "TERMED": str(tmp_path / "termed"),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    ) as cli:
        try:
            deadline = time.monotonic() + 30
            while not (tmp_path / "started").exists():
                assert time.monotonic() < deadline, "the job never started"
                time.sleep(0.05)
            cli.send_signal(signal.SIGTERM)
            status = cli.wait(timeout=30)
        finally:
            subprocess.run(["pkill", "-KILL", "-s", str(cli.pid)], check=False)

    assert status == 128 + signal.SIGTERM
    assert (tmp_path / "termed").read_text() == "term\n"


def test_sign_builds_leaves_a_shared_stdout_blocking(tmp_path: Path) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        "head -c 200000 /dev/zero | tr '\\0' x\n"
        "echo\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n'
        'echo finished > "$FINISHED"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    read_end, write_end = os.pipe()

    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            SIGN_BUILDS,
            str(release_script),
            "archive",
            "tmp",
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "FINISHED": str(tmp_path / "finished"),
        },
        stdout=write_end,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    ) as cli:
        try:
            deadline = time.monotonic() + 30
            while not (tmp_path / "finished").exists():
                assert time.monotonic() < deadline, "the job never finished"
                time.sleep(0.05)
            blocking = os.get_blocking(write_end)
            os.close(write_end)
            with os.fdopen(read_end, "rb") as output:
                output.read()
            cli.wait(timeout=30)
        finally:
            subprocess.run(["pkill", "-KILL", "-s", str(cli.pid)], check=False)

    assert blocking
    assert cli.returncode == 0


def test_sign_builds_drops_output_past_the_limit_while_stdout_lags(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        "head -c 200000 /dev/zero | tr '\\0' x\n"
        "echo\n"
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n'
        'echo finished > "$FINISHED"\n',
    )
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()
    script = (
        "from signing import sign_execution\n"
        "sign_execution._OUTPUT_LIMIT = 1000\n" + SIGN_BUILDS
    )

    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(release_script),
            "archive",
            "tmp",
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "FINISHED": str(tmp_path / "finished"),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    ) as cli:
        try:
            deadline = time.monotonic() + 30
            while not (tmp_path / "finished").exists():
                assert time.monotonic() < deadline, "the job never finished"
                time.sleep(0.05)
            stdout, _ = cli.communicate(timeout=30)
        finally:
            subprocess.run(["pkill", "-KILL", "-s", str(cli.pid)], check=False)

    assert cli.returncode == 0
    assert b"[job output dropped while stdout lags]\n" in stdout
    assert len(stdout) < 200000
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()


def test_sign_builds_reports_a_failed_move_below_a_path_that_is_not_utf8(
    tmp_path: Path,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        'if [ "$1" = redfin ]; then sleep 1; fi\n'
        'mkdir -p "out/release-$1-$BUILD_NUMBER"\n',
    )
    archive = os.fsencode(tmp_path) + b"/archive-\xff"
    os.makedirs(archive + b"/release-bramble-100")
    (tmp_path / "tmp").mkdir()

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            SIGN_BUILDS,
            str(release_script),
            archive,
            "tmp",
            "2",
            "bramble,100,100",
            "redfin,100,100",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        capture_output=True,
        timeout=60,
        check=False,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == 1, result.stderr
    assert b"bramble,100,100\tDestination path" in result.stdout
    assert os.path.isdir(archive + b"/release-redfin-100")


def test_sign_builds_runs_with_stdout_closed(tmp_path: Path) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(release_script, FAKE_RELEASE_TOOL + "echo done\n")
    (tmp_path / "archive").mkdir()
    (tmp_path / "tmp").mkdir()

    result, _ = _run_in_session(
        [
            "bash",
            "-c",
            'exec python3 -c "$SIGN_BUILDS" "$@" >&-',
            "bash",
            str(release_script),
            "archive",
            "tmp",
            "1",
            "bramble,100,100",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "archive" / "release-bramble-100").is_dir()


def test_sign_builds_stops_its_jobs_when_the_orchestrator_dies(
    tmp_path: Path,
) -> None:
    result, session = _run_signalling_caller(
        tmp_path,
        {
            "IGNORED": "",
            "FIRST": "group-kill",
            "SECOND": "",
            "TENTHS": "20",
        },
        timeout=20,
    )

    assert "cli exited 137" in result.stdout, result.stderr
    for device in ("bramble", "redfin"):
        assert (tmp_path / f"termed.{device}").exists(), device
        assert (tmp_path / f"finished.{device}").exists(), device
    deadline = time.monotonic() + 10
    while _live_in_session(session):
        assert time.monotonic() < deadline, "a job outlived the orchestrator"
        time.sleep(0.1)


@pytest.mark.parametrize("target", ("process", "group", "interrupt"))
def test_sign_builds_sigterm_waits_for_the_jobs_to_finish(
    tmp_path: Path,
    target: str,
) -> None:
    release_script = tmp_path / "release.sh"
    install_executable(
        release_script,
        "#!/bin/sh\n"
        'case "$1" in bramble) delay=0 ;; redfin) delay=1 ;; '
        "*) delay=2 ;; esac\n"
        "trap 'sleep $delay; echo finished > \"$FINISHED.$1\"; exit 1' TERM\n"
        'echo started > "$STARTED.$1"\n'
        "i=0\n"
        'while [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done\n',
    )
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    original_tmpdir = tmp_path / "tmp"
    original_tmpdir.mkdir()
    devices = ("bramble", "redfin", "oriole")
    caller = r"""
set -m
python3 -c "$SIGN_BUILDS" "$1" "$2" "$3" 3 \
  bramble,100,100 redfin,100,100 oriole,100,100 &
cli=$!
for device in bramble redfin oriole; do
  while [ ! -s "$STARTED.$device" ]; do sleep 0.05; done
done
case "$TARGET" in
  group) kill -TERM -- "-$cli" ;;
  interrupt) kill -INT "$cli" ;;
  *) kill -TERM "$cli" ;;
esac
status=0
wait "$cli" || status=$?
echo "cli exited $status"
"""

    result, _ = _run_in_session(
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
            "STARTED": str(tmp_path / "started"),
            "FINISHED": str(tmp_path / "finished"),
            "TARGET": target,
            "SIGN_BUILDS": SIGN_BUILDS,
        },
    )

    expected = 130 if target == "interrupt" else 143
    assert f"cli exited {expected}" in result.stdout, result.stderr
    for device in devices:
        assert (tmp_path / f"finished.{device}").read_text() == "finished\n"
