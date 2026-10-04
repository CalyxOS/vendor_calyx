#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from conftest import SCRIPTS_DIR, run

_LATE_OUTPUT = """
import subprocess, sys, time
from pathlib import Path
from signing import release_execution

release_execution._TRANSCRIPT_STOP_TIMEOUT = 0.2
transcript = release_execution.Transcript()
transcript.start(Path(sys.argv[1]))
print("early", flush=True)
child = subprocess.Popen(["sh", "-c", "sleep 1; echo late-output"])
started = time.monotonic()
transcript.stop()
stopped_after = time.monotonic() - started
child.wait()
time.sleep(0.5)
print(f"stopped after {stopped_after}")
"""


def test_transcript_keeps_output_of_a_child_that_outlives_stop(
    tmp_path: Path,
) -> None:
    log = tmp_path / "exec.log"

    result = run(
        [sys.executable, "-c", _LATE_OUTPUT, log],
        env={"PYTHONPATH": str(SCRIPTS_DIR)},
    )

    assert "Traceback" not in result.stderr
    (line,) = [
        line for line in result.stdout.splitlines() if "stopped after" in line
    ]
    assert 0.2 <= float(line.split()[-1]) < 0.9
    assert log.read_text().splitlines() == ["early", "late-output"]


_CLOSED_TERMINAL = """
import subprocess, sys
from pathlib import Path
from signing import release_execution

transcript = release_execution.Transcript()
transcript.start(Path(sys.argv[1]))
subprocess.run(["head", "-c", "262144", "/dev/zero"], check=True)
transcript.stop()
"""


def test_transcript_keeps_logging_after_the_terminal_goes_away(
    tmp_path: Path,
) -> None:
    log = tmp_path / "exec.log"
    process = subprocess.Popen(
        [sys.executable, "-c", _CLOSED_TERMINAL, log],
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    process.stdout.close()

    assert process.wait(timeout=60) == 0
    assert log.stat().st_size == 262144


_FULL_LOG = """
import subprocess
from pathlib import Path
from signing import release_execution

transcript = release_execution.Transcript()
transcript.start(Path("/dev/full"))
subprocess.run(["sh", "-c", "echo one; echo two"], check=True)
print("after", flush=True)
transcript.stop()
"""


def test_transcript_keeps_the_terminal_when_the_log_cannot_be_written() -> None:
    result = run(
        [sys.executable, "-c", _FULL_LOG],
        env={"PYTHONPATH": str(SCRIPTS_DIR)},
    )

    assert result.stdout.splitlines() == ["one", "two", "after"]
    assert "Traceback" not in result.stderr
