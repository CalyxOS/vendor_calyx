#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Run the release and incremental jobs of a signing run with bounded
concurrency.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import functools
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections import deque
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any

from .release_execution import defer_signals
from .sign_planning import IncrementalTriple, SignPair

_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
_PR_SET_PDEATHSIG = 1
_OUTPUT_LIMIT = 64 * 1024 * 1024
_STDOUT_GONE = (errno.EPIPE, errno.EIO, errno.EBADF, errno.ENXIO)


@dataclass(frozen=True, slots=True)
class Job:
    """
    One subprocess invocation of the fan-out.

    tag is the tag of the job's SignPair or IncrementalTriple, which
    prefixes the job's output lines, followed by a tab.
    """

    argv: tuple[str, ...]
    env: dict[str, str]
    tag: str


@contextlib.contextmanager
def _signals_blocked() -> Generator[None, None, None]:
    """
    Hold the fan-out's signals back for the with block, so that a signal
    cannot interrupt a change of their handlers part way.
    """
    previous = signal.pthread_sigmask(
        signal.SIG_BLOCK,
        (*_SIGNALS, signal.SIGCHLD),
    )
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _ignore_signal(signum: int, frame: FrameType | None) -> None:
    pass


class _RunningJob:
    """A started job whose output or exit status is still to be read."""

    def __init__(self, job: Job, process: subprocess.Popen[bytes]) -> None:
        self.job = job
        self.process = process
        self.reading = True
        self.tag = job.tag.encode() + b"\t"
        self.line = b""

    def lines(self, data: bytes) -> bytes:
        """Return each complete line of output with the job's tag."""
        *lines, self.line = (self.line + data).split(b"\n")
        return b"".join(self.tag + line + b"\n" for line in lines)

    def end(self) -> bytes:
        """Return a last line the output did not end, ended and tagged."""
        self.reading = False
        return self.tag + self.line + b"\n" if self.line else b""

    @property
    def done(self) -> bool:
        return not self.reading and self.process.poll() is not None


class _FanOut:
    """
    Run jobs from one thread, which waits on their output, on stdout
    taking more of it and on a pipe that the signal handlers write the
    signal numbers to.
    """

    def __init__(
        self,
        jobs: Sequence[Job],
        max_jobs: int,
        on_success: Callable[[Job], str | None],
    ) -> None:
        self.queue = deque(jobs)
        self.max_jobs = max_jobs
        self.on_success = on_success
        self.failed = 0
        self.signals: list[int] = []
        self.error: BaseException | None = None
        self.stopping = False
        self.running: set[_RunningJob] = set()
        self.output = bytearray()
        self.dropping = False
        self.stdout: int | None = None
        self.private_stdout: int | None = None
        self.shared_stdout = False
        self.waiting_for_stdout = False
        self.orchestrator = os.getpid()
        self.prctl: Callable[..., int] | None = None
        with contextlib.suppress(AttributeError, OSError):
            self.prctl = ctypes.CDLL(None, use_errno=True).prctl
        self.selector = selectors.DefaultSelector()

    def run(self) -> int:
        self.open_stdout()
        handlers: dict[int, Callable[[int, FrameType | None], None]] = {
            signum: self.note
            for signum in _SIGNALS
            if signal.getsignal(signum) != signal.SIG_IGN
        }
        handlers.setdefault(signal.SIGTERM, _ignore_signal)
        handlers[signal.SIGCHLD] = self.note
        self.notes, self.note_writer = os.pipe()
        previous_handlers: dict[
            int,
            Callable[[int, FrameType | None], Any] | int | None,
        ] = {}
        try:
            os.set_blocking(self.notes, False)
            os.set_blocking(self.note_writer, False)
            self.selector.register(
                self.notes,
                selectors.EVENT_READ,
                self.take_notes,
            )
            with _signals_blocked():
                for signum, handler in handlers.items():
                    previous_handlers[signum] = signal.signal(signum, handler)
            self.loop()
        finally:
            with _signals_blocked():
                for signum, previous in previous_handlers.items():
                    signal.signal(signum, previous)
                self.signals += [
                    signum for signum in self.read_notes() if signum in _SIGNALS
                ]
            self.selector.close()
            os.close(self.notes)
            os.close(self.note_writer)
            if self.private_stdout is not None:
                os.close(self.private_stdout)
        if self.error is not None:
            raise self.error
        if self.signals:
            raise SystemExit(128 + self.signals[0])
        return self.failed

    def loop(self) -> None:
        while True:
            try:
                self.take_notes()
                if self.queue and len(self.running) < self.max_jobs:
                    self.start(self.queue.popleft())
                    continue
                if not self.running and not (self.output and not self.stopping):
                    return
                for key, _ in self.selector.select(timeout=1):
                    key.data()
            except BaseException as error:
                if self.error is None:
                    self.error = error
                self.stop(kill=True)

    def note(self, signum: int, frame: FrameType | None) -> None:
        # A job runs this as well between fork and exec.
        if os.getpid() == self.orchestrator:
            with contextlib.suppress(BlockingIOError):
                os.write(self.note_writer, bytes([signum]))

    def read_notes(self) -> bytes:
        notes = b""
        with contextlib.suppress(BlockingIOError):
            while chunk := os.read(self.notes, 512):
                notes += chunk
        return notes

    def take_notes(self) -> None:
        """
        Collect the jobs that exited, and stop the jobs on a SIGINT,
        SIGTERM or SIGHUP.
        """
        for signum in self.read_notes():
            if signum in _SIGNALS:
                self.signals.append(signum)
                self.stop(kill=signum != signal.SIGHUP)
        for running in list(self.running):
            self.finish(running)

    def stop(self, *, kill: bool) -> None:
        """
        Start no further job, and send the running jobs SIGTERM the first
        time and SIGKILL on a later call with kill set.
        """
        self.queue.clear()
        if not self.stopping:
            self.stopping = True
            self.signal_jobs(signal.SIGTERM)
        elif kill:
            self.signal_jobs(signal.SIGKILL)

    def signal_jobs(self, signum: int) -> None:
        for running in self.running:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(running.process.pid, signum)

    def open_stdout(self) -> None:
        """
        Find stdout, and open a description of its own for a pipe or a
        terminal, which can then be written without blocking while the
        processes sharing stdout keep theirs blocking. Where that cannot
        be done, as for a terminal or pipe of another user, or for a
        socket, set a blocking stdout non-blocking only around each write.
        """
        try:
            sys.stdout.flush()
            stdout = sys.stdout.fileno()
            mode = os.fstat(stdout).st_mode
        except (AttributeError, OSError, ValueError):
            return
        self.stdout = stdout
        if stat.S_ISFIFO(mode) or stat.S_ISCHR(mode):
            with contextlib.suppress(OSError):
                self.private_stdout = os.open(
                    f"/proc/self/fd/{self.stdout}",
                    os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC,
                )
                self.stdout = self.private_stdout
        self.shared_stdout = (
            self.private_stdout is None
            and not stat.S_ISREG(mode)
            and os.get_blocking(stdout)
        )

    def write(self, data: bytes) -> None:
        """
        Queue job output for stdout and write what stdout takes without
        blocking, so that a stdout that is not read holds up neither the
        jobs nor the handling of signals. Drop the output past
        _OUTPUT_LIMIT queued bytes, and once stdout is gone, as when the
        terminal hangs up or a pipe reader exits.
        """
        if self.stdout is None:
            return
        if len(self.output) + len(data) > _OUTPUT_LIMIT:
            if not self.dropping:
                self.dropping = True
                self.output += b"[job output dropped while stdout lags]\n"
        elif data:
            self.output += data
            self.dropping = False
        self.write_output()

    def write_output(self) -> None:
        stdout = self.stdout
        if stdout is None:
            return
        try:
            if self.shared_stdout:
                os.set_blocking(stdout, False)
            try:
                while self.output:
                    del self.output[: os.write(stdout, self.output)]
            finally:
                if self.shared_stdout:
                    os.set_blocking(stdout, True)
        except BlockingIOError:
            pass
        except OSError as error:
            if error.errno in _STDOUT_GONE:
                self.stdout = None
            self.output.clear()
        waiting = bool(self.output)
        if waiting != self.waiting_for_stdout:
            if waiting:
                self.selector.register(
                    stdout,
                    selectors.EVENT_WRITE,
                    self.write_output,
                )
            else:
                self.selector.unregister(stdout)
            self.waiting_for_stdout = waiting

    def prepare_job(self) -> None:
        if self.prctl is not None:
            self.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
        if os.getppid() != self.orchestrator:
            raise ChildProcessError("the fan-out has exited")

    def start(self, job: Job) -> None:
        try:
            process = subprocess.Popen(
                list(job.argv),
                env=job.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                process_group=0,
                preexec_fn=self.prepare_job,
            )
        except OSError as error:
            self.write(os.fsencode(f"{job.tag}\t{error}\n"))
            self.failed += 1
            return
        running = _RunningJob(job, process)
        self.running.add(running)
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        self.selector.register(
            process.stdout,
            selectors.EVENT_READ,
            functools.partial(self.read_output, running),
        )

    def read_output(self, running: _RunningJob) -> None:
        stdout = running.process.stdout
        assert stdout is not None
        try:
            data = os.read(stdout.fileno(), 65536)
        except BlockingIOError:
            return
        if data:
            self.write(running.lines(data))
            return
        self.selector.unregister(stdout)
        stdout.close()
        self.write(running.end())
        self.finish(running)

    def finish(self, running: _RunningJob) -> None:
        if not running.done:
            return
        self.running.remove(running)
        if running.process.returncode != 0:
            self.failed += 1
        elif (message := self.on_success(running.job)) is not None:
            self.write(running.tag + os.fsencode(message) + b"\n")
            self.failed += 1


def _run_fan_out(
    jobs: Sequence[Job],
    *,
    max_jobs: int,
    on_success: Callable[[Job], str | None] = lambda job: None,
) -> int:
    """
    Run every job with bounded concurrency and count the failures.

    on_success runs for each successful job as soon as it finishes. A job
    whose on_success returns a message counts as failed, and the message
    is written as a line of the job's output.

    Each job runs in a process group of its own. The first SIGINT, SIGTERM
    or SIGHUP sends every running job's group SIGTERM, starts no further
    job and ends the fan-out with SystemExit(128 + signal number) once the
    running jobs are done. A later SIGINT or SIGTERM sends them SIGKILL,
    and a later SIGHUP, which a hangup delivers twice, changes nothing. An
    exception stops the jobs the same way and is raised once they are
    done. Output that stdout has not taken yet is written before the
    fan-out ends, unless it ends on a signal or an exception.

    A signal the process ignores stays ignored, and the jobs inherit an
    ignored SIGINT or SIGHUP but get the default SIGTERM. A job gets
    SIGTERM when the process running the fan-out dies.
    """
    return _FanOut(jobs, max_jobs, on_success).run()


def sign_builds(
    pairs: Sequence[SignPair],
    *,
    release_script: Path,
    archive_dir: Path,
    jobs: int,
    original_tmpdir: Path,
    environment: Mapping[str, str] | None = None,
) -> int:
    """
    Sign each (device, build, target_build) and archive the signed output.

    Args:
        pairs: The releases to sign.
        release_script: Path to release.sh.
        archive_dir: Directory signed output is moved into on success
            (sign.sh's `archive/`).
        jobs: Maximum concurrent release.sh invocations (NUM_SIGN_JOBS).
        original_tmpdir: Base directory for the per-run TMPDIR
            (sign.sh's TMPDIR, defaulting to /dev/shm).
        environment: Environment the jobs start from, the process
            environment unless given.

    Returns:
        0 if every device signed successfully, 1 otherwise, never a
        per-job or aggregate failure count.
    """
    print()
    print(
        "Signing release for:",
        " ".join(pair.tag for pair in pairs),
        flush=True,
    )

    outputs = {
        pair.tag: Path("out") / f"release-{pair.device}-{pair.target_build}"
        for pair in pairs
    }

    def archive(job: Job) -> str | None:
        output = outputs[job.tag]
        final = archive_dir / output.name
        partial = archive_dir / f".{output.name}.partial"
        try:
            if final.exists():
                raise OSError(f"Destination path '{final}' already exists")
            shutil.rmtree(partial, ignore_errors=True)
            shutil.move(str(output), str(partial))
            partial.rename(final)
        except OSError as error:
            return str(error)
        return None

    tmpdir = Path(
        tempfile.mkdtemp(prefix="sign_tmp.", dir=str(original_tmpdir)),
    )
    try:
        base_env = {
            **(os.environ if environment is None else environment),
            "TMPDIR": str(tmpdir),
            "ENSURE_KEY_IS_AVAILABLE": "n",
        }
        work_jobs = [
            Job(
                argv=(
                    str(release_script),
                    pair.device,
                    f"calyx_{pair.device}-target_files-{pair.build}.zip",
                ),
                env={**base_env, "BUILD_NUMBER": str(pair.build)},
                tag=pair.tag,
            )
            for pair in pairs
        ]
        failed = _run_fan_out(work_jobs, max_jobs=jobs, on_success=archive)
    finally:
        with defer_signals(interrupt=True):
            shutil.rmtree(tmpdir, ignore_errors=True)

    if failed:
        print(file=sys.stderr)
        print(f"Signing failed for {failed} devices.", file=sys.stderr)
        print(
            "You can run this script again to sign the devices that failed.",
            file=sys.stderr,
        )
        return 1

    return 0


def generate_incrementals(
    triples: Sequence[IncrementalTriple],
    *,
    generate_delta_script: Path,
    jobs: int,
    original_tmpdir: Path,
    environment: Mapping[str, str] | None = None,
) -> int:
    """
    Generate each (device, old_build, new_build) incremental.

    Args:
        triples: The incrementals to generate.
        generate_delta_script: Path to generate_delta.sh.
        jobs: Maximum concurrent generate_delta.sh invocations
            (NUM_INCREMENTAL_JOBS).
        original_tmpdir: Base directory for the per-run TMPDIR
            (sign.sh's TMPDIR, defaulting to /dev/shm).
        environment: Environment the jobs start from, the process
            environment unless given.

    Returns:
        0 if every incremental generated successfully, 1 otherwise, never
        a per-job or aggregate failure count.
    """
    print()
    print(
        "Generating incremental updates for:",
        " ".join(triple.tag for triple in triples),
        flush=True,
    )

    tmpdir = Path(
        tempfile.mkdtemp(prefix="incremental_tmp.", dir=str(original_tmpdir)),
    )
    try:
        base_env = {
            **(os.environ if environment is None else environment),
            "TMPDIR": str(tmpdir),
            "ENSURE_KEY_IS_AVAILABLE": "n",
        }
        work_jobs = [
            Job(
                argv=(
                    str(generate_delta_script),
                    triple.device,
                    str(triple.old_build),
                    str(triple.new_build),
                ),
                env={
                    **base_env,
                    "BUILD_NUMBER": f"{triple.new_build}_{triple.old_build}",
                },
                tag=triple.tag,
            )
            for triple in triples
        ]
        failed = _run_fan_out(work_jobs, max_jobs=jobs)
    finally:
        with defer_signals(interrupt=True):
            shutil.rmtree(tmpdir, ignore_errors=True)
    if failed:
        print(file=sys.stderr)
        print(
            f"Generating incrementals failed for {failed} devices.",
            file=sys.stderr,
        )
        print(
            "You can run this script again to generate incrementals for "
            "the devices that failed.",
            file=sys.stderr,
        )
        return 1

    return 0
