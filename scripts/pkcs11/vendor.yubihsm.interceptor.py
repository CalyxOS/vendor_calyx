#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

"""Python port of the YubiHSM signing interceptor.

This keeps the original shell script's behavior and inlines the helper logic it
pulled from ``vendor.yubihsm.include.sh`` that the interceptor depends on.
"""

import errno
import fcntl
import os
import select
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, TextIO


CONNECTOR_ERROR_MESSAGES = (
    "Connector operation failed",
    "Unable to find a suitable connector",
)
SESSION_ALLOCATION_MESSAGES = (
    "All sessions are allocated",
    "SESSION_COUNT",
)
YUBIHSM_SPAM_LINES = {
    "Session keepalive set up to run every 15 seconds",
}


class InterceptorError(RuntimeError):
    """Raised for fatal interceptor failures."""

    def __init__(self, message: str, returncode: int = 1):
        super().__init__(message)
        self.returncode = returncode


@dataclass
class TeeCaptureResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass
class Interceptor:
    pkcs11_scriptpath: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    scriptpath: Path = field(init=False)
    cmd: str = ""
    num_tries: int = 2
    fail_sleep_time: int = 15
    is_a_signing_command: bool = False
    fifo_read_wait_time: int = 77
    fifo_read_cycles: int = 9
    args: list[str] = field(default_factory=list)
    tool_args: list[str] = field(default_factory=list)
    jar: str | None = None
    _vendor_environment_loaded: bool = False
    _we_started_apksigner: bool = False
    _we_started_yubihsm_connector: bool = False
    _batch_restart_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.scriptpath = self.pkcs11_scriptpath.parent

    def run(self, argv: list[str]) -> int:
        self.cmd = os.environ["SIGNING_COMMAND"]
        if self.cmd == "avbtool":
            self.handle_avbtool(argv)
        elif self.cmd == "java":
            self.handle_java(argv)
        else:
            self.args = list(argv)
            # Prefer caution and treat everything else as a signing command.
            self.is_a_signing_command = True

        with self.maybe_hold_lock():
            result = self.run_command_maybe_batch()
        return 0 if result is None else result

    def maybe_hold_lock(self):
        lockfile = os.environ.get("YUBIHSM_LOCKFILE", "")
        if not lockfile:
            return _NullContext()
        return _LockedFile(Path(lockfile))

    def run_command_maybe_batch(self) -> int:
        use_apksigner_batch = False
        command_err = 0
        try_number = 1

        if self.is_a_signing_command:
            self.load_vendor_environment()
            if self.jar == "apksigner" and os.environ.get("APKSIGNER_BATCH_RUNTIME_DIR"):
                use_apksigner_batch = True
                self.maybe_start_apksigner_batch()

        if use_apksigner_batch:
            command_err = self.run_apksigner_batch_once()
            if command_err:
                print(
                    f"apksigner batch command exited with error {command_err}, so we will try non-batch this time.",
                    file=sys.stderr,
                )

        if command_err or not use_apksigner_batch:
            command_err = 0
            for try_number in range(1, self.num_tries + 1):
                result = self.transparent_catch([self.cmd, *self.args])
                command_err = result.returncode

                if command_err and os.environ.get("YUBIHSM_CONNECTOR_PIDFILE"):
                    if any(message in result.stderr for message in CONNECTOR_ERROR_MESSAGES):
                        self.maybe_start_or_restart_yubihsm_connector()
                        result = self.transparent_catch([self.cmd, *self.args])
                        command_err = result.returncode

                if command_err and self.should_retry_for_session_error(result.stdout, result.stderr):
                    print(
                        f"Warning: {self.cmd} failed on try {try_number} (error {command_err}).",
                        file=sys.stderr,
                    )
                    time.sleep(self.fail_sleep_time)
                    continue

                break

        log_err = 0
        if self.is_a_signing_command:
            for log_try in range(1, self.num_tries + 1):
                prepend_line = self.build_log_prefix(command_err or 0, try_number, log_try)
                try:
                    self.extract_logs(prepend_line)
                except InterceptorError as exc:
                    log_err = exc.returncode
                    print(
                        f"Warning: extract_logs failed on try {log_try} (error {log_err}).",
                        file=sys.stderr,
                    )
                    time.sleep(self.fail_sleep_time)
                    continue
                log_err = 0
                break

        if (command_err or 0) == 0:
            return log_err
        return command_err

    def handle_avbtool(self, argv: list[str]) -> None:
        self.args = []
        for arg in argv:
            if arg.startswith("--signing"):
                self.is_a_signing_command = True
            self.args.append(arg)

    def handle_java(self, argv: list[str]) -> None:
        self.args = []
        self.tool_args = []
        index = 0
        while index < len(argv):
            arg = argv[index]
            if self.jar is None and arg == "-jar" and index + 1 < len(argv):
                jar_path = argv[index + 1]
                self.jar = Path(jar_path).name.removesuffix(".jar")
                self.args.extend((arg, jar_path))
                index += 2
                continue

            if self.jar is not None:
                if arg == "--min-sdk-version" and index + 1 < len(argv):
                    min_sdk_version = int(argv[index + 1])
                    to_add = [arg, argv[index + 1]]
                    if min_sdk_version >= 24:
                        to_add.append("--v1-signing-enabled=false")
                    if min_sdk_version >= 28:
                        to_add.append("--v2-signing-enabled=false")
                    self.args.extend(to_add)
                    self.tool_args.extend(to_add)
                    index += 2
                    continue
                self.tool_args.append(arg)

            self.args.append(arg)
            index += 1

        if self.jar in {"signapk", "apksigner"}:
            self.is_a_signing_command = True

    def load_vendor_environment(self) -> None:
        if self._vendor_environment_loaded:
            return

        defaults = {
            "KEYMAPPER": "static",
            "USE_APKSIGNER": "y",
            "FIND_KEYS_BY_ID": "y",
            "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
            "STRIP_HEX_KEY_ID_PREFIX": "y",
            "YUBIHSM_CONNECTOR": "http://127.0.0.1:12345",
            "YUBIHSM_KEY_CAPABILITIES": "sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa",
            "YUBIHSM_OPAQUE_CAPABILITIES": "",
            "YUBIHSM_ONDEMAND_DOMAIN": "2",
            "YUBIHSM_EXPORTABLE_DOMAIN": "3",
            "YUBIHSM_UNEXPORTABLE_DOMAIN": "4",
            "DATE_FORMAT": "%Y%m%d-%H%M%S",
            "KEYMAP_FILE": str(self.pkcs11_scriptpath / "keymap.tsv"),
        }
        for name, value in defaults.items():
            os.environ.setdefault(name, value)

        self.find_pkcs11_module()
        self.find_yubihsm_shell()
        self._vendor_environment_loaded = True

    def find_pkcs11_module(self) -> str:
        current = os.environ.get("PKCS11_MODULE")
        if current:
            return current

        roots = ("/usr/lib", "/usr/local/lib")
        arches = ("", "/x86_64-linux-gnu", "/aarch64-linux-gnu", "/64")
        subdirs = ("", "/pkcs11")
        for root in roots:
            for arch in arches:
                for subdir in subdirs:
                    candidate = Path(f"{root}{arch}{subdir}/yubihsm_pkcs11.so")
                    if candidate.exists():
                        os.environ["PKCS11_MODULE"] = str(candidate)
                        return str(candidate)

        raise InterceptorError(
            "Please install the YubiHSM PKCS#11 module, or set PKCS11_MODULE to its path.",
        )

    def find_yubihsm_shell(self) -> str:
        current = os.environ.get("YUBIHSM_SHELL_BIN")
        if current:
            return current

        shell_bin = self.which("yubihsm-shell")
        if not shell_bin:
            raise InterceptorError(
                "Please install yubihsm-shell, or set YUBIHSM_SHELL_BIN to its path.",
            )
        os.environ["YUBIHSM_SHELL_BIN"] = shell_bin
        return shell_bin

    def find_yubihsm_connector(self) -> str:
        current = os.environ.get("YUBIHSM_CONNECTOR_BIN")
        if current:
            return current

        connector_bin = self.which("yubihsm-connector")
        if not connector_bin:
            raise InterceptorError(
                "Please install yubihsm-connector, or set YUBIHSM_CONNECTOR_BIN to its path.\n"
                "Alternatively, set NEVER_START_YUBIHSM_CONNECTOR=y.",
            )
        os.environ["YUBIHSM_CONNECTOR_BIN"] = connector_bin
        return connector_bin

    def build_log_prefix(self, command_err: int, try_number: int, log_try: int) -> str:
        quoted = "".join(f" {shlex.quote(value)}" for value in [self.cmd, *self.args])
        prepend_line = f"{quoted} # Result: {command_err}"
        if try_number > 1:
            prepend_line += f" Try: {try_number}"
        if log_try > 1:
            prepend_line += f" Try (log): {log_try}"
        return prepend_line

    def transparent_catch(self, command: list[str]) -> TeeCaptureResult:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except FileNotFoundError:
            message = f"{command[0]}: command not found\n"
            sys.stderr.write(message)
            sys.stderr.flush()
            return TeeCaptureResult(stdout="", stderr=message, returncode=127)

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        def reader(stream, sink: TextIO, capture: list[bytes], spam_filter: bool = False) -> None:
            for chunk in iter(lambda: stream.read(8192), b""):
                capture.append(chunk)
                if spam_filter:
                    sink.buffer.write(self.filter_yubihsm_spam(chunk))
                else:
                    sink.buffer.write(chunk)
                sink.flush()

        stdout_thread = threading.Thread(
            target=reader,
            args=(process.stdout, sys.stdout, stdout_chunks),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=reader,
            args=(process.stderr, sys.stderr, stderr_chunks),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        returncode = process.wait()
        stdout_thread.join()
        stderr_thread.join()

        stdout = b"".join(stdout_chunks).decode(errors="replace")
        stderr = b"".join(stderr_chunks).decode(errors="replace")
        return TeeCaptureResult(stdout=stdout, stderr=stderr, returncode=returncode)

    def filter_yubihsm_spam(self, data: bytes) -> bytes:
        text = data.decode(errors="replace")
        filtered_lines = []
        for line in text.splitlines(keepends=True):
            stripped = line.rstrip("\r\n")
            if stripped.startswith("Created session"):
                continue
            if stripped in YUBIHSM_SPAM_LINES:
                continue
            filtered_lines.append(line)
        return "".join(filtered_lines).encode()

    def should_retry_for_session_error(self, stdout: str, stderr: str) -> bool:
        combined = f"{stdout} {stderr}"
        return any(message in combined for message in SESSION_ALLOCATION_MESSAGES)

    def extract_logs(self, comment: str = "") -> None:
        if os.environ.get("DRY_RUN") == "y":
            return

        log_path = os.environ.get("AUDIT_LOG_PATH")
        if not log_path:
            raise InterceptorError(
                "Cannot extract logs when there is nowhere appropriate to extract them to.",
            )

        audit_script = self.pkcs11_scriptpath / "vendor.yubihsm.audit.logs.py"
        env = os.environ.copy()
        command = [str(audit_script), "--log-file", log_path, "--comment", comment]
        result = subprocess.run(command, env=env, check=False)
        if result.returncode != 0:
            raise InterceptorError("Failed to extract logs.", result.returncode)

    def is_yubihsm_connector_running(self) -> bool:
        connector_bin = os.environ.get("YUBIHSM_CONNECTOR_BIN", "")
        connector_name = Path(connector_bin).name if connector_bin else "yubihsm-connector"
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            try:
                cmdline = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").strip()
            except OSError:
                continue
            if not cmdline:
                continue
            try:
                command = cmdline.decode(errors="replace")
            except UnicodeDecodeError:
                continue
            first_token = command.split(" ", 1)[0]
            first_name = Path(first_token).name
            if first_token == connector_bin or first_name == connector_name or first_name == "yubihsm-connector":
                return True
        return False

    def maybe_start_yubihsm_connector(self, pidfile: str | None = None) -> None:
        self.maybe_start_or_restart_yubihsm_connector(pidfile=pidfile, start_only=True)

    def maybe_start_or_restart_yubihsm_connector(
        self,
        pidfile: str | None = None,
        start_only: bool = False,
    ) -> None:
        if os.environ.get("NEVER_START_YUBIHSM_CONNECTOR") == "y":
            return

        connector_url = os.environ.get("YUBIHSM_CONNECTOR", "")
        if connector_url.startswith("yhusb://"):
            return

        connector_bin = self.find_yubihsm_connector()
        if start_only and self.is_yubihsm_connector_running():
            return

        resolved_pidfile = os.environ.get("YUBIHSM_CONNECTOR_PIDFILE") or pidfile
        if not resolved_pidfile:
            raise InterceptorError(
                "Cannot start/restart YubiHSM connector without YUBIHSM_CONNECTOR_PIDFILE specified.",
            )

        os.environ["YUBIHSM_CONNECTOR_PIDFILE"] = resolved_pidfile
        self.maybe_stop_yubihsm_connector(for_restart=True)
        os.environ["YUBIHSM_CONNECTOR_PIDFILE"] = resolved_pidfile

        process = subprocess.Popen(
            [connector_bin],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        Path(resolved_pidfile).write_text(f"{process.pid}\n")
        self._we_started_yubihsm_connector = True

    def maybe_stop_yubihsm_connector(self, for_restart: bool = False) -> None:
        if os.environ.get("NEVER_START_YUBIHSM_CONNECTOR") == "y":
            return
        if not for_restart and not self._we_started_yubihsm_connector:
            return

        pidfile = os.environ.get("YUBIHSM_CONNECTOR_PIDFILE", "")
        if not pidfile:
            return

        pid_path = Path(pidfile)
        if pid_path.exists():
            pid = self.read_pid(pid_path)
            if pid is not None and self.is_process_running(pid):
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
            if pid is not None and self.is_process_running(pid):
                raise InterceptorError("Could not kill existing yubihsm-connector.")
            pid_path.unlink(missing_ok=True)
        os.environ["YUBIHSM_CONNECTOR_PIDFILE"] = ""

    def maybe_start_apksigner_batch(self, runtime_dir: str | None = None) -> None:
        self.maybe_start_or_restart_apksigner_batch(runtime_dir=runtime_dir, start_only=True)

    def maybe_start_or_restart_apksigner_batch(
        self,
        runtime_dir: str | None = None,
        start_only: bool = False,
    ) -> None:
        if os.environ.get("NEVER_START_APKSIGNER_BATCH") == "y":
            return
        if os.environ.get("DRY_RUN") == "y":
            return

        runtime_dir_value = os.environ.get("APKSIGNER_BATCH_RUNTIME_DIR") or runtime_dir
        if not runtime_dir_value:
            raise InterceptorError("Must set APKSIGNER_BATCH_RUNTIME_DIR to start apksigner")
        os.environ["APKSIGNER_BATCH_RUNTIME_DIR"] = runtime_dir_value
        runtime_path = Path(runtime_dir_value)

        pidfile = os.environ.get("APKSIGNER_BATCH_PIDFILE") or str(runtime_path / "apksigner.pid")
        os.environ["APKSIGNER_BATCH_PIDFILE"] = pidfile

        apksigner_batch_pid = None
        keepalive_pid = None
        was_running_once = Path(pidfile).exists()
        if was_running_once:
            apksigner_batch_pid = self.read_pid(Path(pidfile))
            keepalive_path = runtime_path / "apksigner_keepalive.pid"
            if not keepalive_path.exists():
                raise InterceptorError(f"Missing apksigner keepalive pid file: {keepalive_path}")
            keepalive_pid = self.read_pid(keepalive_path)

        stdin_fifo = runtime_path / "apksigner_stdin_fifo"
        stdout_fifo = runtime_path / "apksigner_stdout_fifo"
        stderr_fifo = runtime_path / "apksigner_stderr_fifo"
        os.environ["APKSIGNER_BATCH_STDIN_FIFO"] = str(stdin_fifo)
        os.environ["APKSIGNER_BATCH_STDOUT_FIFO"] = str(stdout_fifo)
        os.environ["APKSIGNER_BATCH_STDERR_FIFO"] = str(stderr_fifo)

        if start_only and apksigner_batch_pid and self.is_process_running(apksigner_batch_pid):
            os.environ["APKSIGNER_BATCH_PID"] = str(apksigner_batch_pid)
            return

        self.maybe_stop_apksigner_batch(
            runtime_dir=runtime_dir_value,
            apksigner_batch_pid=apksigner_batch_pid,
            keepalive_pid=keepalive_pid,
            should_stop=True,
        )

        runtime_path.mkdir(parents=True, exist_ok=True)
        for fifo in (stdin_fifo, stdout_fifo, stderr_fifo):
            try:
                os.mkfifo(fifo)
            except FileExistsError:
                fifo.unlink()
                os.mkfifo(fifo)

        cwd = Path.cwd()
        java_cmd = [
            "java",
            "-Xmx4096m",
            "--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED",
            "--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
            f"-Djava.library.path={cwd / 'lib64'}",
            "-jar",
            str(cwd / "framework" / "apksigner.jar"),
            "batch",
        ]

        stdin_fd = os.open(stdin_fifo, os.O_RDWR)
        stdout_fd = os.open(stdout_fifo, os.O_RDWR)
        stderr_fd = os.open(stderr_fifo, os.O_RDWR)
        try:
            process = subprocess.Popen(
                java_cmd,
                stdin=stdin_fd,
                stdout=stdout_fd,
                stderr=stderr_fd,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            os.close(stdin_fd)
            os.close(stdout_fd)
            os.close(stderr_fd)

        Path(pidfile).write_text(f"{process.pid}\n")
        os.environ["APKSIGNER_BATCH_PID"] = str(process.pid)

        keepalive_fd = os.open(stdin_fifo, os.O_RDWR)
        try:
            keepalive = subprocess.Popen(
                ["sleep", "infinity"],
                stdin=subprocess.DEVNULL,
                stdout=keepalive_fd,
                stderr=keepalive_fd,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            os.close(keepalive_fd)

        (runtime_path / "apksigner_keepalive.pid").write_text(f"{keepalive.pid}\n")
        if not was_running_once:
            self._we_started_apksigner = True

        time.sleep(1)
        if not self.is_process_running(process.pid):
            raise InterceptorError("Apksigner not running!")
        if not self.is_process_running(keepalive.pid):
            raise InterceptorError("Keepalive not running!")

    def maybe_stop_apksigner_batch(
        self,
        runtime_dir: str | None = None,
        apksigner_batch_pid: int | None = None,
        keepalive_pid: int | None = None,
        should_stop: bool | None = None,
    ) -> None:
        if os.environ.get("NEVER_START_APKSIGNER_BATCH") == "y":
            return
        if os.environ.get("DRY_RUN") == "y":
            return
        if should_stop is None:
            should_stop = self._we_started_apksigner
        if not should_stop:
            return

        runtime_path = Path(runtime_dir or os.environ.get("APKSIGNER_BATCH_RUNTIME_DIR", ""))
        if not runtime_path.is_dir():
            print(f"apksigner runtime dir does not exist: {runtime_path}", file=sys.stderr)
            return

        pid_path = runtime_path / "apksigner.pid"
        keepalive_path = runtime_path / "apksigner_keepalive.pid"
        if (apksigner_batch_pid is None or keepalive_pid is None) and pid_path.exists():
            apksigner_batch_pid = apksigner_batch_pid or self.read_pid(pid_path)
            keepalive_pid = keepalive_pid or self.read_pid(keepalive_path)

        stdin_fifo = runtime_path / "apksigner_stdin_fifo"
        stdout_fifo = runtime_path / "apksigner_stdout_fifo"
        stderr_fifo = runtime_path / "apksigner_stderr_fifo"

        self.write_batch_shutdown(stdin_fifo)
        self.drain_fifo(stdout_fifo)
        self.drain_fifo(stderr_fifo)

        if keepalive_pid is not None:
            self.stop_process(keepalive_pid, "Could not kill apksigner keepalive process")

        pid_path.unlink(missing_ok=True)
        keepalive_path.unlink(missing_ok=True)
        stdin_fifo.unlink(missing_ok=True)
        stdout_fifo.unlink(missing_ok=True)
        stderr_fifo.unlink(missing_ok=True)

        if apksigner_batch_pid is not None:
            self.stop_process(apksigner_batch_pid, f"Could not kill apksigner, pid {apksigner_batch_pid}")

    def write_batch_shutdown(self, fifo_path: Path) -> None:
        try:
            fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
        except OSError:
            return
        try:
            os.write(fd, b"\0\0")
        except OSError:
            pass
        finally:
            os.close(fd)

    def drain_fifo(self, fifo_path: Path, timeout_seconds: float = 1.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
            except OSError:
                return
            try:
                ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
                if not ready:
                    return
                try:
                    if not os.read(fd, 8192):
                        return
                except BlockingIOError:
                    return
            finally:
                os.close(fd)

    def run_apksigner_batch_once(self) -> int:
        stdin_fifo = os.environ["APKSIGNER_BATCH_STDIN_FIFO"]
        payload = self.build_batch_payload(self.tool_args)
        try:
            with open(stdin_fifo, "ab", buffering=0) as fifo:
                fifo.write(payload)
        except OSError as exc:
            return exc.errno or 1

        stdout_returncode: int | None = None
        exceptions: list[BaseException] = []

        def stdout_reader() -> None:
            nonlocal stdout_returncode
            try:
                stdout_returncode = self.read_all_fifo(
                    Path(os.environ["APKSIGNER_BATCH_STDOUT_FIFO"]),
                    sys.stdout,
                )
            except BaseException as exc:  # pragma: no cover - defensive
                exceptions.append(exc)

        def stderr_reader() -> None:
            try:
                self.read_all_fifo(Path(os.environ["APKSIGNER_BATCH_STDERR_FIFO"]), sys.stderr)
            except BaseException as exc:  # pragma: no cover - defensive
                exceptions.append(exc)

        out_thread = threading.Thread(target=stdout_reader, daemon=True)
        err_thread = threading.Thread(target=stderr_reader, daemon=True)
        out_thread.start()
        err_thread.start()
        out_thread.join()
        err_thread.join()

        if exceptions:
            first = exceptions[0]
            if isinstance(first, InterceptorError):
                return first.returncode
            return 1
        return stdout_returncode if stdout_returncode is not None else 1

    def build_batch_payload(self, arguments: Iterable[str]) -> bytes:
        argument_list = list(arguments)
        parts = [str(len(argument_list)), *argument_list]
        return b"\0".join(part.encode() for part in parts) + b"\0"

    def read_all_fifo(self, fifo_path: Path, sink: TextIO) -> int:
        for _ in range(self.fifo_read_cycles):
            captured = self.read_fifo_record(fifo_path, timeout=self.fifo_read_wait_time)
            if captured.startswith("RETURN:"):
                value = captured.removeprefix("RETURN:")
                return int(value or "0")
            if any(message in captured for message in CONNECTOR_ERROR_MESSAGES):
                self.restart_batch_after_connector_failure()
                continue
            sink.write(captured)
            sink.flush()
        return 1

    def read_fifo_record(self, fifo_path: Path, timeout: int) -> str:
        fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
        try:
            buffer = bytearray()
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InterceptorError(f"Timed out reading FIFO {fifo_path}")
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    raise InterceptorError(f"Timed out reading FIFO {fifo_path}")
                try:
                    chunk = os.read(fd, 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    raise InterceptorError(f"Unexpected EOF reading FIFO {fifo_path}")
                nul = chunk.find(b"\0")
                if nul == -1:
                    buffer.extend(chunk)
                    continue
                buffer.extend(chunk[:nul])
                return buffer.decode(errors="replace")
        finally:
            os.close(fd)
        raise InterceptorError(f"Failed to read FIFO {fifo_path}")

    def restart_batch_after_connector_failure(self) -> None:
        with self._batch_restart_lock:
            self.maybe_start_or_restart_yubihsm_connector()
            time.sleep(1)
            self.maybe_start_or_restart_apksigner_batch()
            time.sleep(1)

    def read_pid(self, path: Path) -> int | None:
        try:
            return int(path.read_text().strip())
        except (OSError, ValueError):
            return None

    def which(self, command: str) -> str | None:
        search_path = os.environ.get("PATH", "")
        for directory in search_path.split(os.pathsep):
            if not directory:
                continue
            candidate = Path(directory) / command
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def is_process_running(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def stop_process(self, pid: int, error_message: str) -> None:
        if self.is_process_running(pid):
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.1)
        if self.is_process_running(pid):
            os.kill(pid, signal.SIGKILL)
            time.sleep(1)
        if self.is_process_running(pid):
            raise InterceptorError(error_message)


class _NullContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class _LockedFile:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+")
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
        return self.handle

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.handle is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
        return False


def main(argv: list[str] | None = None) -> int:
    interceptor = Interceptor()
    try:
        return interceptor.run(list(sys.argv[1:] if argv is None else argv))
    except InterceptorError as exc:
        print(exc, file=sys.stderr)
        return exc.returncode
    except KeyError as exc:
        print(f"Missing required environment variable: {exc.args[0]}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return errno.EPIPE


if __name__ == "__main__":
    raise SystemExit(main())





