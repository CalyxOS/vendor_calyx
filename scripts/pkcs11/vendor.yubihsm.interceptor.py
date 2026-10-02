#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

"""
Signing-command interceptor for the YubiHSM vendor.

It is invoked as argv[0] in place of the underlying signing tool (avbtool,
or "java -jar apksigner.jar"/"signapk.jar"), with that tool's command name
in the SIGNING_COMMAND environment variable.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import threading
import time
import unicodedata
from io import BufferedReader
from pathlib import Path
from typing import BinaryIO

SCRIPT_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(SCRIPT_DIR.parent))
sys.path.insert(0, str(SCRIPT_DIR))

from signing.apksigner_batch import run_in_batch
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    extract_and_save_audit_log,
    restart_connector,
)
from signing_cache import from_cache, to_cache

_NUM_TRIES = 2
_FAIL_SLEEP_TIME = 15
_CONNECTOR_FAILURE_MARKERS = (
    b"Connector operation failed",
    b"Unable to find a suitable connector",
)
_SESSION_EXHAUSTION_MARKERS = (b"All sessions are allocated", b"SESSION_COUNT")


_PRINTF_Q_ESCAPED = frozenset(" !\"$&'()*,;<>?[\\]^`{|}")
_ANSI_C_ESCAPES = {
    "\a": "\\a",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\v": "\\v",
    "\f": "\\f",
    "\r": "\\r",
    "\x1b": "\\E",
    "\\": "\\\\",
    "'": "\\'",
}
_ANSI_C_QUOTED_CATEGORIES = frozenset(("Cc", "Cn", "Cs", "Zl", "Zp"))


def _needs_ansi_c_quoting(character: str) -> bool:
    return unicodedata.category(character) in _ANSI_C_QUOTED_CATEGORIES


def _ansi_c_escape(character: str) -> str:
    if character in _ANSI_C_ESCAPES:
        return _ANSI_C_ESCAPES[character]
    if _needs_ansi_c_quoting(character):
        return "".join(
            f"\\{byte:03o}"
            for byte in character.encode("utf-8", "surrogateescape")
        )
    return character


def printf_q(argument: str) -> str:
    """
    Quote an argument for a shell, escaping special characters with
    backslashes and writing control characters in $'...' form.

    Args:
        argument: Command-line argument.

    Returns:
        The quoted argument.
    """
    if not argument:
        return "''"
    if any(_needs_ansi_c_quoting(c) for c in argument):
        return "$'" + "".join(map(_ansi_c_escape, argument)) + "'"
    return "".join(
        f"\\{c}"
        if c in _PRINTF_Q_ESCAPED
        or (c == "#" and index == 0)
        or (c == "~" and (index == 0 or argument[index - 1] in "=:"))
        else c
        for index, c in enumerate(argument)
    )


def classify_avbtool(args: list[str]) -> bool:
    """
    Return whether an avbtool invocation is a signing command.

    Any "--signing*" argument marks the whole invocation as a signing
    command (avbtool is also used for non-signing operations like image
    inspection, which must not trigger caching/audit log extraction).

    Args:
        args: The avbtool arguments, without the program name.

    Returns:
        Whether the invocation signs.
    """
    return any(arg.startswith("--signing") for arg in args)


def classify_java(args: list[str]) -> tuple[list[str], str | None, bool]:
    """
    Rewrite a "java ..." invocation and classify it as a signing command.

    A signapk or apksigner -jar target is a signing command, and
    "--min-sdk-version N" becomes the matching
    "--v1/v2-signing-enabled=false" flags apksigner needs to skip
    unnecessary signature schemes.

    Args:
        args: The java arguments, without the program name.

    Returns:
        (rewritten_args, jar_name_without_extension, is_signing_command).
    """
    rewritten: list[str] = []
    jar: str | None = None
    index = 0
    count = len(args)
    while index < count:
        arg = args[index]
        if jar is None and arg == "-jar" and index + 1 < count:
            jar = Path(args[index + 1]).name
            if jar.endswith(".jar"):
                jar = jar[: -len(".jar")]
            rewritten += [arg, args[index + 1]]
            index += 2
            continue
        if jar is not None and arg == "--min-sdk-version" and index + 1 < count:
            min_sdk_version = int(args[index + 1])
            to_add = [arg, args[index + 1]]
            if min_sdk_version >= 24:
                to_add.append("--v1-signing-enabled=false")
            if min_sdk_version >= 28:
                to_add.append("--v2-signing-enabled=false")
            rewritten += to_add
            index += 2
            continue
        rewritten.append(arg)
        index += 1
    is_signing_command = jar in ("signapk", "apksigner")
    return rewritten, jar, is_signing_command


def extract_logs(comment: str) -> None:
    """
    Append the YubiHSM's new audit log entries and a comment line.

    A no-op under DRY_RUN, and requires AUDIT_LOG_PATH, YUBIHSM_AUTHKEY and
    YUBIHSM_PASSWORD to be set otherwise.

    Args:
        comment: Text of the comment line written after the entries.

    Raises:
        RuntimeError: If AUDIT_LOG_PATH is unset or the extraction fails.
        KeyError: If YUBIHSM_AUTHKEY or YUBIHSM_PASSWORD is unset.
    """
    if os.environ.get("DRY_RUN") == "y":
        return
    log_path = os.environ.get("AUDIT_LOG_PATH")
    if not log_path:
        raise RuntimeError(
            "Cannot extract logs when there is nowhere appropriate to "
            "extract them to.",
        )
    config = YubiHsmConfig(
        connector_url=os.environ.get(
            "YUBIHSM_CONNECTOR",
            "http://127.0.0.1:12345",
        ),
        auth_key=os.environ["YUBIHSM_AUTHKEY"],
        password=os.environ["YUBIHSM_PASSWORD"],
    )
    extract_and_save_audit_log(config, Path(log_path), comment)


def _run_wrapped_command(
    cmd: str,
    args: list[str],
) -> subprocess.CompletedProcess[bytes]:
    """
    Run the underlying signing command, passing its output through as it
    arrives while also capturing it for marker checks.

    Args:
        cmd: The signing command.
        args: Its arguments.

    Returns:
        The finished process with its captured output.
    """
    process = subprocess.Popen(
        [cmd, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    captured: dict[str, bytes] = {}

    def relay(name: str, source: BufferedReader, sink: BinaryIO) -> None:
        chunks: list[bytes] = []
        for chunk in iter(lambda: source.read1(65536), b""):
            sink.write(chunk)
            sink.flush()
            chunks.append(chunk)
        captured[name] = b"".join(chunks)

    relays = [
        threading.Thread(
            target=relay,
            args=("stdout", process.stdout, sys.stdout.buffer),
        ),
        threading.Thread(
            target=relay,
            args=("stderr", process.stderr, sys.stderr.buffer),
        ),
    ]
    for thread in relays:
        thread.start()
    returncode = process.wait()
    for thread in relays:
        thread.join()
    return subprocess.CompletedProcess(
        [cmd, *args],
        returncode,
        captured["stdout"],
        captured["stderr"],
    )


def run_command(
    cmd: str,
    args: list[str],
    is_signing_command: bool,
    jar: str | None,
) -> int:
    """
    Run the underlying signing command with caching, retry, and audit logging.

    Args:
        cmd: The signing command.
        args: Its arguments.
        is_signing_command: Whether the command signs, so that its result
            may be cached and the audit log extracted after it.
        jar: The Java tool the command runs, if any.

    Returns:
        The command's exit status.

    Raises:
        RuntimeError: If the audit log cannot be extracted.
    """
    cache_miss: bool | None = None
    need_log_export = False
    err = 0
    try_number = 1

    cache_dir = os.environ.get("YUBIHSM_SIGNING_CACHE", "")
    cache_enabled = bool(cache_dir) and Path(cache_dir).is_dir()
    use_cache = is_signing_command and jar == "apksigner" and cache_enabled
    if use_cache:
        try:
            from_cache([cmd, *args])
        except SystemExit as cache_result:
            cache_miss = cache_result.code != 0
        except Exception as error:
            print(f"Signing cache lookup failed: {error}", file=sys.stderr)
            cache_miss = True

    server_socket = os.environ.get("SIGNING_SERVER_SOCKET", "")
    ran_in_batch = False
    if (
        server_socket
        and is_signing_command
        and jar == "apksigner"
        and cache_miss is not False
    ):
        batch_result = run_in_batch(
            Path(server_socket),
            args[args.index("-jar") + 2 :],
            cwd=Path.cwd(),
        )
        if batch_result is not None:
            need_log_export = True
            err, stdout, stderr = batch_result
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.write(stderr)
            sys.stderr.buffer.flush()
            if err == 0:
                ran_in_batch = True
            else:
                print(
                    f"apksigner batch command exited with error {err}, so "
                    "we will try non-batch this time.",
                    file=sys.stderr,
                )

    if cache_miss is not False and not ran_in_batch:
        for try_number in range(1, _NUM_TRIES + 1):
            need_log_export = True
            result = _run_wrapped_command(cmd, args)
            stdout, stderr = result.stdout, result.stderr
            err = result.returncode

            if err != 0:
                pid_file = os.environ.get("YUBIHSM_CONNECTOR_PIDFILE")
                if pid_file and any(
                    marker in stderr for marker in _CONNECTOR_FAILURE_MARKERS
                ):
                    restart_connector()
                    result = _run_wrapped_command(cmd, args)
                    stdout, stderr = result.stdout, result.stderr
                    err = result.returncode

                combined = stdout + stderr
                if not any(
                    marker in combined for marker in _SESSION_EXHAUSTION_MARKERS
                ):
                    break
                print(
                    f"Warning: {cmd} failed on try {try_number} (error {err}).",
                    file=sys.stderr,
                )
                time.sleep(_FAIL_SLEEP_TIME)
                continue
            break

    if cache_miss and err == 0 and cache_enabled:
        try:
            to_cache([cmd, *args])
        except (Exception, SystemExit) as error:
            print(f"Signing cache store failed: {error}", file=sys.stderr)

    log_err = 0
    if is_signing_command and need_log_export:
        for log_try in range(1, _NUM_TRIES + 1):
            prepend_line = "".join(f" {printf_q(a)}" for a in [cmd, *args])
            prepend_line += f" # Result: {err}"
            if try_number > 1:
                prepend_line += f" Try: {try_number}"
            if log_try > 1:
                prepend_line += f" Try (log): {log_try}"
            try:
                extract_logs(prepend_line)
                log_err = 0
                break
            except Exception as error:
                log_err = 1
                print(
                    f"Warning: extract_logs failed on try {log_try} ({error}).",
                    file=sys.stderr,
                )
                time.sleep(_FAIL_SLEEP_TIME)

    return err if err != 0 else log_err


def main(argv: list[str] | None = None) -> int:
    """
    Run the signing command SIGNING_COMMAND names with the given arguments.

    Args:
        argv: The command's arguments, or None for sys.argv.

    Returns:
        The command's exit status.
    """
    arguments = sys.argv[1:] if argv is None else argv
    cmd = os.environ.get("SIGNING_COMMAND", "")
    jar: str | None = None
    if cmd == "avbtool":
        args = list(arguments)
        is_signing_command = classify_avbtool(args)
    elif cmd == "java":
        args, jar, is_signing_command = classify_java(list(arguments))
    else:
        # An unknown command may sign, so its audit log is extracted.
        args = list(arguments)
        is_signing_command = True

    lockfile = os.environ.get("YUBIHSM_LOCKFILE")
    if not lockfile:
        return run_command(cmd, args, is_signing_command, jar)

    # A restarted yubihsm-connector must not keep this lock open, which
    # holds because subprocess closes descriptors other than 0/1/2.
    with open(lockfile, "a") as lock_handle:
        fcntl.flock(lock_handle, fcntl.LOCK_EX)
        try:
            return run_command(cmd, args, is_signing_command, jar)
        finally:
            fcntl.flock(lock_handle, fcntl.LOCK_UN)


if __name__ == "__main__":
    sys.exit(main())
