#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR

STUB_VENDOR_INCLUDE = """\
maybe_start_apksigner_batch() { :; }
maybe_start_or_restart_apksigner_batch() { :; }
maybe_start_or_restart_yubihsm_connector() { :; }
is_connector_failure_message() { return 1; }
extract_logs() { :; }
"""

JAVA = """\
#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--out" ]; then out="$arg"; fi
  prev="$arg"
done
printf %s "signed by java" > "$out"
"""


class FakeBatchServer(threading.Thread):
    """
    Answer one request on the apksigner batch FIFOs. Read the
    NUL-separated argument list, write "signed by batch" to its --out
    file when it succeeds, and reply RETURN:<status> on both output FIFOs.
    """

    def __init__(self, runtime: Path, status: int) -> None:
        super().__init__(daemon=True)
        self.runtime = runtime
        self.status = status
        self.request: list[str] | None = None

    def run(self) -> None:
        stdin = self.runtime / "stdin"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            fields = stdin.read_bytes().split(b"\0")
            if fields[0] and len(fields) > int(fields[0]) + 1:
                break
            time.sleep(0.02)
        else:
            return
        self.request = [field.decode() for field in fields[1:-1]]
        if self.status == 0:
            out = self.request[self.request.index("--out") + 1]
            Path(out).write_text("signed by batch")
        reply = f"RETURN:{self.status}\0".encode()
        for name in ("stdout", "stderr"):
            descriptor = os.open(self.runtime / name, os.O_WRONLY)
            os.write(descriptor, reply)
            os.close(descriptor)


def _install_interceptor(tmp_path: Path) -> Path:
    scripts = tmp_path / "scripts"
    (scripts / "pkcs11").mkdir(parents=True)
    shutil.copy(SCRIPTS_DIR / "common.include.sh", scripts)
    interceptor = scripts / "pkcs11" / "vendor.yubihsm.interceptor.sh"
    shutil.copy(
        SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.sh",
        interceptor,
    )
    (scripts / "pkcs11" / "vendor.yubihsm.include.sh").write_text(
        STUB_VENDOR_INCLUDE,
    )
    return interceptor


@pytest.mark.parametrize(
    ("jar", "batch_status", "signed_by", "message"),
    [
        ("apksigner", 0, "signed by batch", None),
        ("apksigner", 1, "signed by java", "try non-batch this time"),
        ("signapk", 0, "signed by java", None),
    ],
)
def test_interceptor_signs_with_batch_runtime_configured(
    tmp_path: Path,
    jar: str,
    batch_status: int,
    signed_by: str,
    message: str | None,
) -> None:
    interceptor = _install_interceptor(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "stdin").touch()
    for name in ("stdout", "stderr"):
        os.mkfifo(runtime / name)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    java = bin_dir / "java"
    java.write_text(JAVA)
    java.chmod(java.stat().st_mode | stat.S_IXUSR)
    out = tmp_path / "out.apk"
    server = FakeBatchServer(runtime, batch_status)
    if jar == "apksigner":
        server.start()

    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in ("YUBIHSM_SIGNING_CACHE", "YUBIHSM_LOCKFILE")
    }
    result = subprocess.run(
        [
            "bash",
            interceptor,
            "-jar",
            f"/out/{jar}.jar",
            "sign",
            "--out",
            str(out),
            "in.apk",
        ],
        env={
            **environment,
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "SIGNING_COMMAND": "java",
            "APKSIGNER_BATCH_RUNTIME_DIR": str(runtime),
            "APKSIGNER_BATCH_STDIN_FIFO": str(runtime / "stdin"),
            "APKSIGNER_BATCH_STDOUT_FIFO": str(runtime / "stdout"),
            "APKSIGNER_BATCH_STDERR_FIFO": str(runtime / "stderr"),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert out.read_text() == signed_by
    if message is not None:
        assert message in result.stderr
