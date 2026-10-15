#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    SCRIPTS_DIR,
    aosp_jar_command,
    install_executable,
    run,
)
from signing.apksigner_batch import (
    ApksignerBatch,
    run_in_batch,
)
from signing.signing_server import SigningServer
from test_release_orchestration import (
    BUILD_NUMBER,
    PKCS11_ENVIRONMENT,
    make_release_tree,
    write_target_files_zip,
)

pytestmark = pytest.mark.usefixtures("small_metadata")


INTERCEPTOR = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.py"

FAKE_JAVA = f"""#!{sys.executable}
import os, sys
from pathlib import Path

log = Path(os.environ["FAKE_JAVA_LOG"])
args = sys.argv[1:]
tool_args = args[args.index("-jar") + 2:]

def record(line):
    with log.open("a") as handle:
        handle.write(line + "\\n")

def execute(command):
    if "--die" in command:
        os._exit(3)
    if "--out" in command:
        Path(command[command.index("--out") + 1]).write_text(command[-1])
    sys.stdout.write(f"pid={{os.getpid()}} args={{' '.join(command)}}")
    sys.stderr.write("stderr from fake apksigner")
    return 1 if "--fail" in command else 0

if tool_args != ["batch"]:
    record("direct " + " ".join(tool_args))
    sys.exit(execute(tool_args))

if os.environ.get("FAKE_JAVA_NO_BATCH") == "y":
    sys.stderr.write("Unsupported command: batch")
    sys.exit(1)

record(f"start {{os.getpid()}} " + " ".join(args[:args.index("-jar") + 2]))
record("extra=" + os.environ.get("FAKE_JAVA_EXTRA", ""))
stdin = sys.stdin.buffer
tokens = []
buffer = b""
while True:
    while b"\\0" not in buffer:
        chunk = os.read(stdin.fileno(), 4096)
        if not chunk:
            record("eof")
            sys.exit(0)
        buffer += chunk
    token, buffer = buffer.split(b"\\0", 1)
    tokens.append(token.decode())
    count = int(tokens[0])
    if count == 0:
        record("stop")
        sys.exit(0)
    if len(tokens) < count + 1:
        continue
    command, tokens = tokens[1:], []
    code = execute(command)
    for stream in (sys.stdout, sys.stderr):
        stream.write(f"\\0RETURN:{{code}}\\0")
        stream.flush()
"""


@pytest.fixture
def fake_java(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    install_executable(bin_dir / "java", FAKE_JAVA)
    log = tmp_path / "java.log"
    log.touch()
    monkeypatch.setenv("FAKE_JAVA_LOG", str(log))
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log


def _server(tmp_path: Path) -> SigningServer:
    server = SigningServer(tmp_path / "batch.sock")
    batch = ApksignerBatch(cwd=tmp_path, env=os.environ)
    server.add_service({"apksigner": batch.handle}, batch.close)
    return server


def _starts(log: Path) -> list[str]:
    return [
        line
        for line in log.read_text().splitlines()
        if line.startswith("start")
    ]


def test_command_after_a_failed_one_still_succeeds(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    server = _server(tmp_path)
    with server:
        failed = run_in_batch(
            server.socket_path,
            ["sign", "--fail"],
            cwd=tmp_path,
        )
        after = run_in_batch(
            server.socket_path,
            ["sign", "a.apk"],
            cwd=tmp_path,
        )

    assert failed is not None and failed[0] == 1
    assert after is not None and after[0] == 0
    assert after[1].endswith(b"args=sign a.apk")


def test_two_fresh_processes_failing_their_first_command_disable_batch(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    server = _server(tmp_path)
    with server:
        results = [
            run_in_batch(
                server.socket_path,
                ["sign", "--fail"],
                cwd=tmp_path,
            )
            for _ in range(3)
        ]

    assert [result[0] if result else None for result in results] == [
        1,
        1,
        None,
    ]
    assert len(_starts(fake_java)) == 2


def test_server_keeps_serving_after_a_request_raises(
    tmp_path: Path,
    fake_java: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from signing import apksigner_batch

    original_process = apksigner_batch.BatchProcess
    failures = [OSError("cannot start java")]

    def flaky_process(
        *,
        cwd: Path,
        env: Mapping[str, str],
    ) -> apksigner_batch.BatchProcess:
        if failures:
            raise failures.pop()
        return original_process(cwd=cwd, env=env)

    monkeypatch.setattr(apksigner_batch, "BatchProcess", flaky_process)
    server = _server(tmp_path)
    with server, ThreadPoolExecutor(1) as pool:
        failed = run_in_batch(
            server.socket_path,
            ["sign", "a.apk"],
            cwd=tmp_path,
        )
        after = pool.submit(
            run_in_batch,
            server.socket_path,
            ["sign", "a.apk"],
            cwd=tmp_path,
        ).result(timeout=10)

    assert failed is None
    assert after is not None and after[0] == 0


def test_process_dying_after_a_command_restarts_it(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    server = _server(tmp_path)
    with server:
        run_in_batch(server.socket_path, ["sign", "a"], cwd=tmp_path)
        died = run_in_batch(
            server.socket_path,
            ["sign", "--die"],
            cwd=tmp_path,
        )
        after = run_in_batch(
            server.socket_path,
            ["sign", "b"],
            cwd=tmp_path,
        )

    assert died is None
    assert after is not None and after[0] == 0
    assert len(_starts(fake_java)) == 2


def test_unsupported_batch_mode_disables_the_server(
    tmp_path: Path,
    fake_java: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("FAKE_JAVA_NO_BATCH", "y")
    server = _server(tmp_path)
    with server:
        first = run_in_batch(
            server.socket_path,
            ["sign", "a"],
            cwd=tmp_path,
        )
        monkeypatch.delenv("FAKE_JAVA_NO_BATCH")
        second = run_in_batch(
            server.socket_path,
            ["sign", "b"],
            cwd=tmp_path,
        )

    assert first is None and second is None
    assert _starts(fake_java) == []
    assert (
        "apksigner batch did not complete a command" in capsys.readouterr().err
    )


def test_batch_process_runs_the_apksigner_of_its_directory(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    server = _server(tmp_path)
    with server:
        run_in_batch(server.socket_path, ["sign", "a"], cwd=tmp_path)

    (start,) = _starts(fake_java)
    assert start.endswith(
        f"-Djava.library.path={tmp_path}/lib64 "
        f"-jar {tmp_path}/framework/apksigner.jar",
    )


@pytest.mark.parametrize(
    ("arguments", "directory"),
    ((["sign", "a"], "bin"), ([], "")),
)
def test_a_command_the_batch_cannot_run_is_unavailable(
    tmp_path: Path,
    fake_java: Path,
    arguments: list[str],
    directory: str,
) -> None:
    server = _server(tmp_path)
    with server:
        result = run_in_batch(
            server.socket_path,
            arguments,
            cwd=tmp_path / directory,
        )

    assert result is None
    assert _starts(fake_java) == []


def _run_interceptor(
    tmp_path: Path,
    socket_path: Path,
    *tool_args: str,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        [
            INTERCEPTOR,
            "-Xmx1g",
            "-jar",
            "apksigner.jar",
            "sign",
            *tool_args,
        ],
        cwd=tmp_path,
        env={
            "SIGNING_COMMAND": "java",
            "DRY_RUN": "y",
            "SIGNING_SERVER_SOCKET": str(socket_path),
            **(environment or {}),
        },
        check=False,
    )


def test_interceptor_runs_directly_after_a_failed_batch_command(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    server = _server(tmp_path)
    with server:
        result = _run_interceptor(tmp_path, server.socket_path, "--fail")

    assert result.returncode == 1
    assert "we will try non-batch this time" in result.stderr
    assert "direct sign --fail" in fake_java.read_text().splitlines()


def test_interceptor_serves_a_cached_result_without_the_batch_server(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (tmp_path / "in.apk").write_text("unsigned")
    (tmp_path / "cert.pem").write_text("certificate")
    server = _server(tmp_path)
    with server:
        signed, cached = (
            _run_interceptor(
                tmp_path,
                server.socket_path,
                "--kms-key-alias",
                "0x1100",
                "--cert",
                "cert.pem",
                "--out",
                f"{name}.apk",
                "in.apk",
                environment={"YUBIHSM_SIGNING_CACHE": str(cache)},
            )
            for name in ("signed", "cached")
        )

    assert signed.returncode == 0 and cached.returncode == 0
    assert "args=sign" in signed.stdout
    assert "args=sign" not in cached.stdout
    assert "Cache hit" in cached.stdout
    assert (tmp_path / "cached.apk").read_text() == "in.apk"
    assert len(_starts(fake_java)) == 1
    assert not [
        line
        for line in fake_java.read_text().splitlines()
        if line.startswith("direct")
    ]


def test_interceptor_runs_directly_when_batch_is_unavailable(
    tmp_path: Path,
    fake_java: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_JAVA_NO_BATCH", "y")
    server = _server(tmp_path)
    with server:
        result = _run_interceptor(tmp_path, server.socket_path, "a.apk")

    assert result.returncode == 0
    assert result.stdout.endswith("args=sign a.apk")
    assert "direct sign a.apk" in fake_java.read_text().splitlines()


YUBIHSM_INTERCEPTOR = "/s/pkcs11/vendor.yubihsm.interceptor.py"
RECORDING_SIGN_TARGET_FILES = f"""#!{sys.executable}
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, {str(SCRIPTS_DIR)!r})
from signing.apksigner_batch import run_in_batch

socket = os.environ.get("SIGNING_SERVER_SOCKET")
batch = None
if socket:
    result = run_in_batch(
        Path(socket),
        ["sign", "from-release.apk"],
        cwd=Path.cwd(),
    )
    batch = None if result is None else result[1].decode()
Path(os.environ["RELEASE_RECORD"]).write_text(
    json.dumps({{"argv": sys.argv[1:], "socket": socket, "batch": batch}})
)
Path(sys.argv[-1]).write_text("signed-target-files")
"""


def _release_tree(root: Path) -> Path:
    make_release_tree(root)
    install_executable(
        root / "bin" / "sign_target_files_apks",
        RECORDING_SIGN_TARGET_FILES,
    )
    write_target_files_zip(
        root / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    return root


@pytest.fixture
def short_tmpdir() -> Iterator[Path]:
    """
    A TMPDIR short enough for the release's signing-server socket path.
    """
    directory = Path(tempfile.mkdtemp(prefix="release.", dir="/tmp"))
    yield directory
    shutil.rmtree(directory)


def _release(
    tmp_path: Path,
    tmpdir: Path,
    environment: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
    tree = _release_tree(tmp_path / "release")
    record = tmp_path / "release-record.json"
    result = run(
        [
            SCRIPTS_DIR / "release.sh",
            "bramble",
            f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        ],
        cwd=tree,
        env={
            "BUILD_NUMBER": BUILD_NUMBER,
            "KEYMAPPER": "id2b",
            "OTA_ONLY": "y",
            "PYTHONPATH": str(SCRIPTS_DIR),
            "RELEASE_RECORD": str(record),
            "TMPDIR": str(tmpdir),
            **PKCS11_ENVIRONMENT,
            "YUBIHSM_AUTHKEY": "0x0001",
            "YUBIHSM_PASSWORD": "test-only",
            **environment,
        },
        check=False,
    )
    recorded = json.loads(record.read_text()) if record.exists() else None
    return result, recorded


HELPERS = SCRIPTS_DIR / "pkcs11"


@pytest.mark.parametrize(
    ("extra", "batch_runs"),
    [({}, True), ({"NEVER_START_APKSIGNER_BATCH": "y"}, False)],
)
def test_release_hosts_the_signing_server_for_its_tools(
    tmp_path: Path,
    short_tmpdir: Path,
    fake_java: Path,
    extra: dict[str, str],
    batch_runs: bool,
) -> None:
    result, recorded = _release(
        tmp_path,
        short_tmpdir,
        {"SIGNING_COMMAND_INTERCEPTOR": YUBIHSM_INTERCEPTOR, **extra},
    )

    assert result.returncode == 0, result.stderr
    assert recorded is not None
    assert recorded["socket"] is not None
    assert not Path(recorded["socket"]).exists()
    if batch_runs:
        assert recorded["batch"].endswith("args=sign from-release.apk")
        assert len(_starts(fake_java)) == 1
    else:
        assert recorded["batch"] is None
        assert _starts(fake_java) == []
    argv = " ".join(recorded["argv"])
    assert "--apksigner_kms_type external" in argv
    assert f"--signing_helper {HELPERS}/signing_helper.py" in argv
    assert f"--payload_signer {HELPERS}/payload_signer.py" in argv


@pytest.mark.parametrize(
    "environment",
    [
        {"SIGNING_COMMAND_INTERCEPTOR": "/s/x.sh"},
        {},
    ],
)
def test_release_without_the_yubihsm_interceptor_has_no_server(
    tmp_path: Path,
    short_tmpdir: Path,
    fake_java: Path,
    environment: dict[str, str],
) -> None:
    result, recorded = _release(tmp_path, short_tmpdir, environment)

    assert result.returncode == 0, result.stderr
    assert recorded is not None
    assert recorded["socket"] is None
    assert "--apksigner_kms_type external" in " ".join(recorded["argv"])


def test_release_dry_run_has_no_server(
    tmp_path: Path,
    short_tmpdir: Path,
    fake_java: Path,
) -> None:
    result, recorded = _release(
        tmp_path,
        short_tmpdir,
        {"SIGNING_COMMAND_INTERCEPTOR": YUBIHSM_INTERCEPTOR, "DRY_RUN": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert recorded is None
    assert "sign_target_files_apks" in result.stderr
    assert "--apksigner_kms_type external" in result.stderr
    assert "signing_helper.py" in result.stderr
    assert "payload_signer.py" in result.stderr


def test_batch_process_sees_environment_set_after_the_handler(
    tmp_path: Path,
    fake_java: Path,
) -> None:
    environment = dict(os.environ)
    handler = ApksignerBatch(cwd=tmp_path, env=environment)
    environment["FAKE_JAVA_EXTRA"] = "set-later"
    server = SigningServer(tmp_path / "batch.sock")
    server.add_service({"apksigner": handler.handle}, handler.close)

    with server:
        run_in_batch(server.socket_path, ["sign", "a"], cwd=tmp_path)

    assert "extra=set-later" in fake_java.read_text()


def _local_signing_key(directory: Path) -> tuple[Path, Path]:
    key = directory / "key.pem"
    certificate = directory / "key.x509.pem"
    pk8 = directory / "key.pk8"
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key,
            "-out",
            certificate,
            "-days",
            "1",
            "-subj",
            "/CN=apksigner batch test",
        ],
    )
    run(
        [
            "openssl",
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            key,
            "-outform",
            "DER",
            "-out",
            pk8,
        ],
    )
    return pk8, certificate


def _sign_arguments(
    pk8: Path,
    certificate: Path,
    app: Path,
    output: str,
) -> list[str]:
    return [
        "sign",
        "--v4-signing-enabled=false",
        "--key",
        str(pk8),
        "--cert",
        str(certificate),
        "--out",
        output,
        str(app),
    ]


@pytest.mark.aosp
def test_interceptor_signs_with_the_tree_apksigner_through_the_server(
    tmp_path: Path,
    aosp_top: Path,
) -> None:
    java, *java_options = aosp_jar_command(aosp_top, "apksigner.jar")
    app = aosp_top / "build/make/tools/releasetools/testdata/TestApp.apk"
    pk8, certificate = _local_signing_key(tmp_path)
    run(
        [
            java,
            *java_options,
            *_sign_arguments(pk8, certificate, app, "direct.apk"),
        ],
        cwd=tmp_path,
    )
    # The interceptor reports its resolved cwd, so resolve a symlinked out/.
    host = (aosp_top / "out" / "host" / "linux-x86").resolve()
    handler = ApksignerBatch(
        cwd=host,
        env={**os.environ, "PATH": f"{Path(java).parent}:{os.environ['PATH']}"},
    )
    server = SigningServer(tmp_path / "batch.sock")
    server.add_service({"apksigner": handler.handle}, handler.close)

    signed: list[subprocess.CompletedProcess[str]] = []
    processes: list[object] = []
    with server:
        for name in ("first.apk", "second.apk"):
            signed.append(
                run(
                    [
                        INTERCEPTOR,
                        *java_options,
                        *_sign_arguments(
                            pk8,
                            certificate,
                            app,
                            str(tmp_path / name),
                        ),
                    ],
                    cwd=host,
                    env={
                        "PATH": f"{Path(java).parent}:{os.environ['PATH']}",
                        "SIGNING_COMMAND": "java",
                        "DRY_RUN": "y",
                        "SIGNING_SERVER_SOCKET": str(server.socket_path),
                    },
                    check=False,
                ),
            )
            processes.append(handler.process)

    assert [result.returncode for result in signed] == [0, 0], signed[0].stderr
    assert not any("non-batch" in result.stderr for result in signed)
    assert processes[0] is not None
    assert processes[1] is processes[0]
    direct = (tmp_path / "direct.apk").read_bytes()
    assert (tmp_path / "first.apk").read_bytes() == direct
    assert (tmp_path / "second.apk").read_bytes() == direct
