#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import (
    ID2B_KEYMAP,
    REPO_ROOT,
    SCRIPTS_DIR,
    default_signal_dispositions,
    install_executable,
    run,
)
from signing import sign_app
from signing.metadata import default_metadata_path, load_metadata
from yubihsm_emulator import Connector

APP = "com.google.android.apps.photos"
ANDROID_TOP = REPO_ROOT.resolve().parents[1]

_FAKE_JAVA = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["FAKE_JAVA_LOG"], "w") as log:
    json.dump(sys.argv[1:], log)
out = sys.argv[sys.argv.index("--out") + 1]
open(out, "w").write("signed")
"""


@pytest.fixture
def sign_app_tree(tmp_path: Path) -> Path:
    root = tmp_path / "android"
    (root / "keys").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "logs" / "upload.py").write_text("#!/bin/sh\n")
    (root / "bin").mkdir()
    install_executable(root / "bin" / "java", _FAKE_JAVA)
    (root / "tmp").mkdir()
    (root / "app.apk").write_text("unsigned")
    return root


def _sign_app_environment(root: Path, yubihsm: Connector) -> dict[str, str]:
    return {
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
        "TMPDIR": str(root / "tmp"),
        "KEY_DIR": str(root / "keys"),
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "PKCS11_MODULE": "/dev/null",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "KEYMAP_FILE": str(ID2B_KEYMAP),
    }


def _run_sign_app(
    root: Path,
    yubihsm: Connector,
    *arguments: str,
    **environment: str,
) -> tuple[subprocess.CompletedProcess[str], list[str] | None]:
    java_log = root / "java.json"
    result = run(
        [SCRIPTS_DIR / "sign-app.sh", *arguments],
        cwd=root,
        env={
            **_sign_app_environment(root, yubihsm),
            "YUBIHSM_SIGNING_CACHE": "",
            "FAKE_JAVA_LOG": str(java_log),
            **environment,
        },
        check=False,
    )
    argv = json.loads(java_log.read_text()) if java_log.exists() else None
    return result, argv


def test_sign_app_signs_through_the_calyx_kms_provider(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    root = sign_app_tree
    (root / "keys" / "0x1502.x509.pem").write_text("certificate")

    result, argv = _run_sign_app(root, yubihsm, APP, "app.apk")

    assert result.returncode == 0, result.stderr
    assert argv == [
        "-jar",
        f"{ANDROID_TOP}/framework/apksigner.jar",
        "sign",
        "--v4-signing-enabled=false",
        "--min-sdk-version",
        "30",
        "--v1-signing-enabled=false",
        "--v2-signing-enabled=false",
        "--kms-type",
        "calyx",
        "--kms-key-alias",
        "0x1502",
        "--cert",
        f"{root}/keys/0x1502.x509.pem",
        "--out",
        "app-signed.apk",
        "app.apk",
    ]
    assert yubihsm.device.unread_log() == []
    (audit_log,) = (root / "logs" / "YubiHSM2-123456").glob(f"*-{APP}.log")
    assert "apksigner.jar sign" in audit_log.read_text()
    assert list((root / "tmp").glob("yubihsm.*")) == []


@pytest.mark.parametrize(
    ("arguments", "message", "usage_on_stderr"),
    (
        ((APP,), "incorrect number of arguments", False),
        (("--help",), "incorrect number of arguments", False),
        (
            (APP, "missing.apk"),
            "missing.apk is not an existing regular file",
            True,
        ),
        (("nope", "app.apk"), "Unsupported app nope", False),
    ),
    ids=("count", "help", "apk", "app"),
)
def test_sign_app_refuses_bad_arguments(
    sign_app_tree: Path,
    arguments: tuple[str, ...],
    message: str,
    usage_on_stderr: bool,
    yubihsm: Connector,
) -> None:
    result, argv = _run_sign_app(sign_app_tree, yubihsm, *arguments)

    usage = result.stderr if usage_on_stderr else result.stdout
    assert result.returncode == 1
    assert f"error: {message}" in result.stderr
    assert f"Usage: {SCRIPTS_DIR / 'sign-app.sh'} <app> file.apk" in usage
    assert "Supported apps: prebuilts/calyx/microg/certs/microg" in usage
    assert argv is None


def test_sign_app_kms_path_needs_the_certificate_file(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    result, argv = _run_sign_app(sign_app_tree, yubihsm, APP, "app.apk")

    assert result.returncode == 1
    assert "no certificate file found at" in result.stderr
    assert argv is None


def test_sign_app_reads_the_password_file(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    (sign_app_tree / "keys" / "0x1502.x509.pem").write_text("certificate")
    password_file = sign_app_tree / "signing.txt"
    password_file.write_text("password\n")
    password_file.chmod(0o600)

    result, _ = _run_sign_app(
        sign_app_tree,
        yubihsm,
        APP,
        "app.apk",
        YUBIHSM_PASSWORD="",
        YUBIHSM_PASSWORD_FILE=str(password_file),
    )

    assert result.returncode == 0, result.stderr
    assert "Using YUBIHSM_PASSWORD from YUBIHSM_PASSWORD_FILE." in result.stdout


def test_sign_app_exports_the_key_dir_it_defaults_to(
    sign_app_tree: Path,
    yubihsm: Connector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = sign_app_tree
    (root / "keys" / "0x1502.x509.pem").write_text("certificate")
    scripts = root / "vendor" / "calyx" / "scripts"
    scripts.mkdir(parents=True)
    monkeypatch.setattr(sign_app, "_SCRIPTS_DIR", scripts)
    monkeypatch.chdir(root)
    environment = {
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "TMPDIR": str(root / "tmp"),
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "PKCS11_MODULE": "/dev/null",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "KEYMAP_FILE": str(ID2B_KEYMAP),
    }
    seen: list[str | None] = []

    def run_release_tool(argv: list[str]) -> int:
        seen.append(environment.get("KEY_DIR"))
        return 0

    monkeypatch.setattr(sign_app, "run_release_tool", run_release_tool)

    code = sign_app.sign_app(
        environment,
        load_metadata(default_metadata_path()),
        [APP, "app.apk"],
    )

    assert code == 0
    assert seen == [f"{root}/keys/"]


def test_sign_app_reports_an_app_missing_from_the_keymap(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    keymap = sign_app_tree / "empty-keymap.tsv"
    keymap.write_text("ID\tDevice\tKey Type\tKey\n")

    result, argv = _run_sign_app(
        sign_app_tree,
        yubihsm,
        APP,
        "app.apk",
        KEYMAP_FILE=str(keymap),
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: " in result.stderr
    assert argv is None


def test_sign_app_reports_an_unreachable_yubihsm(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    result, argv = _run_sign_app(
        sign_app_tree,
        yubihsm,
        APP,
        "app.apk",
        YUBIHSM_CONNECTOR="http://127.0.0.1:9",
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: YubiHSM failure: " in result.stderr
    assert argv is None


def test_sign_app_names_the_signed_app_after_its_file_name(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    root = sign_app_tree
    (root / "keys" / "0x1502.x509.pem").write_text("certificate")
    (root / "build.d").mkdir()
    (root / "build.d" / "app").write_text("unsigned")

    result, argv = _run_sign_app(root, yubihsm, APP, "build.d/app")

    assert result.returncode == 0, result.stderr
    assert argv is not None
    assert argv[-3:] == ["--out", "build.d/app-signed.apk", "build.d/app"]


def test_sign_app_cleans_up_after_sigterm(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    root = sign_app_tree
    (root / "keys" / "0x1502.x509.pem").write_text("certificate")
    install_executable(
        root / "bin" / "java",
        f"#!{sys.executable}\n"
        "import os, signal\n"
        "os.killpg(os.getpgid(0), signal.SIGTERM)\n",
    )

    result = subprocess.run(
        [SCRIPTS_DIR / "sign-app.sh", APP, "app.apk"],
        cwd=root,
        env={**os.environ, **_sign_app_environment(root, yubihsm)},
        capture_output=True,
        text=True,
        timeout=60,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == 128 + signal.SIGTERM, result.stderr
    assert list((root / "tmp").iterdir()) == []


def test_sign_app_lets_the_signing_finish_after_sigterm(
    sign_app_tree: Path,
    yubihsm: Connector,
) -> None:
    root = sign_app_tree
    (root / "keys" / "0x1502.x509.pem").write_text("certificate")
    install_executable(
        root / "bin" / "java",
        f"#!{sys.executable}\n"
        "import os, signal, sys, time\n"
        "pid = os.getppid()\n"
        "while b'sign-app' not in open(f'/proc/{pid}/cmdline', 'rb').read():\n"
        "    stat = open(f'/proc/{pid}/stat').read()\n"
        "    pid = int(stat.rpartition(')')[2].split()[1])\n"
        "os.kill(pid, signal.SIGTERM)\n"
        "time.sleep(2)\n"
        "open(sys.argv[sys.argv.index('--out') + 1], 'w').write('signed')\n",
    )

    result = subprocess.run(
        [SCRIPTS_DIR / "sign-app.sh", APP, "app.apk"],
        cwd=root,
        env={**os.environ, **_sign_app_environment(root, yubihsm)},
        capture_output=True,
        text=True,
        timeout=60,
        start_new_session=True,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == 128 + signal.SIGTERM, result.stderr
    assert (root / "app-signed.apk").read_text() == "signed"
    logs = [path.read_text() for path in root.rglob("*.log")]
    assert any(" java " in log for log in logs), logs
    assert list((root / "tmp").iterdir()) == []
