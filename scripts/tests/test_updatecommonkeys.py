#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import pty
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

SUBJECT = "/C=US/O=Calyx Institute/CN=Test app signing key"


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


METADATA = """KEYS_AVB = ()
KEYS_OTHER = ()
KEYS_CORE = ()
KEYS_APEX = ()
KEYS_APEX_APK = ()
KEYS_APP = ("testapp",)
KEYS_REPO = ()
KEY_TYPES = ("app",)
MAPPED_KEY_TYPES = ("app",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {"app": "keys_app"}
"""


@pytest.fixture
def updatecommonkeys_environment(tmp_path: Path) -> dict[str, str]:
    """
    Run updatecommonkeys.sh in place against metadata with a single app
    key and a make_key stand-in, since this only needs one app key to
    exercise the recovery loop.
    """
    metadata = tmp_path / "metadata.py"
    metadata.write_text(METADATA)
    make_key = tmp_path / "make_key"
    _write_executable(
        make_key,
        """#!/bin/bash
set -euo pipefail
mkdir -p "$(dirname "$1")"
printf 'PRIVATE KEY\n' > "$1.pk8"
chmod 0600 "$1.pk8"
printf 'CERTIFICATE subject=%s\n' "$2" > "$1.x509.pem"
""",
    )
    return {
        "METADATA_FILE": str(metadata),
        "MAKE_KEY_BIN": str(make_key),
        "KEYMAPPER": "legacy",
    }


def test_updatecommonkeys_generates_app_key(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    script = SCRIPTS_DIR / "updatecommonkeys.sh"

    result = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (key_dir / "testapp.pk8").exists()
    assert (key_dir / "testapp.x509.pem").exists()


def test_updatecommonkeys_refuses_a_key_without_its_certificate(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    """
    A private key without its certificate must stop the run instead of
    getting a new certificate, which would be a different signer.
    """
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    script = SCRIPTS_DIR / "updatecommonkeys.sh"

    generated = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    (key_dir / "testapp.x509.pem").unlink()

    refused = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert refused.returncode != 0
    assert "exists without testapp.x509.pem" in refused.stderr
    assert not (key_dir / "testapp.x509.pem").exists()


def _run_updatecommonkeys(
    script: Path,
    key_dir: Path,
    *,
    python: bool,
    keymapper: str = "legacy",
) -> subprocess.CompletedProcess[str]:
    flag = "USE_PYTHON_UPDATECOMMONKEYS" if python else "USE_PYTHON_SIGNING"
    return subprocess.run(
        [script, key_dir, SUBJECT],
        env={
            **os.environ,
            flag: "y",
            "KEYMAPPER": keymapper,
            "MAKE_KEY_BIN": str(key_dir.parent / "missing-make_key"),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
    )


def _run_in_terminal(
    argv: list[str | Path],
    environment: dict[str, str],
    answers: list[tuple[str, str]],
) -> tuple[int, str]:
    """
    Run argv on a pseudo-terminal, answering each prompt as it appears,
    since keytool reads all of standard input at once.
    """
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(str(argv[0]), [str(arg) for arg in argv], environment)
    output = b""
    searched = 0
    pending = list(answers)
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
        while pending:
            position = output.find(pending[0][0].encode(), searched)
            if position < 0:
                break
            searched = position + len(pending[0][0])
            os.write(fd, pending.pop(0)[1].encode() + b"\n")
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


def _public_key(path: Path, *, certificate: bool) -> bytes:
    argv: list[str | Path]
    if certificate:
        argv = ["openssl", "x509", "-in", path, "-noout", "-pubkey"]
    else:
        argv = ["openssl", "pkey", "-inform", "DER", "-in", path, "-pubout"]
    return subprocess.run(argv, capture_output=True, check=True).stdout


@pytest.mark.parametrize("keymapper", ("legacy", "id2b"))
def test_python_updatecommonkeys_matches_bash(
    tmp_path: Path,
    keymapper: str,
) -> None:
    layouts = {}
    for label, python in (("bash", False), ("python", True)):
        script = SCRIPTS_DIR / "updatecommonkeys.sh"
        key_dir = tmp_path / f"{label}-keys"
        key_dir.mkdir()
        result = _run_updatecommonkeys(
            script,
            key_dir,
            python=python,
            keymapper=keymapper,
        )
        assert result.returncode == 0, result.stderr
        layouts[label] = sorted(path.name for path in key_dir.iterdir())
        for private_key in key_dir.glob("*.pk8"):
            certificate = private_key.with_suffix(".x509.pem")
            assert _public_key(private_key, certificate=False) == (
                _public_key(certificate, certificate=True)
            )
        before = {path: path.read_bytes() for path in key_dir.iterdir()}
        rerun = _run_updatecommonkeys(
            script,
            key_dir,
            python=python,
            keymapper=keymapper,
        )
        assert rerun.returncode == 0, rerun.stderr
        assert {path: path.read_bytes() for path in key_dir.iterdir()} == before

    assert layouts["python"] == layouts["bash"]
    assert layouts["bash"]


@pytest.mark.parametrize("missing", (".x509.pem", ".pk8"))
def test_python_updatecommonkeys_refuses_a_half_key_like_bash(
    tmp_path: Path,
    missing: str,
) -> None:
    for label, python in (("bash", False), ("python", True)):
        script = SCRIPTS_DIR / "updatecommonkeys.sh"
        key_dir = tmp_path / f"{label}-keys"
        key_dir.mkdir()
        assert (
            _run_updatecommonkeys(script, key_dir, python=python).returncode
            == 0
        )
        (key_dir / f"microg{missing}").unlink()

        refused = _run_updatecommonkeys(script, key_dir, python=python)

        assert refused.returncode != 0, label
        assert "Traceback" not in refused.stderr, label
        assert not (key_dir / f"microg{missing}").exists(), label


def test_python_updatecommonkeys_converts_the_chromium_keystore_like_bash(
    tmp_path: Path,
) -> None:
    keystore = tmp_path / "calyxos.keystore"
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-keystore",
            keystore,
            "-storetype",
            "jks",
            "-storepass",
            "secret1",
            "-keypass",
            "secret1",
            "-alias",
            "chromium",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-dname",
            "CN=chromium",
            "-validity",
            "3650",
        ],
        capture_output=True,
        check=True,
    )
    outputs = {}
    for label, python in (("bash", False), ("python", True)):
        script = SCRIPTS_DIR / "updatecommonkeys.sh"
        key_dir = tmp_path / f"{label}-keys"
        key_dir.mkdir()
        shutil.copy2(keystore, key_dir / "calyxos.keystore")

        flag = "USE_PYTHON_UPDATECOMMONKEYS" if python else "USE_PYTHON_SIGNING"
        returncode, output = _run_in_terminal(
            [script, key_dir, SUBJECT],
            {
                **os.environ,
                flag: "y",
                "KEYMAPPER": "legacy",
                "MAKE_KEY_BIN": str(tmp_path / "missing-make_key"),
            },
            [
                ("Enter destination keystore password:", "secret2"),
                ("Re-enter new password:", "secret2"),
                ("Enter source keystore password:", "secret1"),
                ("Enter Import Password:", "secret2"),
            ],
        )

        assert returncode == 0, output
        assert not (key_dir / "calyxos.p12").exists()
        assert not (key_dir / "calyxos.pem").exists()
        outputs[label] = (
            (key_dir / "chromium.pk8").read_bytes(),
            (key_dir / "chromium.x509.pem").read_bytes(),
        )

    assert outputs["python"] == outputs["bash"]


def test_updatecommonkeys_skips_a_metadata_placeholder(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    metadata = Path(updatecommonkeys_environment["METADATA_FILE"])
    metadata.write_text(
        METADATA.replace(
            'KEYS_APP = ("testapp",)',
            'KEYS_APP = ("testapp", "", "otherapp")',
        ),
    )
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    result = run(
        [SCRIPTS_DIR / "updatecommonkeys.sh", key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    for name in ("testapp", "otherapp"):
        assert (key_dir / f"{name}.pk8").exists()
        assert (key_dir / f"{name}.x509.pem").exists()
    assert not [path for path in key_dir.rglob(".*")]
