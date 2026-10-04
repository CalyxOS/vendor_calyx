#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import pty
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR

SUBJECT = "/C=US/O=Calyx Institute/CN=Test app signing key"


def _run_updatecommonkeys(
    script: Path,
    key_dir: Path,
    *,
    keymapper: str = "legacy",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [script, key_dir, SUBJECT],
        env={**os.environ, "KEYMAPPER": keymapper},
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


@pytest.mark.parametrize(
    ("keymapper", "keys"),
    (
        (
            "legacy",
            (
                "chromium",
                "com.google.android.apps.photos",
                "microg",
                "org.calyxos.lupin.updater",
            ),
        ),
        ("id2b", ("0x1500", "0x1501", "0x1502", "0x1503")),
    ),
)
def test_updatecommonkeys_generates_the_app_keys(
    tmp_path: Path,
    keymapper: str,
    keys: tuple[str, ...],
) -> None:
    script = SCRIPTS_DIR / "updatecommonkeys.sh"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    result = _run_updatecommonkeys(script, key_dir, keymapper=keymapper)

    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in key_dir.iterdir()) == sorted(
        f"{key}{suffix}" for key in keys for suffix in (".pk8", ".x509.pem")
    )
    for private_key in key_dir.glob("*.pk8"):
        certificate = private_key.with_suffix(".x509.pem")
        assert _public_key(private_key, certificate=False) == (
            _public_key(certificate, certificate=True)
        )
    before = {path: path.read_bytes() for path in key_dir.iterdir()}
    rerun = _run_updatecommonkeys(script, key_dir, keymapper=keymapper)
    assert rerun.returncode == 0, rerun.stderr
    assert {path: path.read_bytes() for path in key_dir.iterdir()} == before


@pytest.mark.parametrize("missing", (".x509.pem", ".pk8"))
def test_updatecommonkeys_refuses_a_half_key(
    tmp_path: Path,
    missing: str,
) -> None:
    script = SCRIPTS_DIR / "updatecommonkeys.sh"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    assert _run_updatecommonkeys(script, key_dir).returncode == 0
    (key_dir / f"microg{missing}").unlink()

    refused = _run_updatecommonkeys(script, key_dir)

    assert refused.returncode != 0
    assert "Traceback" not in refused.stderr
    assert not (key_dir / f"microg{missing}").exists()


def test_updatecommonkeys_leaves_no_chromium_key_behind_on_failure(
    tmp_path: Path,
) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-keystore",
            key_dir / "calyxos.keystore",
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
    temporary = tmp_path / "tmp"
    temporary.mkdir()

    returncode, output = _run_in_terminal(
        [SCRIPTS_DIR / "updatecommonkeys.sh", key_dir, SUBJECT],
        {**os.environ, "KEYMAPPER": "legacy", "TMPDIR": str(temporary)},
        [
            ("Enter destination keystore password:", "secret2"),
            ("Re-enter new password:", "secret2"),
            ("Enter source keystore password:", "secret1"),
            ("Enter Import Password:", "wrong"),
        ],
    )

    assert returncode != 0, output
    assert sorted(path.name for path in key_dir.glob("calyxos.*")) == [
        "calyxos.keystore",
    ]
    assert not (key_dir / "chromium.pk8").exists()
    assert list(temporary.iterdir()) == []


def test_updatecommonkeys_converts_the_chromium_keystore(
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
    script = SCRIPTS_DIR / "updatecommonkeys.sh"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    shutil.copy2(keystore, key_dir / "calyxos.keystore")

    returncode, output = _run_in_terminal(
        [script, key_dir, SUBJECT],
        {**os.environ, "KEYMAPPER": "legacy"},
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
    exported = subprocess.run(
        [
            "keytool",
            "-exportcert",
            "-rfc",
            "-keystore",
            keystore,
            "-storepass",
            "secret1",
            "-alias",
            "chromium",
        ],
        capture_output=True,
        check=True,
    ).stdout
    certificate = key_dir / "chromium.x509.pem"
    keystore_certificate = tmp_path / "keystore.pem"
    keystore_certificate.write_bytes(exported)
    assert _public_key(certificate, certificate=True) == _public_key(
        keystore_certificate,
        certificate=True,
    )
    assert _public_key(key_dir / "chromium.pk8", certificate=False) == (
        _public_key(certificate, certificate=True)
    )
    certificates = [
        subprocess.run(
            ["openssl", "x509", "-in", path, "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout
        for path in (certificate, keystore_certificate)
    ]
    assert certificates[0] == certificates[1]
