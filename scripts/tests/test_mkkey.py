#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
from pathlib import Path

from conftest import SCRIPTS_DIR, run

SUBJECT = "/C=US/O=Calyx Institute/CN=Test signing key"


def install_make_key(directory: Path) -> Path:
    make_key = directory / "make_key"
    make_key.write_text(
        """#!/bin/bash
set -euo pipefail
printf '%s\\n' "$@" >> "${MAKE_KEY_CALLS:?}"
touch "$1.pk8" "$1.pem" "$1.x509.pem"
""",
    )
    make_key.chmod(make_key.stat().st_mode | stat.S_IXUSR)
    return make_key


def install_cryptographic_make_key(directory: Path) -> Path:
    """
    Install a hermetic equivalent of AOSP make_key for integration testing.
    """
    make_key = directory / "make_key"
    make_key.write_text(
        """#!/bin/bash
set -euo pipefail
openssl genrsa -out "$1.pem" 2048
openssl req -new -x509 -key "$1.pem" -out "$1.x509.pem" -subj "$2" -days 1
openssl pkcs8 -in "$1.pem" -topk8 -outform DER -out "$1.pk8" -nocrypt
""",
    )
    make_key.chmod(make_key.stat().st_mode | stat.S_IXUSR)
    return make_key


def test_mkkey_delegates_to_aosp_make_key(
    tmp_path: Path,
) -> None:
    make_key = install_make_key(tmp_path)
    calls = tmp_path / "make-key.calls"
    work = tmp_path / "keys"
    work.mkdir()
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
        env={"MAKE_KEY_BIN": str(make_key), "MAKE_KEY_CALLS": str(calls)},
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert calls.read_text().splitlines() == ["releasekey", SUBJECT]
    assert {path.name for path in work.iterdir()} == {
        "releasekey.pk8",
        "releasekey.pem",
        "releasekey.x509.pem",
    }


def test_mkkey_refuses_to_overwrite_existing_key(
    tmp_path: Path,
) -> None:
    make_key = install_make_key(tmp_path)
    calls = tmp_path / "make-key.calls"
    work = tmp_path / "keys"
    work.mkdir()
    (work / "releasekey.pk8").touch()
    (work / "releasekey.x509.pem").touch()
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
        env={"MAKE_KEY_BIN": str(make_key), "MAKE_KEY_CALLS": str(calls)},
        check=False,
    )

    assert result.returncode != 0
    assert "key releasekey already exists" in result.stderr
    assert not calls.exists()


def test_mkkey_refuses_a_key_without_its_certificate(
    tmp_path: Path,
) -> None:
    make_key = install_make_key(tmp_path)
    calls = tmp_path / "make-key.calls"
    work = tmp_path / "keys"
    work.mkdir()
    (work / "releasekey.pk8").write_bytes(b"private key")
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
        env={"MAKE_KEY_BIN": str(make_key), "MAKE_KEY_CALLS": str(calls)},
        check=False,
    )

    assert result.returncode != 0
    assert "exists without releasekey.x509.pem" in result.stderr
    assert (work / "releasekey.pk8").read_bytes() == b"private key"
    assert not (work / "releasekey.x509.pem").exists()
    assert not calls.exists()


def test_mkkey_requires_name_and_subject(
    tmp_path: Path,
) -> None:
    make_key = install_make_key(tmp_path)
    script = SCRIPTS_DIR / "mkkey.sh"
    result = run(
        [script],
        cwd=tmp_path,
        env={"MAKE_KEY_BIN": str(make_key)},
        check=False,
    )

    assert result.returncode != 0
    assert "incorrect number of arguments" in result.stderr
    assert "Usage:" in result.stdout


def test_mkkey_generates_matching_key_material(
    tmp_path: Path,
) -> None:
    make_key = install_cryptographic_make_key(tmp_path)
    work = tmp_path / "keys"
    work.mkdir()
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
        env={"MAKE_KEY_BIN": str(make_key)},
        check=False,
    )
    assert result.returncode == 0, result.stderr

    private_key = work / "releasekey.pem"
    certificate = work / "releasekey.x509.pem"
    pkcs8_key = work / "releasekey.pk8"
    run(["openssl", "pkey", "-in", private_key, "-check", "-noout"])
    run(
        [
            "openssl",
            "pkcs8",
            "-inform",
            "DER",
            "-in",
            pkcs8_key,
            "-nocrypt",
            "-out",
            "/dev/null",
        ],
    )

    subject = run(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
    )
    assert (
        subject.stdout.strip()
        == "subject=CN=Test signing key,O=Calyx Institute,C=US"
    )

    private_public_key = run(["openssl", "pkey", "-in", private_key, "-pubout"])
    certificate_public_key = run(
        ["openssl", "x509", "-in", certificate, "-pubkey", "-noout"],
    )
    assert private_public_key.stdout == certificate_public_key.stdout
