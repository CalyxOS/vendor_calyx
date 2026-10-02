#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
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


def test_mkkey_generates_a_matching_key_and_certificate_through_python(
    tmp_path: Path,
) -> None:
    work = tmp_path / "keys"
    work.mkdir()
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
        env={
            "USE_PYTHON_SIGNING": "y",
            "MAKE_KEY_BIN": str(tmp_path / "missing-make_key"),
        },
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert {path.name for path in work.iterdir()} == {
        "releasekey.pk8",
        "releasekey.x509.pem",
    }

    certificate = work / "releasekey.x509.pem"
    pkcs8_key = work / "releasekey.pk8"
    private_key = run(
        [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            pkcs8_key,
            "-text",
            "-noout",
        ],
    )
    assert "Private-Key: (2048 bit" in private_key.stdout

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

    private_public_key = run(
        [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            pkcs8_key,
            "-pubout",
        ],
    )
    certificate_public_key = run(
        ["openssl", "x509", "-in", certificate, "-pubkey", "-noout"],
    )
    assert private_public_key.stdout == certificate_public_key.stdout


def test_python_mkkey_shows_why_openssl_refused_the_subject(
    tmp_path: Path,
) -> None:
    work = tmp_path / "keys"
    work.mkdir()

    result = run(
        [SCRIPTS_DIR / "mkkey.sh", "releasekey", "not-a-subject"],
        cwd=work,
        env={
            "USE_PYTHON_SIGNING": "y",
            "MAKE_KEY_BIN": str(tmp_path / "missing-make_key"),
        },
        check=False,
    )

    assert result.returncode == 1
    assert "/type0=value0" in result.stderr


@pytest.mark.parametrize("key_directory", ("absolute", "parent"))
def test_mkkey_generates_a_key_named_with_a_directory_through_python(
    tmp_path: Path,
    key_directory: str,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    keys = tmp_path / "keys" / "bramble"
    keys.mkdir(parents=True)
    key_name = (
        str(keys / "releasekey")
        if key_directory == "absolute"
        else "../keys/bramble/releasekey"
    )
    script = SCRIPTS_DIR / "mkkey.sh"

    generated = run(
        [script, key_name, SUBJECT],
        cwd=work,
        env={
            "USE_PYTHON_SIGNING": "y",
            "MAKE_KEY_BIN": str(tmp_path / "missing-make_key"),
        },
        check=False,
    )

    assert generated.returncode == 0, generated.stderr
    assert (keys / "releasekey.pk8").is_file()
    assert (keys / "releasekey.x509.pem").is_file()
    assert list(work.iterdir()) == []


@pytest.mark.parametrize(
    ("arguments", "existing"),
    (
        ((), ()),
        (("releasekey",), ()),
        (("releasekey", SUBJECT), ("releasekey.pk8", "releasekey.x509.pem")),
        (("releasekey", SUBJECT), ("releasekey.pem",)),
        (("releasekey", SUBJECT), ("releasekey.pk8",)),
    ),
    ids=("none", "one", "exists", "pem-exists", "no-certificate"),
)
def test_python_mkkey_refuses_as_bash_does(
    tmp_path: Path,
    arguments: tuple[str, ...],
    existing: tuple[str, ...],
) -> None:
    make_key = install_make_key(tmp_path)
    script = SCRIPTS_DIR / "mkkey.sh"
    results: list[tuple[int, str, str]] = []
    for flag in ("", "y"):
        work = tmp_path / f"keys{flag}"
        work.mkdir()
        for name in existing:
            (work / name).write_bytes(b"existing")
        result = run(
            [script, *arguments],
            cwd=work,
            env={
                "MAKE_KEY_BIN": str(make_key),
                "MAKE_KEY_CALLS": str(tmp_path / "calls"),
                "USE_PYTHON_SIGNING": flag,
            },
            check=False,
        )
        results.append((result.returncode, result.stdout, result.stderr))
        assert sorted(path.name for path in work.iterdir()) == sorted(existing)

    assert results[1] == results[0]
    assert results[0][0] == 1


def test_mkkey_flag_routes_through_python(tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-path-bin"
    fake_bin.mkdir()
    fake_python3 = fake_bin / "python3"
    fake_python3.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" mkkey "*)\n'
        "  echo FAKE_PYTHON3_INVOKED >&2\n"
        "  exit 1\n"
        "esac\n"
        f'exec {sys.executable} "$@"\n',
    )
    fake_python3.chmod(fake_python3.stat().st_mode | stat.S_IXUSR)
    script = SCRIPTS_DIR / "mkkey.sh"
    results = {
        flag: run(
            [script],
            cwd=tmp_path,
            env={
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "USE_PYTHON_SIGNING": flag,
            },
            check=False,
        )
        for flag in ("", "y")
    }

    assert "FAKE_PYTHON3_INVOKED" in results["y"].stderr
    assert "FAKE_PYTHON3_INVOKED" not in results[""].stderr
