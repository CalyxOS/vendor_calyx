#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, assert_certificate_of, run
from cryptography.hazmat.primitives import serialization

SUBJECT = "/C=US/O=Calyx Institute/CN=Test signing key"


def test_mkkey_generates_a_matching_key_and_certificate(
    tmp_path: Path,
) -> None:
    work = tmp_path / "keys"
    work.mkdir()
    script = SCRIPTS_DIR / "mkkey.sh"

    result = run(
        [script, "releasekey", SUBJECT],
        cwd=work,
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
    assert_certificate_of(
        serialization.load_der_private_key(
            pkcs8_key.read_bytes(),
            None,
        ).public_key(),
        certificate,
        "CN=Test signing key,O=Calyx Institute,C=US",
    )


def test_mkkey_shows_why_openssl_refused_the_subject(tmp_path: Path) -> None:
    work = tmp_path / "keys"
    work.mkdir()

    result = run(
        [SCRIPTS_DIR / "mkkey.sh", "releasekey", "not-a-subject"],
        cwd=work,
        check=False,
    )

    assert result.returncode == 1
    assert "/type0=value0" in result.stderr


@pytest.mark.parametrize("key_directory", ("absolute", "parent"))
def test_mkkey_generates_a_key_named_with_a_directory(
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
        check=False,
    )

    assert generated.returncode == 0, generated.stderr
    assert (keys / "releasekey.pk8").is_file()
    assert (keys / "releasekey.x509.pem").is_file()
    assert list(work.iterdir()) == []


def _usage(script: Path) -> str:
    return (
        f"Usage: {script} key_name subject\n"
        "Example key_name: networkstack\n"
        "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/"
        "OU=Android/CN=Android/emailAddress=android@android.com'\n"
    )


@pytest.mark.parametrize(
    ("arguments", "existing", "error", "usage"),
    (
        (
            ("releasekey",),
            (),
            "error: incorrect number of arguments, please try again\n",
            True,
        ),
        (
            ("releasekey", SUBJECT),
            ("releasekey.pk8", "releasekey.x509.pem"),
            "error: key releasekey already exists, please try again\n",
            True,
        ),
        (
            ("releasekey", SUBJECT),
            ("releasekey.pem",),
            "error: key releasekey already exists, please try again\n",
            True,
        ),
        (
            ("releasekey", SUBJECT),
            ("releasekey.pk8",),
            "error: key releasekey exists without releasekey.x509.pem.\n"
            "Restore the certificate from a backup, or delete releasekey.pk8 "
            "if the key was never used.\n",
            False,
        ),
    ),
    ids=("one", "exists", "pem-exists", "no-certificate"),
)
def test_mkkey_refuses_without_touching_the_keys(
    tmp_path: Path,
    arguments: tuple[str, ...],
    existing: tuple[str, ...],
    error: str,
    usage: bool,
) -> None:
    script = SCRIPTS_DIR / "mkkey.sh"
    work = tmp_path / "keys"
    work.mkdir()
    for name in existing:
        (work / name).write_bytes(b"existing")

    result = run([script, *arguments], cwd=work, check=False)

    assert (result.returncode, result.stdout, result.stderr) == (
        1,
        _usage(script) if usage else "",
        error,
    )
    assert sorted(path.name for path in work.iterdir()) == sorted(existing)
    assert all((work / name).read_bytes() == b"existing" for name in existing)
