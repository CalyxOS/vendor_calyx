#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

SUBJECT = "/C=US/O=Calyx Institute/CN=key script test"
EXAMPLE_SUBJECT = (
    "Example subject: '/C=US/ST=California/L=Mountain View/O=Android/"
    "OU=Android/CN=Android/emailAddress=android@android.com'\n"
)


def _usage(script: str) -> str:
    return (
        f"Usage: {SCRIPTS_DIR}/{script}.sh key_dir subject\n" + EXAMPLE_SUBJECT
    )


def _outcome(
    tmp_path: Path,
    script: str,
    arguments: tuple[str, ...],
    prepare: Callable[[Path], object] | None = None,
) -> tuple[int, str, str, list[str]]:
    work = tmp_path / "work"
    work.mkdir()
    if prepare is not None:
        prepare(work)
    result = run(
        [SCRIPTS_DIR / f"{script}.sh", *arguments],
        cwd=work,
        env={"KEYMAPPER": "legacy"},
        check=False,
    )
    return (
        result.returncode,
        result.stdout,
        result.stderr,
        sorted(str(path.relative_to(work)) for path in work.rglob("*")),
    )


@pytest.mark.parametrize("script", ("updatekeys", "updatecommonkeys"))
def test_key_scripts_check_their_arguments(
    tmp_path: Path,
    script: str,
) -> None:
    assert _outcome(tmp_path, script, ("keys/bramble",)) == (
        1,
        _usage(script),
        "error: incorrect number of arguments, please try again\n",
        [],
    )


@pytest.mark.parametrize(
    ("script", "error"),
    (
        (
            "updatekeys",
            f"{SCRIPTS_DIR}/../../../bin/generate_verity_key not found.",
        ),
        ("updatecommonkeys", "key directory does not exist"),
    ),
)
def test_key_scripts_check_their_setup(
    tmp_path: Path,
    script: str,
    error: str,
) -> None:
    assert _outcome(tmp_path, script, ("keys/bramble", SUBJECT)) == (
        1,
        _usage(script),
        f"Using keymapper: legacy\nerror: {error}, please try again\n",
        [],
    )


def test_mkkeys_refuses_a_directory_the_keymapper_does_not_use(
    tmp_path: Path,
) -> None:
    code, _, stderr, created = _outcome(
        tmp_path,
        "mkkeys",
        ("elsewhere/bramble", SUBJECT),
    )

    assert code == 1
    assert (
        "error: the legacy keymapper keeps the keys of bramble in "
        "keys/bramble, not elsewhere/bramble" in stderr
    )
    assert created == []


def test_mkkeys_names_the_keymapper_file_that_refuses_a_directory(
    tmp_path: Path,
) -> None:
    keymapper_file = tmp_path / "keymapper.py"
    keymapper_file.write_text(
        "from signing.keymap import LegacyKeymapper\n"
        "\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        "    return LegacyKeymapper(metadata)\n",
    )
    work = tmp_path / "work"
    work.mkdir()

    result = run(
        [SCRIPTS_DIR / "mkkeys.sh", "elsewhere/bramble", SUBJECT],
        cwd=work,
        env={"KEYMAPPER_FILE": str(keymapper_file)},
        check=False,
    )

    assert result.returncode == 1
    assert (
        f"error: the keymapper from {keymapper_file} keeps the keys of "
        "bramble in keys/bramble" in result.stderr
    )


@pytest.mark.parametrize("script", ("mkkeys", "mkcommonkeys"))
def test_mkkeys_refuses_an_existing_directory(
    tmp_path: Path,
    script: str,
) -> None:
    assert _outcome(
        tmp_path,
        script,
        ("keys/bramble", SUBJECT),
        prepare=lambda work: (work / "keys" / "bramble").mkdir(parents=True),
    ) == (
        1,
        "",
        ("Using keymapper: legacy\n" if script == "mkkeys" else "")
        + "key directory already exists\n",
        ["keys", "keys/bramble"],
    )


@pytest.mark.parametrize("script", ("mkkeys", "mkcommonkeys"))
def test_mkkeys_reports_a_directory_it_cannot_create(
    tmp_path: Path,
    script: str,
) -> None:
    code, _, stderr, _ = _outcome(
        tmp_path,
        script,
        ("keys/bramble", SUBJECT),
        prepare=lambda work: (work / "keys").write_text(""),
    )

    assert code == 1
    assert "Traceback" not in stderr


@pytest.mark.parametrize("script", ("mkkeys", "mkcommonkeys"))
def test_mkkeys_creates_the_directory(tmp_path: Path, script: str) -> None:
    assert _outcome(tmp_path, script, ("keys/bramble",)) == (
        1,
        _usage(script.replace("mk", "update")),
        "error: incorrect number of arguments, please try again\n",
        ["keys", "keys/bramble"],
    )


def test_updatecommonkeys_reports_an_empty_subject(
    tmp_path: Path,
) -> None:
    (tmp_path / "keys").mkdir()

    result = run(
        [SCRIPTS_DIR / "updatecommonkeys.sh", "keys", ""],
        cwd=tmp_path,
        env={"KEYMAPPER": "legacy"},
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "subject" in result.stderr
