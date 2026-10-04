#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

SUBJECT = "/C=US/O=Calyx Institute/CN=key script test"
FLAGS = {
    "updatecommonkeys": "USE_PYTHON_UPDATECOMMONKEYS",
    "mkcommonkeys": "USE_PYTHON_UPDATECOMMONKEYS",
}


def _run(
    script: str,
    arguments: tuple[str, ...],
    cwd: Path,
    flag: str,
) -> subprocess.CompletedProcess[str]:
    return run(
        [SCRIPTS_DIR / f"{script}.sh", *arguments],
        cwd=cwd,
        env={FLAGS[script]: flag, "KEYMAPPER": "legacy"},
        check=False,
    )


def _outcomes(
    tmp_path: Path,
    script: str,
    arguments: tuple[str, ...],
    prepare: Callable[[Path], object] | None = None,
) -> list[tuple[int, str, str, list[str]]]:
    outcomes: list[tuple[int, str, str, list[str]]] = []
    for flag in ("", "y"):
        work = tmp_path / f"work{flag}"
        work.mkdir()
        if prepare is not None:
            prepare(work)
        result = _run(script, arguments, work, flag)
        outcomes.append(
            (
                result.returncode,
                result.stdout,
                result.stderr,
                sorted(str(path.relative_to(work)) for path in work.rglob("*")),
            ),
        )
    return outcomes


@pytest.mark.parametrize("script", ("updatecommonkeys",))
@pytest.mark.parametrize(
    "arguments",
    ((), ("keys/bramble",), ("a", "b", "c")),
    ids=("0", "1", "3"),
)
def test_python_key_scripts_check_arguments_as_bash_does(
    tmp_path: Path,
    script: str,
    arguments: tuple[str, ...],
) -> None:
    bash, python = _outcomes(tmp_path, script, arguments)

    assert python == bash
    assert bash[0] == 1
    assert "incorrect number of arguments" in bash[2]


@pytest.mark.parametrize("script", ("updatecommonkeys",))
def test_python_key_scripts_refuse_a_missing_directory_as_bash_does(
    tmp_path: Path,
    script: str,
) -> None:
    bash, python = _outcomes(tmp_path, script, ("keys/bramble", SUBJECT))

    assert python == bash
    assert bash[0] == 1


@pytest.mark.parametrize("script", ("mkcommonkeys",))
def test_python_mkkeys_refuses_an_existing_directory_as_bash_does(
    tmp_path: Path,
    script: str,
) -> None:
    bash, python = _outcomes(
        tmp_path,
        script,
        ("keys/bramble", SUBJECT),
        prepare=lambda work: (work / "keys" / "bramble").mkdir(parents=True),
    )

    assert python == bash
    assert bash[:3] == (1, "", "key directory already exists\n")


@pytest.mark.parametrize("script", ("mkcommonkeys",))
def test_python_mkkeys_reports_a_directory_it_cannot_create(
    tmp_path: Path,
    script: str,
) -> None:
    bash, python = _outcomes(
        tmp_path,
        script,
        ("keys/bramble", SUBJECT),
        prepare=lambda work: (work / "keys").write_text(""),
    )

    assert bash[0] == python[0] == 1
    assert "Traceback" not in python[2]


@pytest.mark.parametrize("script", ("mkcommonkeys",))
def test_python_mkkeys_creates_the_directory_as_bash_does(
    tmp_path: Path,
    script: str,
) -> None:
    bash, python = _outcomes(tmp_path, script, ("keys/bramble",))

    assert python == bash
    assert bash[0] == 1
    assert bash[3] == ["keys", "keys/bramble"]
    assert "incorrect number of arguments" in bash[2]


@pytest.mark.parametrize("script", FLAGS)
def test_key_script_flags_route_through_python(
    tmp_path: Path,
    script: str,
) -> None:
    command = script.replace("mk", "update")
    fake_bin = tmp_path / "fake-path-bin"
    fake_bin.mkdir()
    fake_python3 = fake_bin / "python3"
    fake_python3.write_text(
        "#!/bin/sh\n"
        f'case " $* " in *" {command} "*)\n'
        "  echo FAKE_PYTHON3_INVOKED >&2\n"
        "  exit 1\n"
        "esac\n"
        f'exec {sys.executable} "$@"\n',
    )
    fake_python3.chmod(fake_python3.stat().st_mode | stat.S_IXUSR)
    results = {
        flag: run(
            [SCRIPTS_DIR / f"{script}.sh", f"keys{flag}/bramble"],
            cwd=tmp_path,
            env={
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                FLAGS[script]: flag,
            },
            check=False,
        )
        for flag in ("", "y")
    }

    assert "FAKE_PYTHON3_INVOKED" in results["y"].stderr
    assert "FAKE_PYTHON3_INVOKED" not in results[""].stderr
    shutil.rmtree(tmp_path / "keys", ignore_errors=True)


def test_python_updatecommonkeys_reports_an_empty_subject(
    tmp_path: Path,
) -> None:
    (tmp_path / "keys").mkdir()

    result = run(
        [SCRIPTS_DIR / "updatecommonkeys.sh", "keys", ""],
        cwd=tmp_path,
        env={"USE_PYTHON_UPDATECOMMONKEYS": "y", "KEYMAPPER": "legacy"},
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "subject" in result.stderr
