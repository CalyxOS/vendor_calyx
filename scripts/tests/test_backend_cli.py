#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from conftest import run_cli


def test_cli_does_not_accept_raw_pin_argument(tmp_path: Path) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "provider.so",
            "--pin",
            "command-line-secret",
            "--key-id",
            "0x2000",
            "--label",
            "releasekey",
        ],
        check=False,
    )

    assert result.returncode == 2
    assert "raw PINs are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr


def test_cli_reports_an_invalid_key_id_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        ["key-exists", "--module", tmp_path / "provider.so"],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: invalid PKCS#11 key ID" in result.stderr


def test_cli_reports_an_unset_pin_variable_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "provider.so",
            "--pin-env",
            "SIGNING_TEST_UNSET_PIN",
            "--key-id",
            "0x2000",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: PIN environment variable is not set" in result.stderr


@pytest.mark.skipif(
    shutil.which("pkcs11-tool") is None,
    reason="needs pkcs11-tool",
)
def test_cli_reports_a_failing_tool_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "missing.so",
            "--key-id",
            "0x2000",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert result.stderr
