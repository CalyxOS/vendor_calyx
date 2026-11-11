#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        ("  ID:         8192 (0x20:00)", "y"),
        ("  ID:         2000", "y"),
        ("  ID:         3000", "n"),
        ("  ID:         12288 (0x30:00)", "n"),
        ("", "n"),
    ],
)
def test_does_id_exist_matches_only_the_requested_id(
    tmp_path: Path,
    listing: str,
    expected: str,
) -> None:
    tool = tmp_path / "pkcs11-tool"
    tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$FAKE_LISTING\"\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1" || exit $?; pkcs11_tool_args=(); '
            "pkcs11_tool_args_no_pin=(); "
            "does_id_exist_for_type_yn_pkcs11 0x2000 pubkey",
            "pkcs11-include-test",
            SCRIPTS_DIR / "pkcs11" / "include.sh",
        ],
        env={
            "PATH": "/usr/bin:/bin",
            "PKCS11_TOOL_BIN": str(tool),
            "STRIP_HEX_KEY_ID_PREFIX": "y",
            "FAKE_LISTING": listing,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected
