#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from signing.configuration import EnvironmentPin, FilePin


def test_environment_pin_rejects_missing_and_empty_values() -> None:
    source = EnvironmentPin("MISSING_PIN")

    with pytest.raises(KeyError):
        source.resolve({})
    with pytest.raises(ValueError, match="is empty"):
        source.resolve({"MISSING_PIN": ""})


def test_file_pin_reads_private_single_line_file(tmp_path: Path) -> None:
    pin_file = tmp_path / "token.pin"
    pin_file.write_text("file-secret-pin\n")
    pin_file.chmod(0o600)

    assert FilePin(pin_file).resolve() == "file-secret-pin"


def test_file_pin_rejects_permissive_or_multiline_files(tmp_path: Path) -> None:
    pin_file = tmp_path / "token.pin"
    pin_file.write_text("secret\n")
    pin_file.chmod(0o640)
    with pytest.raises(PermissionError, match="group or other permissions"):
        FilePin(pin_file).resolve()

    pin_file.write_text("first\n\n")
    pin_file.chmod(0o600)
    with pytest.raises(ValueError, match="exactly one line"):
        FilePin(pin_file).resolve()
