#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from signing.metadata import BASE_ARRAYS, load_metadata


def test_metadata_arrays_are_populated() -> None:
    metadata = load_metadata(SCRIPTS_DIR / "metadata.py")

    for name in BASE_ARRAYS:
        assert any(metadata.arrays[name]), f"{name} must not be empty"


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        ("ALL_DEVICES = (", "OTHER_DEVICES = (", "defines no ALL_DEVICES"),
        (
            'KEYS_REPO = ("updater",)',
            'KEYS_REPO = ("updater")',
            "KEYS_REPO .* not a tuple of strings",
        ),
        (
            '"avb": "keys_avb",',
            '"avb": ("keys_avb",),',
            "does not map strings to strings",
        ),
        (
            '"avb": "keys_avb",',
            '1: "keys_avb",',
            "does not map strings to strings",
        ),
        (
            '"repo": "keys_repo",\n}',
            '"repo": "keys_extra",\n}\nKEYS_EXTRA = ("updater",)',
            "maps repo to keys_extra",
        ),
    ),
    ids=(
        "missing-array",
        "not-a-tuple",
        "tuple-value",
        "int-key",
        "another-array",
    ),
)
def test_metadata_refuses_a_malformed_module(
    tmp_path: Path,
    old: str,
    new: str,
    message: str,
) -> None:
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    assert old in source
    module = tmp_path / "metadata.py"
    module.write_text(source.replace(old, new))

    with pytest.raises(ValueError, match=message):
        load_metadata(module)


def test_metadata_reports_a_module_that_does_not_load(tmp_path: Path) -> None:
    module = tmp_path / "metadata.py"
    module.write_text("KEYS_AVB = (\n")

    with pytest.raises(ValueError, match="cannot load metadata module"):
        load_metadata(module)

    result = run(
        [
            sys.executable,
            "-m",
            "signing",
            "updatekeys",
            "updatekeys.sh",
            "keys/bramble",
            "/CN=test",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(SCRIPTS_DIR), "METADATA_FILE": str(module)},
        check=False,
    )
    assert result.returncode == 1
    assert "cannot load metadata module" in result.stderr
    assert "Traceback" not in result.stderr


METADATA_TEMPLATE = """KEYS_AVB = ("vbmeta",)
KEYS_OTHER = ()
KEYS_CORE = ()
KEYS_APEX = ()
KEYS_APEX_APK = ()
KEYS_APP = ()
KEYS_REPO = ()
KEY_TYPES = ("avb",)
MAPPED_KEY_TYPES = ()
ALL_DEVICES = {devices}
KEY_TYPE_TO_ARRAY = {{"avb": "keys_avb"}}
"""


def test_metadata_rejects_duplicate_entries(
    tmp_path: Path,
) -> None:
    metadata_file = tmp_path / "metadata.py"
    metadata_file.write_text(
        METADATA_TEMPLATE.format(devices=("test-device", "test-device")),
    )

    with pytest.raises(
        ValueError,
        match="duplicate entries in metadata array all_devices",
    ):
        load_metadata(metadata_file)


def test_metadata_preserves_empty_arrays(tmp_path: Path) -> None:
    metadata_file = tmp_path / "metadata.py"
    metadata_file.write_text(METADATA_TEMPLATE.format(devices=("test-device",)))
    metadata = load_metadata(metadata_file)
    assert metadata.arrays["keys_other"] == ()
    assert metadata.arrays["keys_core"] == ()


def test_metadata_loads_a_module_without_a_py_suffix(tmp_path: Path) -> None:
    module = tmp_path / "metadata"
    module.write_text((SCRIPTS_DIR / "metadata.py").read_text())

    assert load_metadata(module) == load_metadata(SCRIPTS_DIR / "metadata.py")
