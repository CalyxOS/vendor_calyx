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


def test_metadata_refuses_a_module_without_an_array(
    tmp_path: Path,
) -> None:
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    module = tmp_path / "metadata.py"
    module.write_text(source.replace("ALL_DEVICES = (", "OTHER_DEVICES = ("))

    with pytest.raises(ValueError, match="defines no ALL_DEVICES"):
        load_metadata(module)


def test_metadata_refuses_an_array_that_is_not_a_tuple(
    tmp_path: Path,
) -> None:
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    module = tmp_path / "metadata.py"
    module.write_text(
        source.replace('KEYS_REPO = ("updater",)', 'KEYS_REPO = ("updater")'),
    )

    with pytest.raises(ValueError, match="KEYS_REPO .* not a tuple of strings"):
        load_metadata(module)


@pytest.mark.parametrize(
    "entry",
    ('"avb": ("keys_avb",),', '1: "keys_avb",'),
    ids=("tuple-value", "int-key"),
)
def test_metadata_refuses_a_key_type_map_of_other_values(
    tmp_path: Path,
    entry: str,
) -> None:
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    module = tmp_path / "metadata.py"
    module.write_text(source.replace('"avb": "keys_avb",', entry))

    with pytest.raises(ValueError, match="does not map strings to strings"):
        load_metadata(module)


def test_metadata_refuses_a_mapping_to_another_array(tmp_path: Path) -> None:
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    module = tmp_path / "metadata.py"
    module.write_text(
        source.replace('"repo": "keys_repo",', '"repo": "keys_extra",')
        + '\nKEYS_EXTRA = ("updater",)\n',
    )

    with pytest.raises(ValueError, match="maps repo to keys_extra"):
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
