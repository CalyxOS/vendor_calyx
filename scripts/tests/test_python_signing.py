#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_cli
from signing.keymap import Id2bKeymapper
from signing.metadata import SigningMetadata, load_metadata

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


@pytest.fixture(scope="module")
def signing_metadata() -> SigningMetadata:
    return load_metadata(SCRIPTS_DIR / "metadata.py")


def test_python_id2b_matches_bash_for_every_device(
    signing_metadata: SigningMetadata,
    tmp_path: Path,
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(
        f"devices=({' '.join(signing_metadata.all_devices)})\n",
    )
    bash = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={"DEVICES_FILE": str(devices_file), "KEYMAPPER": "id2b"},
    )
    python = Id2bKeymapper(signing_metadata).to_tsv(
        signing_metadata.all_devices,
    )
    assert python == bash.stdout


def test_python_keymap_cli_rejects_duplicate_metadata_entries(
    tmp_path: Path,
) -> None:
    metadata_file = tmp_path / "metadata.py"
    metadata_file.write_text(
        METADATA_TEMPLATE.format(devices=("test-device", "test-device")),
    )

    result = run_cli(
        [
            "generate-keymap",
            "--metadata",
            metadata_file,
            "--devices",
            "test-device",
        ],
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "duplicate entries in metadata array all_devices" in result.stderr


def test_metadata_preserves_empty_arrays(tmp_path: Path) -> None:
    metadata_file = tmp_path / "metadata.py"
    metadata_file.write_text(METADATA_TEMPLATE.format(devices=("test-device",)))
    metadata = load_metadata(metadata_file)
    assert metadata.arrays["keys_other"] == ()
    assert metadata.arrays["keys_core"] == ()


def test_python_id2b_matches_bash_with_metadata_placeholders(
    tmp_path: Path,
) -> None:
    from test_generate_keymap import (
        PLACEHOLDER_DEVICES,
        PLACEHOLDERS,
        metadata_with_placeholders,
    )

    metadata = metadata_with_placeholders(
        SCRIPTS_DIR / "metadata.py",
        tmp_path / "metadata.py",
        (*PLACEHOLDERS, "redfin"),
    )
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(PLACEHOLDER_DEVICES)})\n")
    bash = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER": "id2b",
            "METADATA_FILE": str(metadata),
        },
    )

    python = Id2bKeymapper(load_metadata(metadata)).to_tsv(PLACEHOLDER_DEVICES)

    assert python == bash.stdout
