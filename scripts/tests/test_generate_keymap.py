#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

DEVICES = ("bramble", "redfin")
GOLDEN_KEYMAP = Path(__file__).parent / "fixtures" / "id2b-bramble-redfin.tsv"


def generate_keymap(
    tmp_path: Path,
    devices: tuple[str, ...] = DEVICES,
) -> subprocess.CompletedProcess[str]:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(devices)})\n")
    return run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={"DEVICES_FILE": str(devices_file), "KEYMAPPER": "id2b"},
        check=False,
    )


def test_id2b_keymap_matches_complete_golden_output(tmp_path: Path) -> None:
    result = generate_keymap(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == GOLDEN_KEYMAP.read_text()


def test_id2b_keymap_rejects_device_missing_from_metadata(
    tmp_path: Path,
) -> None:
    result = generate_keymap(tmp_path, ("not-a-supported-device",))

    assert result.returncode != 0
    assert result.stdout == ""
    assert "not-a-supported-device" in result.stderr
    assert "all_devices" in result.stderr


def test_static_keymapper_round_trips_id2b_keymap(tmp_path: Path) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)})\n")
    result = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER": "static",
            "KEYMAP_FILE": str(GOLDEN_KEYMAP),
        },
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == GOLDEN_KEYMAP.read_text()


def test_load_keymapper_fails_when_the_keymapper_does_not_load(
    tmp_path: Path,
) -> None:
    keymapper = tmp_path / "keymapper.broken.include.sh"
    keymapper.write_text("initialize_keymapper() { :; }\nreturn 3\n")

    result = run(
        [
            "bash",
            "-c",
            'source "$1"; load_keymapper; echo "status=$?"',
            "load-keymapper-test",
            SCRIPTS_DIR / "common.include.sh",
        ],
        env={"KEYMAPPER_FILE": str(keymapper)},
        check=False,
    )

    assert "status=3" in result.stdout
    assert "Loading keymapper script failed!" in result.stderr


PLACEHOLDERS = (
    "dtbo",
    "com.android.adservices",
    "packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin",
    "com.google.android.apps.photos",
    "repo",
)
PLACEHOLDER_DEVICES = ("bramble", "panther")


def metadata_with_placeholders(
    source: Path,
    path: Path,
    names: tuple[str, ...] = PLACEHOLDERS,
) -> Path:
    text = source.read_text()
    for name in names:
        entry = f'    "{name}",\n'
        assert text.count(entry) == 1, name
        text = text.replace(entry, '    "",\n')
    path.write_text(text)
    return path


def _keymap_rows(
    tmp_path: Path,
    keymapper: str,
    metadata: Path | None = None,
) -> list[str]:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(PLACEHOLDER_DEVICES)})\n")
    environment = {"DEVICES_FILE": str(devices_file), "KEYMAPPER": keymapper}
    if metadata is not None:
        environment["METADATA_FILE"] = str(metadata)
    result = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
def test_keymap_leaves_out_only_the_metadata_placeholders(
    tmp_path: Path,
    keymapper: str,
) -> None:
    full = _keymap_rows(tmp_path, keymapper)
    metadata = metadata_with_placeholders(
        SCRIPTS_DIR / "metadata.py",
        tmp_path / "metadata.py",
        (*PLACEHOLDERS, "redfin"),
    )

    rows = _keymap_rows(tmp_path, keymapper, metadata)

    assert rows == [
        row for row in full if not set(row.split("\t")[2:]) & set(PLACEHOLDERS)
    ]
