#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import ID2B_KEYMAP, SCRIPTS_DIR, run
from signing.keymap import LegacyKeymapper
from signing.metadata import load_metadata

DEVICES = ("bramble", "redfin")


def generate_keymap(
    tmp_path: Path,
    *,
    devices: tuple[str, ...] = DEVICES,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(devices)})\n")
    return run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            **(environment or {"KEYMAPPER": "id2b"}),
        },
        check=False,
    )


def test_id2b_keymap_matches_complete_golden_output(tmp_path: Path) -> None:
    result = generate_keymap(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ID2B_KEYMAP.read_text()


def test_id2b_keymap_rejects_device_missing_from_metadata(
    tmp_path: Path,
) -> None:
    result = generate_keymap(tmp_path, devices=("not-a-supported-device",))

    assert result.returncode != 0
    assert result.stdout == ""
    assert "not-a-supported-device" in result.stderr
    assert "all_devices" in result.stderr


def test_legacy_keymap_needs_a_device(tmp_path: Path) -> None:
    result = generate_keymap(
        tmp_path,
        devices=(),
        environment={"KEYMAPPER": "legacy"},
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "ERROR: No defined devices for which to generate keys." in (
        result.stderr
    )


def test_generate_keymap_loads_a_python_keymapper_file(
    tmp_path: Path,
) -> None:
    keymapper = tmp_path / "keymapper.py"
    keymapper.write_text(
        "from pathlib import Path\n"
        "from signing.keymap import StaticKeymapper\n"
        "\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        f"    return StaticKeymapper.from_file(Path({str(ID2B_KEYMAP)!r}))\n",
    )

    result = generate_keymap(
        tmp_path,
        environment={"KEYMAPPER_FILE": str(keymapper)},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ID2B_KEYMAP.read_text()


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
def test_generate_keymap_maps_extra_devices(
    tmp_path: Path,
    keymapper: str,
) -> None:
    result = generate_keymap(
        tmp_path,
        devices=(*DEVICES, "cerro"),
        environment={"KEYMAPPER": keymapper, "EXTRA_DEVICES": "cerro"},
    )

    assert result.returncode == 0, result.stderr
    assert "\tcerro\t" in result.stdout


def test_legacy_keymapper_requires_only_some_device() -> None:
    keymapper = LegacyKeymapper(load_metadata(SCRIPTS_DIR / "metadata.py"))

    assert (
        keymapper.key_value("other", "ota", "notadevice")
        == "notadevice/releasekey"
    )
    with pytest.raises(ValueError, match="device is required"):
        keymapper.key_value("other", "ota")


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
    environment = {"KEYMAPPER": keymapper}
    if metadata is not None:
        environment["METADATA_FILE"] = str(metadata)
    result = generate_keymap(
        tmp_path,
        devices=PLACEHOLDER_DEVICES,
        environment=environment,
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
