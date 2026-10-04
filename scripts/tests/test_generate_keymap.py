#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_cli
from signing.keymap import LegacyKeymapper
from signing.metadata import load_metadata

DEVICES = ("bramble", "redfin")
LEGACY_DEVICES = ("bramble", "raven", "cheetah")
GOLDEN_KEYMAP = Path(__file__).parent / "fixtures" / "id2b-bramble-redfin.tsv"


def generate_keymap(
    tmp_path: Path,
    devices: tuple[str, ...] = DEVICES,
    *,
    keymapper: str = "id2b",
) -> subprocess.CompletedProcess[str]:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(devices)})\n")
    environment = {"DEVICES_FILE": str(devices_file), "KEYMAPPER": keymapper}
    return run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env=environment,
        check=False,
    )


def python_generate_keymap(
    keymapper: str,
    devices: tuple[str, ...],
) -> subprocess.CompletedProcess[str]:
    return run_cli(
        [
            "generate-keymap",
            "--keymapper",
            keymapper,
            "--metadata",
            SCRIPTS_DIR / "metadata.py",
            "--devices",
            *devices,
        ],
        check=False,
    )


def test_id2b_keymap_matches_complete_golden_output(tmp_path: Path) -> None:
    result = generate_keymap(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == GOLDEN_KEYMAP.read_text()


def test_id2b_keymap_cli_matches_complete_golden_output() -> None:
    result = python_generate_keymap("id2b", DEVICES)

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


def test_legacy_keymap_needs_a_device(tmp_path: Path) -> None:
    result = generate_keymap(tmp_path, (), keymapper="legacy")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "ERROR: No defined devices for which to generate keys." in (
        result.stderr
    )


def test_generate_keymap_loads_a_python_keymapper_file(
    tmp_path: Path,
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)})\n")
    keymapper = tmp_path / "keymapper.py"
    keymapper.write_text(
        "from pathlib import Path\n"
        "from signing.keymap import StaticKeymapper\n"
        "\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        f"    return StaticKeymapper.from_file(Path({str(GOLDEN_KEYMAP)!r}))\n",
    )

    result = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER_FILE": str(keymapper),
        },
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == GOLDEN_KEYMAP.read_text()


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
def test_generate_keymap_maps_extra_devices(
    tmp_path: Path,
    keymapper: str,
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)} cerro)\n")

    result = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER": keymapper,
            "EXTRA_DEVICES": "cerro",
        },
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "\tcerro\t" in result.stdout


def test_legacy_keymap_cli_matches_the_script(tmp_path: Path) -> None:
    script = generate_keymap(tmp_path, LEGACY_DEVICES, keymapper="legacy")
    command = python_generate_keymap("legacy", LEGACY_DEVICES)

    assert script.returncode == 0, script.stderr
    assert command.returncode == 0, command.stderr
    assert command.stdout == script.stdout


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
