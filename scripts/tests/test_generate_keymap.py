#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import stat
import subprocess
import sys
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
    use_python: bool = False,
) -> subprocess.CompletedProcess[str]:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(devices)})\n")
    environment = {"DEVICES_FILE": str(devices_file), "KEYMAPPER": keymapper}
    if use_python:
        environment["USE_PYTHON_GENERATE_KEYMAP"] = "y"
        environment["PYTHONPATH"] = str(SCRIPTS_DIR)
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


@pytest.mark.parametrize("use_python", (False, True))
def test_id2b_keymap_rejects_device_missing_from_metadata(
    tmp_path: Path,
    use_python: bool,
) -> None:
    result = generate_keymap(
        tmp_path,
        ("not-a-supported-device",),
        use_python=use_python,
    )

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


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
def test_generate_keymap_python_flag_matches_bash_without_devices(
    tmp_path: Path,
    keymapper: str,
) -> None:
    bash = generate_keymap(tmp_path, (), keymapper=keymapper)
    python = generate_keymap(tmp_path, (), keymapper=keymapper, use_python=True)

    assert python.returncode == bash.returncode
    assert python.stdout == bash.stdout
    if bash.returncode != 0:
        expected = "ERROR: No defined devices for which to generate keys."
        assert expected in bash.stderr
        assert expected in python.stderr


@pytest.mark.parametrize(
    ("keymapper", "devices"),
    (("id2b", DEVICES), ("legacy", LEGACY_DEVICES)),
)
def test_generate_keymap_python_flag_matches_bash(
    tmp_path: Path,
    keymapper: str,
    devices: tuple[str, ...],
) -> None:
    bash = generate_keymap(tmp_path, devices, keymapper=keymapper)
    python = generate_keymap(
        tmp_path,
        devices,
        keymapper=keymapper,
        use_python=True,
    )

    assert bash.returncode == 0, bash.stderr
    assert python.returncode == 0, python.stderr
    assert python.stdout == bash.stdout


def test_generate_keymap_python_flag_invokes_python(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "fake-path-bin"
    fake_bin.mkdir()
    fake_python3 = fake_bin / "python3"
    fake_python3.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" generate-keymap "*)\n'
        "  echo FAKE_PYTHON3_INVOKED >&2\n"
        "  exit 1\n"
        "esac\n"
        f'exec {sys.executable} "$@"\n',
    )
    fake_python3.chmod(fake_python3.stat().st_mode | stat.S_IXUSR)
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)})\n")
    path_with_fake = f"{fake_bin}:{os.environ['PATH']}"

    with_flag = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER": "id2b",
            "USE_PYTHON_GENERATE_KEYMAP": "y",
            "PATH": path_with_fake,
        },
        check=False,
    )
    assert "FAKE_PYTHON3_INVOKED" in with_flag.stderr
    assert with_flag.returncode != 0

    without_flag = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "KEYMAPPER": "id2b",
            "PATH": path_with_fake,
        },
        check=False,
    )
    assert "FAKE_PYTHON3_INVOKED" not in without_flag.stderr
    assert without_flag.returncode == 0, without_flag.stderr


@pytest.mark.parametrize(
    "environment",
    ({"KEYMAPPER": "static"}, {"KEYMAPPER_FILE": "keymapper.id2b.include.sh"}),
    ids=("static", "keymapper-file"),
)
def test_generate_keymap_python_flag_rejects_other_keymappers(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)})\n")

    result = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={
            "DEVICES_FILE": str(devices_file),
            "USE_PYTHON_GENERATE_KEYMAP": "y",
            **environment,
        },
        check=False,
    )

    assert result.returncode == 1
    assert "supports only the legacy and id2b keymappers" in result.stderr


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
def test_generate_keymap_python_flag_matches_bash_for_extra_devices(
    tmp_path: Path,
    keymapper: str,
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(f"devices=({' '.join(DEVICES)} cerro)\n")
    environment = {
        "DEVICES_FILE": str(devices_file),
        "KEYMAPPER": keymapper,
        "EXTRA_DEVICES": "cerro",
    }

    bash = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env=environment,
        check=False,
    )
    python = run(
        [SCRIPTS_DIR / "generate_keymap.sh"],
        env={**environment, "USE_PYTHON_GENERATE_KEYMAP": "y"},
        check=False,
    )

    assert bash.returncode == 0, bash.stderr
    assert python.returncode == 0, python.stderr
    assert "\tcerro\t" in bash.stdout
    assert python.stdout == bash.stdout


def test_python_legacy_keymap_cli_matches_bash(tmp_path: Path) -> None:
    bash = generate_keymap(tmp_path, LEGACY_DEVICES, keymapper="legacy")
    python = python_generate_keymap("legacy", LEGACY_DEVICES)

    assert bash.returncode == 0, bash.stderr
    assert python.returncode == 0, python.stderr
    assert python.stdout == bash.stdout


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
