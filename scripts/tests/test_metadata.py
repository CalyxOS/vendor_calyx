#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from signing.metadata import load_metadata

ARRAYS = (
    "keys_avb",
    "keys_other",
    "keys_core",
    "keys_apex",
    "keys_apex_apk",
    "keys_app",
    "keys_repo",
    "key_types",
    "mapped_key_types",
    "all_devices",
)


def read_metadata_arrays() -> dict[str, list[str]]:
    names = " ".join(ARRAYS)
    script = f"""
set -euo pipefail
source "$1"
for name in {names}; do
  declare -n values="$name"
  for value in "${{values[@]}}"; do
    printf '%s\\t%s\\n' "$name" "$value"
  done
done
for key_type in "${{!key_type_to_array[@]}}"; do
  printf 'key_type_to_array\\t%s=%s\\n' \
    "$key_type" "${{key_type_to_array[$key_type]}}"
done
"""
    result = run(
        ["bash", "-c", script, "metadata-test", SCRIPTS_DIR / "metadata"],
    )
    arrays: dict[str, list[str]] = {name: [] for name in ARRAYS}
    arrays["key_type_to_array"] = []
    for line in result.stdout.splitlines():
        name, value = line.split("\t", 1)
        arrays[name].append(value)
    return arrays


def test_metadata_arrays_are_nonempty_and_unique() -> None:
    arrays = read_metadata_arrays()
    for name in ARRAYS:
        values = [value for value in arrays[name] if value]
        assert values, f"{name} must not be empty"
        duplicates = sorted(
            value for value, count in Counter(values).items() if count > 1
        )
        assert not duplicates, f"duplicate entries in {name}: {duplicates}"


def test_every_key_type_resolves_to_a_populated_array() -> None:
    arrays = read_metadata_arrays()
    mappings = dict(item.split("=", 1) for item in arrays["key_type_to_array"])

    assert {key_type for key_type in arrays["key_types"] if key_type} <= set(
        mappings,
    )
    for key_type, array_name in mappings.items():
        assert array_name in arrays, (
            f"{key_type} refers to unknown array {array_name!r}"
        )
        assert arrays[array_name], (
            f"{key_type} refers to empty array {array_name}"
        )


def test_mapped_key_types_are_known() -> None:
    arrays = read_metadata_arrays()
    mappings = dict(item.split("=", 1) for item in arrays["key_type_to_array"])
    assert set(arrays["mapped_key_types"]) <= set(mappings)


def test_sourcing_metadata_fails_when_metadata_py_does_not_load(
    tmp_path: Path,
) -> None:
    (tmp_path / "metadata").write_text((SCRIPTS_DIR / "metadata").read_text())
    (tmp_path / "metadata.py").write_text("KEYS_AVB = (\n")

    result = run(
        [
            "bash",
            "-c",
            'source "$1" || exit 7',
            "metadata-test",
            tmp_path / "metadata",
        ],
        check=False,
    )

    assert result.returncode == 7
    assert f"cannot load {tmp_path}/metadata.py" in result.stderr


def test_sourcing_metadata_refuses_an_array_that_is_not_a_tuple(
    tmp_path: Path,
) -> None:
    (tmp_path / "metadata").write_text((SCRIPTS_DIR / "metadata").read_text())
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    (tmp_path / "metadata.py").write_text(
        source.replace('KEYS_REPO = ("updater",)', 'KEYS_REPO = ("updater")'),
    )

    result = run(
        [
            "bash",
            "-c",
            'source "$1" || exit 7',
            "metadata-test",
            tmp_path / "metadata",
        ],
        check=False,
    )

    assert result.returncode == 7
    assert "KEYS_REPO in" in result.stderr
    assert "is not a tuple of strings" in result.stderr


def test_sourcing_metadata_refuses_a_key_type_map_of_other_values(
    tmp_path: Path,
) -> None:
    (tmp_path / "metadata").write_text((SCRIPTS_DIR / "metadata").read_text())
    source = (SCRIPTS_DIR / "metadata.py").read_text()
    (tmp_path / "metadata.py").write_text(
        source.replace('"avb": "keys_avb",', '"avb": ("keys_avb",),'),
    )

    result = run(
        [
            "bash",
            "-c",
            'source "$1" || exit 7',
            "metadata-test",
            tmp_path / "metadata",
        ],
        check=False,
    )

    assert result.returncode == 7
    assert "does not map strings to strings" in result.stderr


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


def test_metadata_loads_a_module_without_a_py_suffix(tmp_path: Path) -> None:
    module = tmp_path / "metadata"
    module.write_text((SCRIPTS_DIR / "metadata.py").read_text())

    assert load_metadata(module) == load_metadata(SCRIPTS_DIR / "metadata.py")
