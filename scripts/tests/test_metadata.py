#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections import Counter

from conftest import SCRIPTS_DIR, run

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
