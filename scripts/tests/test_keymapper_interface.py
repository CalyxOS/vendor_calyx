#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from signing.keymap import (
    Id2bKeymapper,
    Keymapper,
    LegacyKeymapper,
    StaticKeymapper,
)
from signing.metadata import SigningMetadata, load_metadata

FIXTURE = SCRIPTS_DIR / "tests" / "fixtures" / "id2b-bramble-redfin.tsv"
KEYMAPPERS: dict[
    str,
    tuple[dict[str, str], Callable[[SigningMetadata], Keymapper]],
] = {
    "legacy": ({"KEYMAPPER": "legacy"}, LegacyKeymapper),
    "id2b": ({"KEYMAPPER": "id2b"}, Id2bKeymapper),
    "static": (
        {"KEYMAPPER": "static", "KEYMAP_FILE": str(FIXTURE)},
        lambda metadata: StaticKeymapper.from_file(FIXTURE),
    ),
}
KEYS = (
    ("avb", "vbmeta"),
    ("avb", "vbmeta_system"),
    ("other", "ota"),
    ("core", "build/make/target/product/security/platform"),
    ("core", "build/make/target/product/security/devkey"),
    ("apex_container", "com.android.adbd"),
    ("apex_payload", "com.android.adbd"),
    ("app", "prebuilts/calyx/microg/certs/microg"),
)

_BASH = r"""
set -euo pipefail
devices=(bramble redfin)
source "$1/metadata"
source "$1/common.include.sh"
load_keymapper 2>/dev/null
printf 'avb_custom_key\t%s\n' "${AVB_CUSTOM_KEY:-}"
printf 'key_dir\t%s\n' "$KEY_DIR"
shift
while [ $# -gt 0 ]; do
  printf 'key\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(get_key "$1" "$2" "$3")"
  shift 3
done
"""


def _bash_answers(
    environment: dict[str, str],
    key_suffix: str | None,
) -> list[str]:
    arguments: list[str] = []
    for key_type, key_name in KEYS:
        for suffix in ("", ".pem", ".key"):
            arguments += [key_type, key_name, suffix]
    variables = {**environment, "DEVICE": "bramble"}
    if key_suffix is not None:
        variables["KEY_SUFFIX"] = key_suffix
    result = run(
        ["bash", "-c", _BASH, "keymapper-test", SCRIPTS_DIR, *arguments],
        cwd=SCRIPTS_DIR,
        env=variables,
    )
    return result.stdout.splitlines()


@pytest.mark.parametrize("name", KEYMAPPERS)
@pytest.mark.parametrize("key_suffix", (None, "", ".key"))
def test_keymapper_interface_matches_the_bash_keymapper(
    name: str,
    key_suffix: str | None,
) -> None:
    environment, create = KEYMAPPERS[name]
    keymapper = create(load_metadata(SCRIPTS_DIR / "metadata.py"))
    effective_suffix = ".pem" if key_suffix is None else key_suffix
    answers = _bash_answers(environment, key_suffix)
    key_dir = answers[1].removeprefix("key_dir\t")

    expected = [
        f"avb_custom_key\t{SCRIPTS_DIR}/"
        f"{key_dir}{keymapper.avb_custom_key('bramble')}",
        f"key_dir\t{key_dir}",
    ]
    for key_type, key_name in KEYS:
        for suffix in ("", ".pem", ".key"):
            value = keymapper.key(
                key_type,
                key_name,
                "bramble",
                suffix=suffix,
                key_suffix=effective_suffix,
            )
            expected.append(
                f"key\t{key_type}\t{key_name}\t{suffix}\t"
                f"{f'{key_dir}{value}' if value else ''}",
            )

    assert expected == answers


_BASH_KEY_IDS = r"""
set -euo pipefail
devices=(bramble redfin)
source "$1/metadata"
source "$1/common.include.sh"
load_keymapper 2>/dev/null
printf 'map\t%s\n' "${device_specific_key_ids_map[bramble]}"
"""


@pytest.mark.parametrize("name", ("id2b", "static"))
def test_keymapper_key_id_queries_match_the_bash_keymapper(name: str) -> None:
    environment, create = KEYMAPPERS[name]
    keymapper = create(load_metadata(SCRIPTS_DIR / "metadata.py"))
    result = run(
        ["bash", "-c", _BASH_KEY_IDS, "key-ids-test", SCRIPTS_DIR],
        cwd=SCRIPTS_DIR,
        env={**environment, "DEVICE": "bramble"},
    )
    lines = result.stdout.splitlines()

    assert set(lines[0].split("\t")[1:]) - {""} == set(
        keymapper.device_key_ids("bramble"),
    )


def test_legacy_keymapper_has_no_device_key_ids() -> None:
    keymapper = LegacyKeymapper(load_metadata(SCRIPTS_DIR / "metadata.py"))

    with pytest.raises(ValueError, match="does not assign key IDs"):
        keymapper.device_key_ids("bramble")


def test_static_keymapper_skips_empty_lines(tmp_path: Path) -> None:
    keymap_file = tmp_path / "keymap.tsv"
    keymap_file.write_text(FIXTURE.read_text() + "\n\n")

    assert StaticKeymapper.from_file(keymap_file).device_key_ids(
        "bramble",
    ) == StaticKeymapper.from_file(FIXTURE).device_key_ids("bramble")


def test_static_keymapper_refuses_a_short_line(tmp_path: Path) -> None:
    keymap_file = tmp_path / "keymap.tsv"
    keymap_file.write_text("ID\tDevice\tKey Type\tKey\n0x2000\tbramble\n")

    with pytest.raises(ValueError, match="keymap.tsv:2: expected four"):
        StaticKeymapper.from_file(keymap_file)
