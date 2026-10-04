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
    load_keymapper,
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
shift
for key_id in "$@"; do
  per_device=$(get_key_id_is_per_device_yn "$key_id")
  printf 'per_device\t%s\t%s\n' "$key_id" "$per_device"
done
"""
KEY_IDS = ("0x1100", "0x1200", "0x2000", "0x2001", "0x2100", "0x2140", "0xfe00")


@pytest.mark.parametrize("name", ("id2b", "static"))
def test_keymapper_key_id_queries_match_the_bash_keymapper(name: str) -> None:
    environment, create = KEYMAPPERS[name]
    keymapper = create(load_metadata(SCRIPTS_DIR / "metadata.py"))
    result = run(
        ["bash", "-c", _BASH_KEY_IDS, "key-ids-test", SCRIPTS_DIR, *KEY_IDS],
        cwd=SCRIPTS_DIR,
        env={**environment, "DEVICE": "bramble"},
    )
    lines = result.stdout.splitlines()

    assert set(lines[0].split("\t")[1:]) - {""} == set(
        keymapper.device_key_ids("bramble"),
    )
    assert lines[1:] == [
        f"per_device\t{key_id}\t"
        f"{'y' if keymapper.key_id_is_per_device(key_id) else 'n'}"
        for key_id in KEY_IDS
    ]


def test_legacy_keymapper_has_no_device_key_ids() -> None:
    keymapper = LegacyKeymapper(load_metadata(SCRIPTS_DIR / "metadata.py"))

    assert keymapper.key_id_is_per_device("0x1100")
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


@pytest.mark.parametrize(
    ("environment", "message"),
    (
        ({"KEYMAPPER": "nope"}, "Could not find keymapper 'nope'."),
        ({"KEYMAPPER": "static"}, "Please set KEYMAP_FILE"),
        (
            {"KEYMAPPER": "static", "KEYMAP_FILE": "/nonexistent/keymap.tsv"},
            "Cannot find KEYMAP_FILE /nonexistent/keymap.tsv",
        ),
    ),
    ids=("unknown", "static-without-keymap", "static-missing-keymap"),
)
def test_load_keymapper_refuses_unknown_or_unconfigured_keymapper(
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        load_keymapper(environment, load_metadata(SCRIPTS_DIR / "metadata.py"))


@pytest.mark.parametrize(
    "environment",
    ({}, {"KEYMAPPER": ""}),
    ids=("unset", "empty"),
)
def test_load_keymapper_defaults_to_legacy(
    environment: dict[str, str],
) -> None:
    keymapper = load_keymapper(
        environment,
        load_metadata(SCRIPTS_DIR / "metadata.py"),
    )

    assert isinstance(keymapper, LegacyKeymapper)


_PLUGIN = """
from signing.keymap import Id2bKeymapper


class PluginKeymapper(Id2bKeymapper):
    def key(self, key_type, key_name, device="", *, suffix="", key_suffix=""):
        return "plugin/" + super().key(
            key_type, key_name, device, suffix=suffix, key_suffix=key_suffix
        )


def create_keymapper(environment, metadata, *, extra_devices):
    return PluginKeymapper(metadata, extra_devices=extra_devices)
"""


def test_keymapper_file_supplies_the_keymapper(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(_PLUGIN)

    keymapper = load_keymapper(
        {"KEYMAPPER_FILE": str(plugin), "KEYMAPPER": "legacy"},
        load_metadata(SCRIPTS_DIR / "metadata.py"),
    )

    assert keymapper.key("other", "ota", "bramble") == "plugin/0x2000"


def test_keymapper_file_resolves_relative_to_the_scripts_directory() -> None:
    with pytest.raises(ValueError, match=f"{SCRIPTS_DIR}/missing.py"):
        load_keymapper(
            {"KEYMAPPER_FILE": "missing.py"},
            load_metadata(SCRIPTS_DIR / "metadata.py"),
        )


@pytest.mark.parametrize(
    ("source", "message"),
    (
        ("", r"does not define create_keymapper\(\)"),
        (
            "def create_keymapper(environment, metadata, *, extra_devices):\n"
            "    return object()\n",
            "returned object, not a Keymapper",
        ),
    ),
    ids=("no-factory", "not-a-keymapper"),
)
def test_keymapper_file_must_create_a_keymapper(
    tmp_path: Path,
    source: str,
    message: str,
) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(source)

    with pytest.raises(ValueError, match=message):
        load_keymapper(
            {"KEYMAPPER_FILE": str(plugin)},
            load_metadata(SCRIPTS_DIR / "metadata.py"),
        )


def test_a_keymapper_must_define_rows() -> None:
    assert Keymapper.__abstractmethods__ == {"rows"}


def test_keymapper_file_can_define_a_dataclass(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n"
        "from signing.keymap import Id2bKeymapper\n"
        "@dataclass\n"
        "class Settings:\n"
        "    prefix: str = ''\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        "    Settings()\n"
        "    return Id2bKeymapper(metadata, extra_devices=extra_devices)\n",
    )

    keymapper = load_keymapper(
        {"KEYMAPPER_FILE": str(plugin)},
        load_metadata(SCRIPTS_DIR / "metadata.py"),
    )

    assert keymapper.key("other", "ota", "bramble") == "0x2000"


def test_keymapper_file_that_fails_to_load_is_named(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text("import does_not_exist\n")

    with pytest.raises(
        ValueError,
        match=f"Cannot load KEYMAPPER_FILE {plugin}",
    ):
        load_keymapper(
            {"KEYMAPPER_FILE": str(plugin)},
            load_metadata(SCRIPTS_DIR / "metadata.py"),
        )


def test_keymapper_file_prints_its_keymap(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(_PLUGIN)

    keymapper = load_keymapper(
        {"KEYMAPPER_FILE": str(plugin)},
        load_metadata(SCRIPTS_DIR / "metadata.py"),
    )

    assert keymapper.to_tsv(("bramble", "redfin")) == FIXTURE.read_text()


def test_keymapper_file_whose_create_keymapper_fails_is_named(
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "failing.py"
    plugin.write_text(
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        "    raise RuntimeError('no keymapper today')\n",
    )

    with pytest.raises(ValueError, match=r"failing.py failed \(no keymapper"):
        load_keymapper(
            {"KEYMAPPER_FILE": str(plugin)},
            load_metadata(SCRIPTS_DIR / "metadata.py"),
        )
