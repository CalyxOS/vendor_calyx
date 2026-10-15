#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import (
    FIXTURES_DIR,
    ID2B_KEYMAP,
    PKCS11_DIR,
    SCRIPTS_DIR,
    shipped_metadata,
)
from signing.keymap import (
    Id2bConfig,
    Id2bKeymapper,
    Keymapper,
    LegacyKeymapper,
    StaticKeymapper,
    load_keymapper,
)
from signing.metadata import SigningMetadata


def test_static_keymapper_skips_empty_lines(tmp_path: Path) -> None:
    keymap_file = tmp_path / "keymap.tsv"
    keymap_file.write_text(ID2B_KEYMAP.read_text() + "\n\n")

    assert StaticKeymapper.from_file(keymap_file).device_key_ids(
        "bramble",
    ) == StaticKeymapper.from_file(ID2B_KEYMAP).device_key_ids("bramble")


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
        load_keymapper(environment, shipped_metadata())


@pytest.mark.parametrize(
    "environment",
    ({}, {"KEYMAPPER": ""}),
    ids=("unset", "empty"),
)
def test_load_keymapper_defaults_to_legacy(
    environment: dict[str, str],
) -> None:
    keymapper = load_keymapper(environment, shipped_metadata())

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
        shipped_metadata(),
    )

    assert keymapper.key("other", "ota", "bramble") == "plugin/0x2000"


def test_keymapper_file_resolves_relative_to_the_scripts_directory() -> None:
    with pytest.raises(ValueError, match=f"{SCRIPTS_DIR}/missing.py"):
        load_keymapper({"KEYMAPPER_FILE": "missing.py"}, shipped_metadata())


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
        load_keymapper({"KEYMAPPER_FILE": str(plugin)}, shipped_metadata())


def test_a_keymapper_must_define_rows_and_is_per_device() -> None:
    assert Keymapper.__abstractmethods__ == {"is_per_device", "rows"}


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
        shipped_metadata(),
    )

    assert keymapper.key("other", "ota", "bramble") == "0x2000"


def test_keymapper_file_that_fails_to_load_is_named(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text("import does_not_exist\n")

    with pytest.raises(
        ValueError,
        match=f"Cannot load KEYMAPPER_FILE {plugin}",
    ):
        load_keymapper({"KEYMAPPER_FILE": str(plugin)}, shipped_metadata())


def test_keymapper_file_prints_its_keymap(tmp_path: Path) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(_PLUGIN)

    keymapper = load_keymapper(
        {"KEYMAPPER_FILE": str(plugin)},
        shipped_metadata(),
    )

    assert keymapper.to_tsv(("bramble", "redfin")) == ID2B_KEYMAP.read_text()


def test_legacy_keymapper_assigns_no_key_ids() -> None:
    keymapper = load_keymapper({"KEYMAPPER": "legacy"}, shipped_metadata())

    with pytest.raises(ValueError, match="does not assign key IDs"):
        keymapper.device_key_ids("bramble")
    with pytest.raises(ValueError, match="does not assign key IDs"):
        keymapper.key_id_is_per_device("0x1100")


def test_legacy_keymapper_overrides_a_preset_key_dir() -> None:
    keymapper = load_keymapper({"KEYMAPPER": "legacy"}, shipped_metadata())
    environment = {"KEY_DIR": "custom/"}

    assert keymapper.key_dir(environment) == "keys/"
    assert environment["KEY_DIR"] == "keys/"


def test_keymapper_file_whose_create_keymapper_fails_is_named(
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "failing.py"
    plugin.write_text(
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        "    raise RuntimeError('no keymapper today')\n",
    )

    with pytest.raises(ValueError, match=r"failing.py failed \(no keymapper"):
        load_keymapper({"KEYMAPPER_FILE": str(plugin)}, shipped_metadata())


@pytest.mark.parametrize(
    ("config", "message"),
    (
        (Id2bConfig(avb_consolidation="some"), "invalid AVB consolidation"),
        (Id2bConfig(apex_consolidation="some"), "invalid APEX consolidation"),
        (Id2bConfig(device_prefix_end=0x20), "exceeds the configured"),
        (
            Id2bConfig(device_prefix_start=0x16),
            "0x16-0xfe overlaps the prefix of key types repo",
        ),
        (
            Id2bConfig(device_prefix_start=0x00),
            "overlaps the prefix of key types apex_apk, apex_container, "
            "apex_payload, app, avb, core, repo",
        ),
        (Id2bConfig(device_prefix_end=0x100), "0x100 does not fit one byte"),
    ),
    ids=("avb", "apex", "range", "overlap", "overlap-all", "byte"),
)
def test_id2b_keymapper_validates_the_config_it_is_given(
    config: Id2bConfig,
    message: str,
) -> None:
    metadata = shipped_metadata()

    with pytest.raises(ValueError, match=message):
        Id2bKeymapper(metadata, config=config)


ANSWERS = json.loads(
    (FIXTURES_DIR / "keymapper-answers.json").read_text(),
)
KEYMAPPERS: dict[
    str,
    tuple[dict[str, str], Callable[[SigningMetadata], Keymapper]],
] = {
    "legacy": ({"KEYMAPPER": "legacy"}, LegacyKeymapper),
    "id2b": ({"KEYMAPPER": "id2b"}, Id2bKeymapper),
    "static": (
        {"KEYMAPPER": "static", "KEYMAP_FILE": str(ID2B_KEYMAP)},
        lambda metadata: StaticKeymapper.from_file(ID2B_KEYMAP),
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


@pytest.mark.parametrize("name", KEYMAPPERS)
@pytest.mark.parametrize("key_suffix", (None, "", ".key"))
def test_keymapper_resolves_the_recorded_key_paths(
    name: str,
    key_suffix: str | None,
) -> None:
    environment, create = KEYMAPPERS[name]
    keymapper = create(shipped_metadata())
    answers = (
        ANSWERS["key_paths"]["legacy"][
            "none" if key_suffix is None else key_suffix
        ]
        if name == "legacy"
        else ANSWERS["key_paths"]["id2b_static"]
    )

    assert keymapper.key_dir(dict(environment)) == answers["key_dir"]
    assert keymapper.avb_custom_key("bramble") == answers["avb_custom_key"]
    assert [
        [
            key_type,
            key_name,
            suffix,
            keymapper.key(
                key_type,
                key_name,
                "bramble",
                suffix=suffix,
                key_suffix=".pem" if key_suffix is None else key_suffix,
            ),
        ]
        for key_type, key_name in KEYS
        for suffix in ("", ".pem", ".key")
    ] == answers["keys"]


@pytest.mark.parametrize("name", ("id2b", "static"))
def test_keymapper_reports_the_recorded_key_ids(name: str) -> None:
    _, create = KEYMAPPERS[name]
    keymapper = create(shipped_metadata())
    answers = ANSWERS["key_ids"][name]

    assert set(keymapper.device_key_ids("bramble")) == set(
        answers["device_key_ids"],
    )
    assert {
        key_id: keymapper.key_id_is_per_device(key_id)
        for key_id in answers["per_device"]
    } == answers["per_device"]


@pytest.mark.parametrize("name", KEYMAPPERS)
def test_is_per_device_gives_the_recorded_answers(name: str) -> None:
    _, create = KEYMAPPERS[name]
    keymapper = create(shipped_metadata())

    assert [
        [key_type, key_name, keymapper.is_per_device(key_type, key_name)]
        for key_type, key_name in KEYS
    ] == ANSWERS["per_device"][name]


def test_id2b_keymap_of_every_shipped_device_is_the_shipped_keymap() -> None:
    metadata = shipped_metadata()
    expected = PKCS11_DIR / "keymap.tsv"

    assert (
        Id2bKeymapper(metadata).to_tsv(
            metadata.all_devices,
        )
        == expected.read_text()
    )
