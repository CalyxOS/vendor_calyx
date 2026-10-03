#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections.abc import Callable

import pytest
from conftest import SCRIPTS_DIR, run
from signing.keymap import Id2bKeymapper, Keymapper, LegacyKeymapper
from signing.metadata import SigningMetadata, load_metadata

KEYMAPPERS: dict[
    str,
    tuple[dict[str, str], Callable[[SigningMetadata], Keymapper]],
] = {
    "legacy": ({"KEYMAPPER": "legacy"}, LegacyKeymapper),
    "id2b": ({"KEYMAPPER": "id2b"}, Id2bKeymapper),
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
