#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from conftest import SCRIPTS_DIR
from signing.keymap import Id2bKeymapper
from signing.metadata import load_metadata


def test_id2b_keymap_of_every_shipped_device_is_the_shipped_keymap() -> None:
    metadata = load_metadata(SCRIPTS_DIR / "metadata.py")
    expected = SCRIPTS_DIR / "pkcs11/keymap.tsv"

    assert (
        Id2bKeymapper(metadata).to_tsv(
            metadata.all_devices,
        )
        == expected.read_text()
    )
