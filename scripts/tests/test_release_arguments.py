#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import pytest
from conftest import ID2B_KEYMAP, TEST_METADATA
from signing.keymap import Id2bKeymapper, StaticKeymapper
from signing.metadata import load_metadata
from signing.release_arguments import (
    ReleaseArguments,
    build_release_arguments,
    make_get_key,
)


def release_arguments(
    device: str,
    *,
    rollback: str | None = None,
    extra_devices: tuple[str, ...] = (),
) -> ReleaseArguments:
    metadata = load_metadata(TEST_METADATA)
    return build_release_arguments(
        metadata,
        make_get_key(
            Id2bKeymapper(metadata, extra_devices=extra_devices),
            {},
            device=device,
        ),
        device=device,
        avb_rollback_index_override=rollback,
        avb_algorithm="SHA256_RSA4096",
    )


def test_extra_device_already_in_all_devices_is_a_noop() -> None:
    assert release_arguments(
        "bramble",
        extra_devices=("bramble",),
    ) == release_arguments("bramble")


def test_id2b_rejects_a_device_outside_all_devices() -> None:
    with pytest.raises(ValueError, match="not found in all_devices"):
        release_arguments("unlisteddevice")


def test_static_keymapper_get_key_raises_for_unknown_key() -> None:
    get_key = make_get_key(
        StaticKeymapper.from_file(ID2B_KEYMAP),
        {},
        device="bramble",
    )

    with pytest.raises(ValueError, match="Could not find key type"):
        get_key("core", "no/such/key")


@pytest.mark.parametrize(
    "device",
    ("devon", "hawao", "rhode", "fogos", "bangkk", "fogo"),
)
def test_release_arguments_pass_the_rollback_index_as_given(
    device: str,
) -> None:
    arguments = release_arguments(device, rollback="007")

    index = arguments.signing_args.index("--avb_rollback_index_override")
    assert arguments.signing_args[index + 1] == "007"
