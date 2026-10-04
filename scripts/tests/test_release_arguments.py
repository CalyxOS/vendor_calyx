#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import TEST_METADATA, run_cli_bytes
from signing.keymap import StaticKeymapper
from signing.release_arguments import make_get_key


@pytest.fixture(autouse=True)
def _small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


STATIC_KEYMAP_FIXTURE = (
    Path(__file__).parent / "fixtures" / "id2b-bramble-redfin.tsv"
)


def run_build_release_args(
    device: str,
    *args: str,
) -> subprocess.CompletedProcess[bytes]:
    return run_cli_bytes(
        [
            "build-release-args",
            "--metadata",
            str(TEST_METADATA),
            "--keymapper",
            "id2b",
            "--device",
            device,
            "--key-dir",
            "keys/",
            "--avb-algorithm",
            "SHA256_RSA4096",
            *args,
        ],
        env={"PATH": "/usr/bin:/bin"},
        replace_env=True,
        check=False,
    )


@pytest.mark.parametrize("device", ("bramble", "FP5"))
def test_build_release_args_rejects_unsupported_rollback_device(
    device: str,
) -> None:
    command_result = run_build_release_args(
        device,
        "--avb-rollback-index-override",
        "42",
    )

    message = f"Unsupported device for AVB Rollback Index override: {device}\n"
    assert command_result.returncode == 1
    assert command_result.stdout.decode() == message


def test_build_release_args_extra_device_already_in_all_devices_is_a_noop() -> (
    None
):
    without = run_build_release_args("bramble", "--extra-devices")
    with_extra = run_build_release_args("bramble", "--extra-devices", "bramble")

    assert without.returncode == with_extra.returncode == 0
    assert with_extra.stdout == without.stdout


def test_id2b_rejects_a_device_outside_all_devices() -> None:
    result = run_build_release_args("unlisteddevice", "--extra-devices")

    assert result.returncode != 0
    assert "not found in all_devices" in result.stderr.decode()


def test_static_get_key_keeps_the_suffix_on_avb_and_apex_payload() -> None:
    get_key = make_get_key(
        StaticKeymapper.from_file(STATIC_KEYMAP_FIXTURE),
        device="bramble",
        key_dir="keys/",
    )

    assert get_key("avb", "vbmeta").endswith(".pem")
    assert get_key("apex_payload", "com.android.adbd") == "keys/0x1300.pem"
    assert get_key("other", "ota") == "keys/0x2000"


def test_static_keymapper_get_key_raises_for_unknown_key() -> None:
    get_key = make_get_key(
        StaticKeymapper.from_file(STATIC_KEYMAP_FIXTURE),
        device="bramble",
        key_dir="keys/",
    )

    with pytest.raises(ValueError, match="Could not find key type"):
        get_key("core", "no/such/key")


@pytest.mark.parametrize(
    ("device", "key_type", "key_name"),
    [
        ("bramble", "core", "build/make/target/product/security/testkey"),
        ("bramble", "core", "build/make/target/product/security/devkey"),
        ("bramble", "avb", "vbmeta"),
        ("redfin", "avb", "vbmeta"),
        ("bramble", "other", "ota"),
        ("redfin", "other", "ota"),
        (
            "bramble",
            "apex_apk",
            "device/google/gs-common/uwb-certs/com.qorvo.uwb",
        ),
    ],
)
def test_static_keymapper_get_key_reads_the_keymap_file(
    device: str,
    key_type: str,
    key_name: str,
) -> None:
    suffix = ".pem" if key_type in ("avb", "apex_payload") else ""
    lookup = key_name.replace("security/devkey", "security/testkey")
    (key_id,) = {
        fields[0]
        for fields in (
            line.split("\t")
            for line in STATIC_KEYMAP_FIXTURE.read_text().splitlines()[1:]
        )
        if fields[1] in (device, "") and fields[2:] == [key_type, lookup]
    }
    expected = f"keys/{key_id}{suffix}"

    get_key = make_get_key(
        StaticKeymapper.from_file(STATIC_KEYMAP_FIXTURE),
        device=device,
        key_dir="keys/",
    )

    assert get_key(key_type, key_name) == expected


def test_build_release_args_passes_the_rollback_index_as_given() -> None:
    result = run_build_release_args(
        "devon",
        "--avb-rollback-index-override",
        "007",
    )

    assert result.returncode == 0, result.stderr.decode()
    assert (
        b"signing\x00--avb_rollback_index_override\x00signing\x00007\x00"
        in result.stdout
    )
