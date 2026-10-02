#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import re
import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, TEST_METADATA, run, run_cli, run_cli_bytes
from signing.keymap import StaticKeymapper
from signing.release_arguments import make_get_key
from test_release_orchestration import (
    PKCS11_ENVIRONMENT,
    ROLLBACK_DEVICES,
    make_release_tree,
    run_release,
)


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


def _streams(output: bytes) -> dict[str, list[str]]:
    fields = output.decode().split("\0")
    assert fields[-1] == ""
    streams: dict[str, list[str]] = {"avb": [], "signing": [], "ota": []}
    for stream, value in zip(fields[:-1:2], fields[1:-1:2], strict=True):
        streams[stream].append(value)
    return streams


def _contains_run(haystack: list[str], needle: list[str]) -> bool:
    return any(
        haystack[index : index + len(needle)] == needle
        for index in range(len(haystack) - len(needle) + 1)
    )


def _rendered(stderr: str, tool: str) -> list[str]:
    line = next(line for line in stderr.splitlines() if f"/bin/{tool}" in line)
    return shlex.split(line)


@pytest.mark.parametrize(
    ("device", "environment", "rollback"),
    (
        ("bramble", {}, None),
        (
            "bramble",
            {**PKCS11_ENVIRONMENT, "SIGNING_HELPER_TOOL": "pkcs11-tool"},
            None,
        ),
        *(
            (device, {"AVB_ROLLBACK_INDEX_OVERRIDE": "42"}, "42")
            for device in ROLLBACK_DEVICES
        ),
    ),
    ids=("plaintext", "pkcs11", *ROLLBACK_DEVICES),
)
def test_build_release_args_matches_release_sh_dry_run(
    tmp_path: Path,
    device: str,
    environment: dict[str, str],
    rollback: str | None,
) -> None:
    """
    USE_PYTHON_RELEASE_ARGS=y replaces release.sh's avb_arguments and
    generated EXTRA_SIGNING_ARGS/EXTRA_OTA_ARGS entries with these
    streams, so each must appear in the command release.sh renders, in
    the same order.
    """
    bash_result = run_release(
        make_release_tree(tmp_path),
        device,
        environment=environment,
    )
    rollback_args = (
        ["--avb-rollback-index-override", rollback] if rollback else []
    )
    python_result = run_build_release_args(device, *rollback_args)

    assert bash_result.returncode == 0, bash_result.stderr
    assert python_result.returncode == 0, python_result.stderr.decode()
    streams = _streams(python_result.stdout)
    assert streams["avb"] and streams["signing"] and streams["ota"]
    signing_command = _rendered(bash_result.stderr, "sign_target_files_apks")
    assert _contains_run(signing_command, streams["signing"] + streams["avb"])
    if rollback is None:
        ota_command = _rendered(bash_result.stderr, "ota_from_target_files")
        assert _contains_run(ota_command, streams["ota"])


@pytest.mark.parametrize("device", ("bramble", "FP5"))
def test_build_release_args_rejects_unsupported_rollback_device(
    tmp_path: Path,
    device: str,
) -> None:
    bash_result = run_release(
        make_release_tree(tmp_path),
        device,
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
    )
    python_result = run_build_release_args(
        device,
        "--avb-rollback-index-override",
        "42",
    )

    message = f"Unsupported device for AVB Rollback Index override: {device}\n"
    assert bash_result.returncode == python_result.returncode == 1
    assert bash_result.stdout.endswith(message)
    assert python_result.stdout.decode() == message


def _without_tmpdir_names(text: str) -> str:
    return re.sub(r"/signing\.\w+/", "/signing.X/", text)


_PKCS11_ENVIRONMENT = {
    "PKCS11_MODULE": "/dev/null",
    "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
    "PKCS11_PIN": "test-only",
}


@pytest.mark.parametrize(
    "environment",
    (
        {},
        {"KEY_SUFFIX": ""},
        {"KEYMAPPER": "legacy"},
        {"KEYMAPPER": "legacy", "KEY_SUFFIX": ".key"},
        {"EXTRA_SIGNING_ARGS": "--extra_flag value", "EXTRA_OTA_ARGS": "--x"},
        {"KEYMAPPER": "legacy", "RSA_KEY_SIZE": "2048"},
        {"KEYMAPPER": "legacy", "AVB_RSA_KEY_SIZE": "2048"},
        {"RSA_KEY_SIZE": "2048"},
        {"AVB_RSA_KEY_SIZE": "2048"},
        {**_PKCS11_ENVIRONMENT, "AVB_RSA_KEY_SIZE": "2048"},
        {**_PKCS11_ENVIRONMENT, "RSA_KEY_SIZE": "2048"},
    ),
    ids=(
        "id2b",
        "id2b-no-suffix",
        "legacy",
        "legacy-suffix",
        "extra-args",
        "legacy-rsa-key-size",
        "legacy-avb-rsa-key-size",
        "id2b-rsa-key-size",
        "id2b-avb-rsa-key-size",
        "pkcs11-avb-rsa-key-size",
        "pkcs11-rsa-key-size",
    ),
)
def test_release_sh_renders_the_same_commands_with_python_arguments(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    bash_result = run_release(
        make_release_tree(tmp_path / "bash"),
        "bramble",
        environment=environment,
    )
    python_result = run_release(
        make_release_tree(tmp_path / "python"),
        "bramble",
        environment={**environment, "USE_PYTHON_RELEASE_ARGS": "y"},
    )

    assert bash_result.returncode == 0, bash_result.stderr
    assert python_result.returncode == 0, python_result.stderr
    python_stderr = python_result.stderr.replace(
        str(tmp_path / "python"),
        str(tmp_path / "bash"),
    )
    assert _without_tmpdir_names(python_stderr) == _without_tmpdir_names(
        bash_result.stderr,
    )


def test_release_sh_refuses_keymapper_file_with_python_arguments(
    tmp_path: Path,
) -> None:
    keymapper_file = tmp_path / "keymapper.custom.include.sh"
    keymapper_file.write_text(
        (SCRIPTS_DIR / "keymapper.id2b.include.sh").read_text(),
    )
    result = run_release(
        make_release_tree(tmp_path / "tree"),
        "bramble",
        environment={
            "USE_PYTHON_RELEASE_ARGS": "y",
            "KEYMAPPER_FILE": str(keymapper_file),
        },
    )

    assert result.returncode != 0
    assert "does not support KEYMAPPER_FILE" in result.stderr


def test_build_release_args_extra_device_already_in_all_devices_is_a_noop() -> (
    None
):
    without = run_build_release_args("bramble", "--extra-devices")
    with_extra = run_build_release_args("bramble", "--extra-devices", "bramble")

    assert without.returncode == with_extra.returncode == 0
    assert with_extra.stdout == without.stdout


def _bash_id2b_get_key_id(
    device: str,
    key_type: str,
    key_name: str,
    *,
    known_devices: Sequence[str],
    extra_devices: Sequence[str] = (),
) -> subprocess.CompletedProcess[str]:
    devices_decl = " ".join(shlex.quote(d) for d in known_devices)
    program = f"""
devices=({devices_decl})
source "$1" || exit $?
source "$2" || exit $?
initialize_keymapper || exit $?
get_key_id "$3" "$4"
"""
    return run(
        [
            "bash",
            "-c",
            program,
            "id2b-keymapper-test",
            SCRIPTS_DIR / "keymapper.id2b.include.sh",
            SCRIPTS_DIR / "metadata",
            key_type,
            key_name,
        ],
        env={
            "DEVICE": device,
            "EXTRA_DEVICES": " ".join(extra_devices),
            "KEY_DIR": "keys",
        },
        check=False,
    )


def test_id2b_extra_device_matches_bash() -> None:
    bash_result = _bash_id2b_get_key_id(
        "unlisteddevice",
        "avb",
        "vbmeta",
        known_devices=("bramble", "redfin"),
        extra_devices=("unlisteddevice",),
    )
    python_result = run_build_release_args(
        "unlisteddevice",
        "--extra-devices",
        "unlisteddevice",
    )

    assert bash_result.returncode == 0, bash_result.stderr
    assert python_result.returncode == 0, python_result.stderr.decode()
    avb = _streams(python_result.stdout)["avb"]
    vbmeta_key = avb[avb.index("--avb_vbmeta_key") + 1]
    assert vbmeta_key == f"keys/{bash_result.stdout.strip()}.pem"


def test_id2b_rejects_a_device_outside_all_devices_like_bash() -> None:
    bash_result = _bash_id2b_get_key_id(
        "unlisteddevice",
        "avb",
        "vbmeta",
        known_devices=("bramble",),
    )
    python_result = run_build_release_args("unlisteddevice", "--extra-devices")

    assert bash_result.returncode != 0
    assert python_result.returncode != 0
    assert "not found in all_devices" in bash_result.stderr
    assert "not found in all_devices" in python_result.stderr.decode()


def _bash_static_get_key(
    device: str,
    key_type: str,
    key_name: str,
    suffix: str = "",
) -> subprocess.CompletedProcess[str]:
    program = r"""
source "$1" || exit $?
get_key "$2" "$3" "$4"
"""
    return run(
        [
            "bash",
            "-c",
            program,
            "static-keymapper-test",
            SCRIPTS_DIR / "keymapper.static.include.sh",
            key_type,
            key_name,
            suffix,
        ],
        env={
            "KEYMAP_FILE": str(STATIC_KEYMAP_FIXTURE),
            "DEVICE": device,
            "KEY_DIR": "keys",
        },
        check=False,
    )


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
def test_static_keymapper_get_key_matches_bash_keymapper(
    device: str,
    key_type: str,
    key_name: str,
) -> None:
    suffix = ".pem" if key_type in ("avb", "apex_payload") else ""
    bash_result = _bash_static_get_key(device, key_type, key_name, suffix)
    assert bash_result.returncode == 0, bash_result.stderr
    expected = bash_result.stdout.strip()

    get_key = make_get_key(
        StaticKeymapper.from_file(STATIC_KEYMAP_FIXTURE),
        device=device,
        key_dir="keys/",
    )

    assert get_key(key_type, key_name) == expected


@pytest.mark.parametrize("key_suffix", (None, ""), ids=("pem", "no-suffix"))
def test_release_sh_renders_the_same_commands_with_the_static_keymapper(
    tmp_path: Path,
    key_suffix: str | None,
) -> None:
    keymap = run_cli(
        [
            "generate-keymap",
            "--keymapper",
            "id2b",
            "--metadata",
            str(TEST_METADATA),
            "--devices",
            "bramble",
        ],
        env={"PATH": "/usr/bin:/bin"},
        replace_env=True,
        check=True,
    ).stdout
    keymap_file = tmp_path / "keymap.tsv"
    keymap_file.write_text(keymap)
    environment = {"KEYMAPPER": "static", "KEYMAP_FILE": str(keymap_file)}
    if key_suffix is not None:
        environment["KEY_SUFFIX"] = key_suffix

    bash_result = run_release(
        make_release_tree(tmp_path / "bash"),
        "bramble",
        environment=environment,
    )
    python_result = run_release(
        make_release_tree(tmp_path / "python"),
        "bramble",
        environment={**environment, "USE_PYTHON_RELEASE_ARGS": "y"},
    )

    assert bash_result.returncode == 0, bash_result.stderr
    assert python_result.returncode == 0, python_result.stderr
    python_stderr = python_result.stderr.replace(
        str(tmp_path / "python"),
        str(tmp_path / "bash"),
    )
    assert python_stderr == bash_result.stderr


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
