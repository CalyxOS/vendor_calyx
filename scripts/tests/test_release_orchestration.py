#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from conftest import (
    ID2B_KEYMAP,
    SCRIPTS_DIR,
    TEST_METADATA,
    default_signal_dispositions,
    install_executable,
    parameter_id,
    run,
    sha256,
    stub,
)
from signing.keymap import load_keymapper
from signing.metadata import load_metadata
from signing.release_execution import Abort
from signing.release_orchestration import (
    ReleaseOrchestrator,
    avb_algorithm_for,
    read_words,
)

pytestmark = pytest.mark.usefixtures("small_metadata")


BUILD_NUMBER = "2026081500"

PKCS11_ENVIRONMENT = {
    "PKCS11_VENDOR": "softhsm",
    "PKCS11_MODULE": "/dev/null",
    "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
    "PKCS11_PIN": "test-only",
}


def make_release_tree(root: Path) -> Path:
    clear_variables = root / "device/common/clear-factory-images-variables.sh"
    clear_variables.parent.mkdir(parents=True)
    clear_variables.touch()
    factory_images_common = (
        root / "device/common/generate-factory-images-common.sh"
    )
    factory_images_common.write_text(
        'cat "$DEVICE-img-$BUILD.zip" > "$DEVICE-$VERSION-factory-fake.zip"'
        " || exit 1\n",
    )
    _install_fake_release_tools(root)
    _write_avb_custom_keys(root)
    return root


def _write_avb_custom_keys(root: Path) -> None:
    metadata = load_metadata(TEST_METADATA)
    for keymapper in ("legacy", "id2b"):
        mapper = load_keymapper({"KEYMAPPER": keymapper}, metadata)
        for device in metadata.all_devices:
            key = root / "keys" / mapper.avb_custom_key(device)
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text("avb custom key\n")


@pytest.fixture
def release_tree(tmp_path: Path) -> Path:
    return make_release_tree(tmp_path)


def write_target_files_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in (
            ("SYSTEM/build.prop", "ro.build.id=TestBuild\n"),
            (
                "OTA/android-info.txt",
                "require version-bootloader=test-bootloader\n"
                "require version-baseband=test-radio\n",
            ),
        ):
            archive.writestr(
                zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)),
                content,
            )


def _install_fake_release_tools(root: Path) -> None:
    for name, content in (
        ("sign_target_files_apks", "signed-target-files"),
        ("ota_from_target_files", "ota-update-zip"),
        ("img_from_target_files", "factory-img-zip"),
    ):
        install_executable(
            root / "bin" / name,
            '#!/bin/sh\neval "out=\\${$#}"\n'
            f'printf %s "{content}" > "$out"\n',
        )


def _manifest(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def run_release(
    release_tree: Path,
    device: str,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
    target_files_arg: str | None = "_default_",
) -> subprocess.CompletedProcess[str]:
    """
    Run the release entry point with deterministic orchestration settings.

    Args:
        release_tree: Hermetic working directory containing required support
            files.
        device: Android product whose release flow should be exercised.
        environment: Optional release environment overrides.
        dry_run: Whether release tools should only be rendered instead of
            executed.
        target_files_arg: The target-files argument, "_default_" for the
            usual calyx_<device>-target_files-<build>.zip name and None for
            none.

    Returns:
        The completed release process without enforcing successful status.
    """
    tmpdir = release_tree / "tmp"
    tmpdir.mkdir(exist_ok=True)
    variables = {
        "TMPDIR": str(tmpdir),
        "BUILD_NUMBER": BUILD_NUMBER,
        "KEYMAPPER": "id2b",
        "OTA_ONLY": "y",
        **(environment or {}),
    }
    if dry_run:
        variables["DRY_RUN"] = "y"
    argv: list[str | Path] = [SCRIPTS_DIR / "release.sh", device]
    if target_files_arg == "_default_":
        argv.append(f"calyx_{device}-target_files-{BUILD_NUMBER}.zip")
    elif target_files_arg is not None:
        argv.append(target_files_arg)
    return run(argv, cwd=release_tree, env=variables, check=False)


DRY_RUN_FIXTURES = Path(__file__).parent / "fixtures" / "dry-run"


def normalize_dry_run(stderr: str, tree: Path) -> str:
    return stderr.replace(str(SCRIPTS_DIR), "<scripts>").replace(
        str(tree),
        "<tree>",
    )


def _command_line(stderr: str, tool: str) -> str:
    return next(line for line in stderr.splitlines() if f"/bin/{tool}" in line)


def test_release_announces_each_step_before_running_it(
    release_tree: Path,
) -> None:
    result = subprocess.run(
        [
            SCRIPTS_DIR / "release.sh",
            "bramble",
            f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        ],
        cwd=release_tree,
        env={
            **os.environ,
            "TMPDIR": str(release_tree),
            "BUILD_NUMBER": BUILD_NUMBER,
            "KEYMAPPER": "id2b",
            "OTA_ONLY": "y",
            "DRY_RUN": "y",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    lines = result.stdout.splitlines()
    assert lines.index("Creating signed targetfiles zip") < next(
        index
        for index, line in enumerate(lines)
        if "/bin/sign_target_files_apks" in line
    ), result.stdout
    assert lines.index("Creating OTA update zip") < next(
        index
        for index, line in enumerate(lines)
        if "/bin/ota_from_target_files" in line
    ), result.stdout


def test_release_runs_the_release_tools(release_tree: Path) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    manifest = _manifest(release_tree / f"out/release-bramble-{BUILD_NUMBER}")
    assert sorted(manifest) == [
        f"bramble-factory-{BUILD_NUMBER}.zip",
        f"bramble-factory-{BUILD_NUMBER}.zip.sha256sum",
        f"bramble-ota_update-{BUILD_NUMBER}.zip",
        f"bramble-ota_update-{BUILD_NUMBER}.zip.sha256sum",
        f"bramble-target_files-{BUILD_NUMBER}.zip",
    ]
    assert manifest[f"bramble-factory-{BUILD_NUMBER}.zip"] == b"factory-img-zip"
    assert f"bramble-img-{BUILD_NUMBER}.zip" not in manifest
    assert manifest[f"bramble-ota_update-{BUILD_NUMBER}.zip"] == (
        b"ota-update-zip"
    )
    assert manifest[f"bramble-factory-{BUILD_NUMBER}.zip.sha256sum"].endswith(
        f"  bramble-factory-{BUILD_NUMBER}.zip\n".encode(),
    )
    assert manifest[
        f"bramble-ota_update-{BUILD_NUMBER}.zip.sha256sum"
    ].endswith(f"  bramble-ota_update-{BUILD_NUMBER}.zip\n".encode())


def test_release_skip_signing_copies_the_target_files(
    release_tree: Path,
) -> None:
    unsigned = release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip"
    write_target_files_zip(unsigned)

    result = run_release(
        release_tree,
        "bramble",
        environment={
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": "",
            "SKIP_SIGNING": "y",
        },
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    assert "sign_target_files_apks" not in result.stderr
    assert "ota_from_target_files" not in result.stderr
    assert "Skipping signing and OTA generation" in result.stdout
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (
        out / f"bramble-target_files-{BUILD_NUMBER}.zip"
    ).read_bytes() == unsigned.read_bytes()
    assert sorted(_manifest(out)) == [
        f"bramble-factory-{BUILD_NUMBER}.zip",
        f"bramble-factory-{BUILD_NUMBER}.zip.sha256sum",
        f"bramble-target_files-{BUILD_NUMBER}.zip",
    ]


def test_release_skip_signing_dry_run_leaves_the_target_files_alone(
    release_tree: Path,
) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out.mkdir(parents=True)
    signed = out / f"bramble-target_files-{BUILD_NUMBER}.zip"
    signed.write_bytes(b"signed earlier")

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "SKIP_SIGNING": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert signed.read_bytes() == b"signed earlier"


def test_release_skip_signing_honors_ota_only(release_tree: Path) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"SKIP_SIGNING": "y"},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Not creating factory image due to OTA_ONLY=y" in result.stdout
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert not list(out.iterdir())


@pytest.mark.parametrize("from_top", (True, False), ids=("top", "no-top"))
def test_release_finds_in_tree_tools_and_target_files(
    release_tree: Path,
    from_top: bool,
) -> None:
    product = release_tree / "out/target/product/bramble"
    product.mkdir(parents=True)
    write_target_files_zip(
        product / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    soong = (
        release_tree / "out/soong/.intermediates/build/make/tools/releasetools"
    )
    for tool in (
        "sign_target_files_apks",
        "ota_from_target_files",
        "img_from_target_files",
    ):
        host = soong / tool / "linux_glibc_x86_64"
        host.mkdir(parents=True)
        (release_tree / "bin" / tool).rename(host / tool)

    result = run_release(
        release_tree,
        "bramble",
        environment={
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": str(release_tree) if from_top else "",
        },
        dry_run=False,
        target_files_arg=None,
    )

    assert result.returncode == 0, result.stderr
    manifest = _manifest(
        release_tree / f"out/release/release-bramble-{BUILD_NUMBER}",
    )
    assert sorted(manifest) == [
        f"bramble-factory-{BUILD_NUMBER}.zip",
        f"bramble-factory-{BUILD_NUMBER}.zip.sha256sum",
        f"bramble-ota_update-{BUILD_NUMBER}.zip",
        f"bramble-ota_update-{BUILD_NUMBER}.zip.sha256sum",
        f"bramble-target_files-{BUILD_NUMBER}.zip",
    ]
    assert manifest[f"bramble-factory-{BUILD_NUMBER}.zip"] == b"factory-img-zip"
    assert f"bramble-ota_update-{BUILD_NUMBER}.zip" in manifest


@pytest.mark.parametrize(
    ("keep", "signs"),
    (("y", False), ("", True)),
    ids=("y", "empty"),
)
def test_release_honors_keep_target_files(
    release_tree: Path,
    keep: str,
    signs: bool,
) -> None:
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out_dir.mkdir(parents=True)
    signed_target_files = out_dir / f"bramble-target_files-{BUILD_NUMBER}.zip"
    signed_target_files.write_bytes(b"already-signed")
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"KEEP_TARGET_FILES": keep, "OTA_ONLY": "y"},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    assert ("Creating signed targetfiles zip" in result.stdout) == signs
    if not signs:
        assert signed_target_files.read_bytes() == b"already-signed"


FAMILY_VARIABLES = (
    "BOOTLOADER",
    "RADIO",
    "FP4",
    "FP5",
    "FP6",
    "MOTO_BENGAL",
    "MOTO_BLAIR",
    "OTTER",
    "QCOM_FIRMWARE",
    "SKIP_AVB_CUSTOM_KEY",
)


@pytest.mark.parametrize(
    ("device", "expected"),
    (
        ("bramble", {"BOOTLOADER": "test-bootloader", "RADIO": "test-radio"}),
        ("tangorpro", {"BOOTLOADER": "test-bootloader"}),
        ("FP4", {"FP4": "true", "QCOM_FIRMWARE": "true"}),
        ("FP5", {"FP5": "true", "QCOM_FIRMWARE": "true"}),
        ("FP6", {"FP6": "true", "QCOM_FIRMWARE": "true"}),
        ("devon", {"MOTO_BENGAL": "true", "QCOM_FIRMWARE": "true"}),
        ("hawao", {"MOTO_BENGAL": "true", "QCOM_FIRMWARE": "true"}),
        ("rhode", {"MOTO_BENGAL": "true", "QCOM_FIRMWARE": "true"}),
        ("fogos", {"MOTO_BLAIR": "true", "QCOM_FIRMWARE": "true"}),
        ("bangkk", {"MOTO_BLAIR": "true", "QCOM_FIRMWARE": "true"}),
        ("fogo", {"MOTO_BLAIR": "true", "QCOM_FIRMWARE": "true"}),
        (
            "otter",
            {
                "OTTER": "true",
                "QCOM_FIRMWARE": "true",
                "SKIP_AVB_CUSTOM_KEY": "true",
            },
        ),
    ),
)
def test_release_sets_the_device_family_for_the_factory_image_script(
    release_tree: Path,
    device: str,
    expected: dict[str, str],
) -> None:
    (
        release_tree / "device/common/generate-factory-images-common.sh"
    ).write_text(
        f"for name in {' '.join(FAMILY_VARIABLES)}; do\n"
        '  [ -z "${!name+set}" ] || printf "%s=%s\\n" "$name" "${!name}"\n'
        "done > family-environment\n"
        'cat "$DEVICE-img-$BUILD.zip" > "$DEVICE-$VERSION-factory-fake.zip"\n',
    )
    write_target_files_zip(
        release_tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        device,
        environment={
            **{name: "" for name in FAMILY_VARIABLES},
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": "",
        },
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    out_dir = release_tree / f"out/release-{device}-{BUILD_NUMBER}"
    recorded = dict(
        line.split("=", 1)
        for line in (out_dir / "family-environment").read_text().splitlines()
    )
    assert {name: value for name, value in recorded.items() if value} == (
        expected
    )


def test_release_runs_the_factory_image_script_without_zip_bomb_detection(
    release_tree: Path,
) -> None:
    (
        release_tree / "device/common/generate-factory-images-common.sh"
    ).write_text(
        'printf "%s" "$UNZIP_DISABLE_ZIPBOMB_DETECTION" > zipbomb-detection\n'
        'cat "$DEVICE-img-$BUILD.zip" > "$DEVICE-$VERSION-factory-fake.zip"\n',
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (out_dir / "zipbomb-detection").read_text() == "TRUE"


@pytest.mark.parametrize(
    ("environment", "expected"),
    (
        ({"KEYMAPPER": "legacy"}, "keys/bramble/avb_custom_key.img"),
        ({"KEYMAPPER": "id2b"}, "keys/0x2000.avbpubkey"),
        (
            {
                "KEYMAPPER": "static",
                "KEYMAP_FILE": str(ID2B_KEYMAP),
            },
            "keys/0x2000.avbpubkey",
        ),
    ),
    ids=("legacy", "id2b", "static"),
)
def test_release_passes_the_avb_custom_key_to_the_factory_image_script(
    release_tree: Path,
    environment: dict[str, str],
    expected: str,
) -> None:
    (
        release_tree / "device/common/generate-factory-images-common.sh"
    ).write_text(
        'printf "%s" "${AVB_CUSTOM_KEY:-}" > avb-custom-key\n'
        'cat "$DEVICE-img-$BUILD.zip"'
        ' > "$DEVICE-$VERSION-factory-fake.zip"\n',
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={**environment, "OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Running: bash -c" in result.stderr
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (out_dir / "avb-custom-key").read_text() == (
        f"{release_tree}/{expected}"
    )


@pytest.mark.parametrize(
    ("device", "environment", "refused"),
    (
        ("bramble", {}, True),
        ("bramble", {"OTA_ONLY": "y"}, False),
        ("bramble", {"SKIP_AVB_CUSTOM_KEY": "true"}, True),
        ("devon", {"OTA_ONLY": "y", "AVB_ROLLBACK_INDEX_OVERRIDE": "42"}, True),
        ("otter", {}, False),
    ),
    ids=("factory-image", "ota-only", "environment-skip", "rollback", "otter"),
)
def test_release_refuses_a_missing_avb_custom_key(
    release_tree: Path,
    device: str,
    environment: dict[str, str],
    refused: bool,
) -> None:
    key = release_tree / f"keys/{device}/avb_custom_key.img"
    key.unlink(missing_ok=True)
    write_target_files_zip(
        release_tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        device,
        environment={
            "KEYMAPPER": "legacy",
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": "",
            **environment,
        },
        dry_run=False,
    )

    if refused:
        assert result.returncode != 0
        assert f"AVB custom key {key} does not exist" in result.stderr
        assert "sign_target_files_apks" not in result.stderr
    else:
        assert result.returncode == 0, result.stderr


def test_release_records_its_output_in_exec_log_path(
    release_tree: Path,
) -> None:
    install_executable(
        release_tree / "bin" / "sign_target_files_apks",
        "#!/bin/sh\necho tool-stdout\necho tool-stderr >&2\n"
        'eval "out=\\${$#}"\nprintf %s signed > "$out"\n',
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    exec_log = release_tree / "exec.log"

    result = run_release(
        release_tree,
        "bramble",
        environment={"EXEC_LOG_PATH": str(exec_log)},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    log = exec_log.read_text()
    for line in ("Command: ", "Running: ", "tool-stdout", "tool-stderr"):
        assert line in log
    assert "tool-stdout" in result.stdout
    assert "tool-stderr" in result.stderr


def test_release_fails_with_the_factory_image_script_status(
    release_tree: Path,
) -> None:
    (
        release_tree / "device/common/generate-factory-images-common.sh"
    ).write_text("false\ntouch kept-going\n(exit 7)\n")
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=False,
    )

    assert result.returncode == 7, result.stderr
    assert "Traceback" not in result.stderr
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (out_dir / "kept-going").exists()


def test_release_normalizes_key_dir_for_child_processes(
    release_tree: Path,
) -> None:
    """
    payload_signer.py reads KEY_DIR from the environment it inherits
    through ota_from_target_files, and strips it from key paths, which
    needs exactly one trailing slash.
    """
    install_executable(
        release_tree / "bin" / "ota_from_target_files",
        '#!/bin/sh\neval "out=\\${$#}"\n'
        'printf "KEY_DIR=[%s]" "$KEY_DIR" > "$out"\n',
    )
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out_dir.mkdir(parents=True)
    (out_dir / f"bramble-target_files-{BUILD_NUMBER}.zip").write_bytes(
        b"already-signed",
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={
            "KEY_DIR": "/some/key/dir",
            "KEEP_TARGET_FILES": "y",
            "OTA_ONLY": "y",
        },
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    ota_zip = out_dir / f"bramble-ota_update-{BUILD_NUMBER}.zip"
    assert ota_zip.read_text() == "KEY_DIR=[/some/key/dir/]"


def test_release_rejects_unrecognized_device_by_default(
    release_tree: Path,
) -> None:
    device = "unlisteddevice"
    write_target_files_zip(
        release_tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        device,
        dry_run=False,
        environment={"KEYMAPPER": "legacy"},
    )

    assert result.returncode != 0
    assert f"Unsupported device {device}" in result.stderr
    assert not (release_tree / f"out/release-{device}-{BUILD_NUMBER}").exists()


def test_release_reports_a_wrong_argument_count_as_release_sh_does(
    release_tree: Path,
) -> None:
    result = run(
        [SCRIPTS_DIR / "release.sh", "bramble", "--help", "-x"],
        cwd=release_tree,
        env={"BUILD_NUMBER": BUILD_NUMBER},
        check=False,
    )

    assert result.returncode == 1
    assert "error: incorrect number of arguments, please try again" in (
        result.stderr
    )
    assert "device [target-files.zip]" in result.stdout


def test_release_prints_its_usage_on_stdout(release_tree: Path) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"BUILD_NUMBER": ""},
    )

    assert result.returncode == 1
    assert "BUILD_NUMBER not set" in result.stderr
    assert "device [target-files.zip]" in result.stdout


def test_release_orchestration_refuses_a_bash_keymapper_file(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"KEYMAPPER_FILE": str(release_tree / "keymapper.sh")},
    )

    assert result.returncode == 1
    assert "is not a Python keymapper (*.py)" in result.stderr
    assert "Traceback" not in result.stderr


_PLUGIN_KEYMAPPER = """
from signing.keymap import Keymapper


class PluginKeymapper(Keymapper):
    def key(self, key_type, key_name, device="", *, suffix="", key_suffix=""):
        if key_type not in ("avb", "apex_payload"):
            suffix = ""
        return f"plugin/{key_type}-{key_name.replace('/', '_')}{suffix}"

    def is_per_device(self, key_type, key_name):
        return False

    def rows(self, devices):
        return ()


def create_keymapper(environment, metadata, *, extra_devices):
    return PluginKeymapper()
"""


def test_release_orchestration_resolves_keys_through_a_keymapper_file(
    release_tree: Path,
) -> None:
    keymapper_file = release_tree / "keymapper.plugin.py"
    keymapper_file.write_text(_PLUGIN_KEYMAPPER)

    result = run_release(
        release_tree,
        "bramble",
        environment={"KEYMAPPER_FILE": str(keymapper_file)},
    )

    assert result.returncode == 0, result.stderr
    signing_command = _command_line(result.stderr, "sign_target_files_apks")
    assert "--avb_vbmeta_key keys/plugin/avb-vbmeta.pem" in signing_command
    assert "--package_key keys/plugin/other-ota" in _command_line(
        result.stderr,
        "ota_from_target_files",
    )


@pytest.mark.parametrize(
    ("base", "algorithm"),
    (
        ("Id2bKeymapper", "SHA256_RSA2048"),
        ("LegacyKeymapper", "SHA256_RSA4096"),
    ),
)
def test_release_takes_the_avb_rule_of_the_keymapper_file_keymapper(
    release_tree: Path,
    base: str,
    algorithm: str,
) -> None:
    keymapper_file = release_tree / "keymapper.plugin.py"
    keymapper_file.write_text(
        f"from signing.keymap import {base}\n"
        "\n"
        "\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        f"    return {base}(metadata)\n",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={
            "KEYMAPPER_FILE": str(keymapper_file),
            "RSA_KEY_SIZE": "2048",
        },
    )

    assert result.returncode == 0, result.stderr
    assert f"--avb_vbmeta_algorithm {algorithm}" in _command_line(
        result.stderr,
        "sign_target_files_apks",
    )


@pytest.mark.parametrize("keymapper", ("legacy", "id2b"))
def test_release_allows_extra_device_via_environment(
    release_tree: Path,
    keymapper: str,
) -> None:
    device = "unlisteddevice"
    write_target_files_zip(
        release_tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
    )
    mapper = load_keymapper(
        {"KEYMAPPER": keymapper, "EXTRA_DEVICES": device},
        load_metadata(TEST_METADATA),
    )
    (release_tree / "keys" / mapper.avb_custom_key(device)).parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    (release_tree / "keys" / mapper.avb_custom_key(device)).touch()

    result = run_release(
        release_tree,
        device,
        environment={
            "KEYMAPPER": keymapper,
            "EXTRA_DEVICES": device,
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": "",
        },
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    out = release_tree / f"out/release-{device}-{BUILD_NUMBER}"
    assert (out / f"{device}-ota_update-{BUILD_NUMBER}.zip").is_file()
    assert (out / f"{device}-factory-{BUILD_NUMBER}.zip").is_file()
    signing_command = result.stderr.split("sign_target_files_apks", 1)[1]
    if keymapper == "legacy":
        assert f"--avb_vbmeta_key keys/{device}/avb.pem" in signing_command
    else:
        assert re.search(
            r"--avb_vbmeta_key keys/0x[0-9a-f]+\.pem",
            signing_command,
        )


def test_release_vendor_keymapper_sets_payload_signature_size(
    release_tree: Path,
) -> None:
    """
    The vendor sets KEYMAPPER before the keymapper sets
    PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE, so a keymapper chosen only by
    the vendor still reserves room for a 4096-bit payload signature.
    """
    result = run_release(
        release_tree,
        "bramble",
        environment={
            **PKCS11_ENVIRONMENT,
            "KEYMAPPER": "",
            "PKCS11_VENDOR": "softhsm",
            "SOFTHSM_LOGS_DIR": str(release_tree / "logs"),
        },
    )

    assert result.returncode == 0, result.stderr
    assert "--payload_signer_maximum_signature_size 512" in result.stderr


def test_release_appends_extra_signing_args_after_the_threads(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            "EXTRA_SIGNING_ARGS": "--threads 2 -k extra/path=other/path",
        },
    )

    assert result.returncode == 0, result.stderr
    signing_command = _command_line(result.stderr, "sign_target_files_apks")
    assert "--threads 8 --threads 2 -k extra/path=other/path" in (
        signing_command
    )


def test_release_passes_the_signing_helpers(release_tree: Path) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment=PKCS11_ENVIRONMENT,
    )

    assert result.returncode == 0, result.stderr
    assert "/signing_helper.py" in _command_line(
        result.stderr,
        "sign_target_files_apks",
    )
    assert "/payload_signer.py" in _command_line(
        result.stderr,
        "ota_from_target_files",
    )
    assert "test-only" not in result.stdout
    assert "test-only" not in result.stderr


def test_release_stops_when_target_files_signing_fails(
    release_tree: Path,
) -> None:
    install_executable(
        release_tree / "bin" / "sign_target_files_apks",
        "#!/bin/sh\nexit 23\n",
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": ""},
        dry_run=False,
    )

    assert result.returncode != 0
    assert "Running:" in result.stderr
    assert "sign_target_files_apks" in result.stderr
    assert "Creating OTA update zip" not in result.stdout
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert not list(out.glob("*.zip"))


def test_release_supports_otatest(release_tree: Path) -> None:
    otatest = "2026081501"
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={
            "OTA_ONLY": "",
            "OTATEST": otatest,
            "ANDROID_BUILD_TOP": "",
        },
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    ota = out / f"bramble-ota_update-{otatest}.zip"
    assert ota.read_bytes() == b"ota-update-zip"
    assert (
        out / f"bramble-ota_update-{otatest}.zip.sha256sum"
    ).read_text() == (f"{sha256(ota)}  bramble-ota_update-{otatest}.zip\n")


@pytest.mark.parametrize("device", ("bramble", "FP5"))
def test_release_rejects_rollback_override_on_unsupported_device(
    release_tree: Path,
    device: str,
) -> None:
    result = run_release(
        release_tree,
        device,
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
    )

    assert result.returncode == 1
    assert (
        f"Unsupported device for AVB Rollback Index override: {device}"
        in result.stdout
    )
    assert "/bin/sign_target_files_apks" not in result.stderr


@pytest.mark.parametrize(
    ("device", "environment"),
    (
        ("bramble", {}),
        (
            "bramble",
            PKCS11_ENVIRONMENT,
        ),
        ("devon", {"AVB_ROLLBACK_INDEX_OVERRIDE": "42"}),
        ("bramble", {"KEY_SUFFIX": ""}),
        ("bramble", {"KEY_SUFFIX": ".key"}),
        ("bramble", {"KEYMAPPER": "legacy", "KEY_SUFFIX": ".key"}),
        ("bramble", {"BUILD_NUMBER": "eng.user"}),
    ),
    ids=(
        "plaintext",
        "pkcs11",
        "rollback-override",
        "empty-key-suffix",
        "key-suffix",
        "legacy-key-suffix",
        "text-build-number",
    ),
)
def test_release_dry_run_renders_the_expected_commands(
    release_tree: Path,
    device: str,
    environment: dict[str, str],
    request: pytest.FixtureRequest,
) -> None:
    """
    DRY_RUN output is the operator's preview of what a live run executes,
    so every rendered command is compared in full, argument order
    included.
    """
    name = parameter_id(request)

    result = run_release(release_tree, device, environment=environment)

    assert result.returncode == 0, result.stderr
    assert (
        result.stdout
        == (DRY_RUN_FIXTURES / f"release-{name}.stdout").read_text()
    )
    assert (
        normalize_dry_run(result.stderr, release_tree)
        == (DRY_RUN_FIXTURES / f"release-{name}.stderr").read_text()
    )


@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_release_removes_its_temporaries(
    release_tree: Path,
    fails: bool,
) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    if fails:
        install_executable(
            release_tree / "bin" / "sign_target_files_apks",
            "#!/bin/sh\nexit 23\n",
        )

    result = run_release(
        release_tree,
        "bramble",
        environment=PKCS11_ENVIRONMENT,
        dry_run=False,
    )

    assert (result.returncode != 0) == fails, result.stderr
    assert list((release_tree / "tmp").iterdir()) == []


def test_release_reports_an_unsupported_vendor(release_tree: Path) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"PKCS11_VENDOR": "acme"},
    )

    assert result.returncode == 1
    assert (
        "error: PKCS11_VENDOR='acme' is not supported. Set PKCS11_VENDOR to "
        "yubihsm or softhsm\n"
    ) in result.stderr


@pytest.mark.parametrize(
    "signum",
    (signal.SIGTERM, signal.SIGHUP),
    ids=("sigterm", "sighup"),
)
def test_python_release_cleans_up_when_terminated(
    release_tree: Path,
    signum: signal.Signals,
) -> None:
    started = release_tree / "started"
    install_executable(
        release_tree / "bin" / "sign_target_files_apks",
        f'#!/bin/sh\ntouch "{started}"\nsleep 30\n',
    )
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    tmpdir = release_tree / "tmp"
    tmpdir.mkdir(exist_ok=True)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "signing",
            "release-orchestrate",
            "release.sh",
            "bramble",
            f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        ],
        cwd=release_tree,
        env={
            **os.environ,
            **PKCS11_ENVIRONMENT,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "TMPDIR": str(tmpdir),
            "BUILD_NUMBER": BUILD_NUMBER,
            "KEYMAPPER": "id2b",
            "OTA_ONLY": "y",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=default_signal_dispositions,
    )
    deadline = time.monotonic() + 30
    while not started.exists():
        assert time.monotonic() < deadline
        assert process.poll() is None
        time.sleep(0.05)
    assert list(tmpdir.glob("signing.*"))

    process.send_signal(signum)

    assert process.wait(timeout=30) == 128 + signum
    assert not list(tmpdir.glob("signing.*"))


@pytest.mark.parametrize("second", ("SIGTERM", "SIGINT", "between"))
def test_python_release_finishes_its_cleanup_after_a_second_signal(
    tmp_path: Path,
    second: str,
) -> None:
    cleaned = tmp_path / "cleaned"
    script = """
import contextlib, os, signal, sys
from pathlib import Path
from signing import release_orchestration
from signing.release_execution import Transcript
from signing.release_orchestration import ReleaseOrchestrator
exit_on_signals = release_orchestration.exit_on_signals
@contextlib.contextmanager
def signal_after_exit_on_signals():
    try:
        with exit_on_signals():
            yield
    finally:
        os.kill(os.getpid(), signal.SIGTERM)
if sys.argv[2] == "between":
    release_orchestration.exit_on_signals = signal_after_exit_on_signals
release = ReleaseOrchestrator.__new__(ReleaseOrchestrator)
release.transcript = Transcript()
def cleanup():
    if sys.argv[2] != "between":
        os.kill(os.getpid(), getattr(signal, sys.argv[2]))
    Path(sys.argv[1]).write_text("cleaned")
def steps():
    release._resources.callback(cleanup)
    os.kill(os.getpid(), signal.SIGTERM)
release._run_steps = steps
sys.exit(release.run())
"""

    result = subprocess.run(
        [sys.executable, "-c", script, cleaned, second],
        env={**os.environ, "PYTHONPATH": str(SCRIPTS_DIR)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        preexec_fn=default_signal_dispositions,
    )

    assert result.returncode == (130 if second == "SIGINT" else -15)
    assert "Traceback" not in result.stderr
    assert cleaned.read_text() == "cleaned"


def test_release_requires_yubihsm_credentials(release_tree: Path) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"PKCS11_VENDOR": "yubihsm"},
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "Using keymapper: static\n"
        "error: YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD not set\n"
    )


def test_release_dry_run_stops_without_a_release_tool(
    release_tree: Path,
) -> None:
    (release_tree / "bin" / "sign_target_files_apks").unlink()

    result = run_release(release_tree, "bramble")

    assert result.returncode == 1
    assert (
        "error: couldn't find releasetools binary 'sign_target_files_apks' "
        f"under {release_tree / 'bin'}\n"
    ) in result.stderr
    assert "ota_from_target_files" not in result.stderr


@pytest.mark.parametrize("dry_run", (True, False), ids=("dry-run", "release"))
def test_release_stops_before_signing_without_the_factory_variables(
    release_tree: Path,
    dry_run: bool,
) -> None:
    (release_tree / "device/common/clear-factory-images-variables.sh").unlink()
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=dry_run,
    )

    assert result.returncode == 1
    assert "clear-factory-images-variables.sh" in result.stderr
    assert "sign_target_files_apks" not in result.stderr
    assert not (release_tree / f"out/release-bramble-{BUILD_NUMBER}").exists()


def test_ota_only_release_needs_no_factory_variables(
    release_tree: Path,
) -> None:
    (release_tree / "device/common/clear-factory-images-variables.sh").unlink()
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(release_tree, "bramble", dry_run=False)

    assert result.returncode == 0, result.stderr
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (out / f"bramble-target_files-{BUILD_NUMBER}.zip").is_file()
    assert "Not creating factory image due to OTA_ONLY=y" in result.stdout


def test_release_session_treats_an_empty_tmpdir_as_unset(
    release_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parents: list[str | None] = []

    def mkdtemp(*, prefix: str, dir: str | None) -> str:
        parents.append(dir)
        raise RuntimeError("stop")

    monkeypatch.setattr(
        "signing.release_orchestration.tempfile.mkdtemp",
        mkdtemp,
    )
    session = ReleaseOrchestrator(
        {**PKCS11_ENVIRONMENT, "KEYMAPPER": "id2b", "TMPDIR": ""},
        cwd=release_tree,
        metadata=load_metadata(TEST_METADATA),
        program="release.sh",
        device="bramble",
        target_files_arg=None,
    )

    with pytest.raises(Abort):
        session.prepare_signing(command_argv=[])

    assert parents == ["/dev/shm"]


@pytest.mark.parametrize("initialized", (False, True))
def test_release_session_finalizes_then_cleans_up_its_vendor(
    release_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    initialized: bool,
) -> None:
    calls: list[tuple[str, object]] = []
    session: ReleaseOrchestrator

    class Vendor:
        def initialize_release(
            self,
            environment: dict[str, str],
            **options: object,
        ) -> None:
            calls.append(("initialize_release", options["build_number"]))

        def finalize_release(
            self,
            environment: dict[str, str],
            **options: object,
        ) -> None:
            assert session.tmpdir is not None
            assert session.tmpdir.is_dir()
            calls.append(("finalize_release", options["record_finish"]))

        def cleanup(
            self,
            environment: dict[str, str],
            *,
            inherited: dict[str, str],
        ) -> None:
            calls.append(
                ("cleanup", inherited is session.inherited_environment),
            )

    monkeypatch.setattr("signing.sign_environment.load_vendor", stub(Vendor()))
    monkeypatch.setattr(
        "signing.sign_environment.maybe_initialize_vendor",
        stub(None),
    )
    environment = {
        **PKCS11_ENVIRONMENT,
        "KEYMAPPER": "id2b",
        "TMPDIR": str(release_tree),
        "BUILD_NUMBER": BUILD_NUMBER,
    }
    if initialized:
        environment["PKCS11_VENDOR_INITIALIZED_RELEASE"] = "y"
    session = ReleaseOrchestrator(
        environment,
        cwd=release_tree,
        metadata=load_metadata(TEST_METADATA),
        program="release.sh",
        device="bramble",
        target_files_arg=None,
    )

    def run_steps() -> None:
        session.prepare_signing(command_argv=[])
        assert environment["PKCS11_VENDOR_INITIALIZED_RELEASE"] == "y"

    monkeypatch.setattr(session, "_run_steps", run_steps)
    assert session.run() == 0

    expected: list[tuple[str, object]] = []
    if not initialized:
        expected.append(("initialize_release", BUILD_NUMBER))
    expected += [("finalize_release", not initialized), ("cleanup", True)]
    assert calls == expected
    assert session.tmpdir is not None
    assert not session.tmpdir.exists()


@pytest.mark.parametrize(
    ("environment", "algorithm"),
    (
        ({"KEYMAPPER": "id2b"}, "SHA256_RSA4096"),
        ({"KEYMAPPER": "legacy", "RSA_KEY_SIZE": "2048"}, "SHA256_RSA4096"),
        ({"KEYMAPPER": "legacy", "AVB_RSA_KEY_SIZE": "2048"}, "SHA256_RSA2048"),
        ({"KEYMAPPER": "id2b", "RSA_KEY_SIZE": "2048"}, "SHA256_RSA2048"),
        (
            {
                "KEYMAPPER": "id2b",
                "AVB_RSA_KEY_SIZE": "2048",
                "RSA_KEY_SIZE": "3072",
            },
            "SHA256_RSA2048",
        ),
        (
            {
                "KEYMAPPER": "id2b",
                "AVB_RSA_KEY_SIZE": "",
                "RSA_KEY_SIZE": "2048",
            },
            "SHA256_RSA2048",
        ),
        (
            {
                "KEYMAPPER": "id2b",
                "PKCS11_MODULE": "x",
                "AVB_RSA_KEY_SIZE": "2048",
            },
            "SHA256_RSA4096",
        ),
        (
            {"KEYMAPPER": "id2b", "PKCS11_MODULE": "x", "RSA_KEY_SIZE": "2048"},
            "SHA256_RSA2048",
        ),
        (
            {
                "KEYMAPPER": "legacy",
                "PKCS11_MODULE": "x",
                "RSA_KEY_SIZE": "2048",
                "AVB_RSA_KEY_SIZE": "3072",
            },
            "SHA256_RSA3072",
        ),
    ),
)
def test_avb_algorithm_is_the_one_bash_picks(
    environment: dict[str, str],
    algorithm: str,
) -> None:
    keymapper = load_keymapper(environment, load_metadata(TEST_METADATA))

    assert avb_algorithm_for(environment, keymapper) == algorithm


def test_release_passes_extra_ota_args_to_the_ota_tool(
    release_tree: Path,
) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"EXTRA_OTA_ARGS": "--x"},
    )

    assert result.returncode == 0, result.stderr
    assert " --x " in _command_line(result.stderr, "ota_from_target_files")


def test_release_with_an_id2b_keymap_file_runs_the_id2b_commands(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            "KEYMAPPER": "static",
            "KEYMAP_FILE": str(ID2B_KEYMAP),
        },
    )

    assert result.returncode == 0, result.stderr
    id2b = (DRY_RUN_FIXTURES / "release-plaintext.stderr").read_text()
    assert [
        line
        for line in normalize_dry_run(result.stderr, release_tree).splitlines()
        if "/bin/" in line
    ] == [line for line in id2b.splitlines() if "/bin/" in line]


def _signing_arguments(stderr: str) -> list[str]:
    line = _command_line(stderr, "sign_target_files_apks")
    return shlex.split(re.sub(r"/signing\.\w+/", "/signing.X/", line))


def test_release_leaves_out_the_metadata_placeholders(
    release_tree: Path,
    tmp_path: Path,
) -> None:
    from test_generate_keymap import metadata_with_placeholders

    metadata = metadata_with_placeholders(
        TEST_METADATA,
        tmp_path / "metadata.py",
    )

    full = run_release(release_tree, "bramble")
    placeholders = run_release(
        release_tree,
        "bramble",
        environment={"METADATA_FILE": str(metadata)},
    )

    assert full.returncode == 0, full.stderr
    assert placeholders.returncode == 0, placeholders.stderr
    left_out = {
        "--extra_apks": ("com.android.adservices.apex=",),
        "--extra_apex_payload_key": ("com.android.adservices.apex=",),
        "-k": (
            "packages/modules/Wifi/OsuLogin/certs/"
            "com.android.hotspot2.osulogin=",
            "com.google.android.apps.photos=",
        ),
    }
    arguments = _signing_arguments(full.stderr)
    expected: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        value = arguments[index + 1] if index + 1 < len(arguments) else ""
        if argument.startswith("--avb_dtbo_") or (
            argument in left_out and value.startswith(left_out[argument])
        ):
            index += 2
            continue
        expected.append(argument)
        index += 1
    assert len(arguments) - len(expected) == 12
    assert _signing_arguments(placeholders.stderr) == expected


def test_release_goes_on_without_an_unwritable_exec_log(
    release_tree: Path,
) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    exec_log = release_tree / "missing" / "exec.log"

    result = run_release(
        release_tree,
        "bramble",
        environment={"EXEC_LOG_PATH": str(exec_log)},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"cannot write EXEC_LOG_PATH {exec_log}" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("status", (0, 23))
def test_run_release_tool_prints_and_runs_like_print_and_run(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    status: int,
) -> None:
    from signing.release_execution import run_release_tool

    tool = tmp_path / "tool"
    install_executable(
        tool,
        f'#!/bin/sh\neval "out=\\${{$#}}"\nprintf %s "$*" > "$out"\n'
        f"exit {status}\n",
    )
    out = tmp_path / "out.zip"

    argv = [str(tool), "-k", "keys/0x2000", "in.zip", str(out)]
    assert run_release_tool(argv) == status
    assert out.read_text() == f"-k keys/0x2000 in.zip {out}"
    assert capfd.readouterr().err == (
        f"Running: {tool} -k keys/0x2000 in.zip {out}\n"
    )


@pytest.mark.parametrize(
    "value",
    (
        "",
        "  --verbose  ",
        "a b\tc",
        "--extra_apks Foo.apk=keys/my\\ key",
        "a\\\\b c",
        "trailing\\",
        "joined\\\nline next",
        "first line\nsecond line",
        "\\ leading space",
    ),
)
def test_read_words_matches_read_a(value: str) -> None:
    bash = run(
        [
            "bash",
            "-c",
            'read -a words <<< "$1"; for w in "${words[@]}"; do '
            'printf "%s\\0" "$w"; done',
            "read-words",
            value,
        ],
    )

    expected = bash.stdout.split("\0")[:-1]
    assert read_words(value) == expected


def test_a_plaintext_release_loads_no_cryptography_package() -> None:
    result = run(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "import signing.cli\n"
            "import signing.release_orchestration\n"
            "print(sorted(name for name in sys.modules "
            "if name.split('.')[0] in ('cryptography', 'yubihsm')))",
        ],
        env={"PYTHONPATH": str(SCRIPTS_DIR)},
    )

    assert result.stdout == "[]\n"


def test_release_dry_run_writes_no_files(release_tree: Path) -> None:
    before = _manifest(release_tree)

    result = run_release(release_tree, "bramble", environment={"OTA_ONLY": ""})

    assert result.returncode == 0, result.stderr
    assert _manifest(release_tree) == before


def test_release_signs_plain_keys_without_its_tmpdir(
    release_tree: Path,
) -> None:
    write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"TMPDIR": str(release_tree / "missing")},
        dry_run=False,
    )

    assert result.returncode == 0, result.stderr


def test_release_refuses_a_pkcs11_module_without_a_vendor(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"PKCS11_MODULE": "/dev/null", "PKCS11_PIN": "test-only"},
    )

    assert result.returncode == 1
    assert "PKCS11_MODULE needs PKCS11_VENDOR" in result.stderr
    assert "Traceback" not in result.stderr
