#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from conftest import (
    SCRIPTS_DIR,
    TEST_METADATA,
    default_signal_dispositions,
    run,
    run_cli,
    sha256,
)
from signing.keymap import load_keymapper
from signing.metadata import load_metadata
from signing.release_orchestration import (
    ReleaseAbort,
    ReleaseOrchestrator,
    read_words,
)


@pytest.fixture(autouse=True)
def _small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


BUILD_NUMBER = "2026081500"
ROLLBACK_DEVICES = ("devon", "hawao", "rhode", "fogos", "bangkk", "fogo")

_PKCS11_CONFIG_PATH = re.compile(r"--pkcs11_config \S+")

PKCS11_ENVIRONMENT = {
    "PKCS11_MODULE": "/dev/null",
    "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
    "PKCS11_PIN": "test-only",
}

implementations = pytest.mark.parametrize(
    "python",
    (False, True),
    ids=("bash", "python"),
)


def _normalize_rendered_commands(text: str) -> str:
    return _PKCS11_CONFIG_PATH.sub("--pkcs11_config <normalized>", text)


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


def _write_target_files_zip(path: Path) -> None:
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


def _install_tool(path: Path, script: str) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _install_fake_release_tools(root: Path) -> None:
    for name, content in (
        ("sign_target_files_apks", "signed-target-files"),
        ("ota_from_target_files", "ota-update-zip"),
        ("img_from_target_files", "factory-img-zip"),
    ):
        _install_tool(
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
    python: bool = False,
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
        python: Whether to run `python3 -m signing release-orchestrate` in
            place of release.sh.
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
    if python:
        variables["PYTHONPATH"] = str(SCRIPTS_DIR)
        argv: list[str | Path] = [
            "release-orchestrate",
            "release.sh",
            device,
        ]
    else:
        argv = [SCRIPTS_DIR / "release.sh", device]
    if target_files_arg == "_default_":
        argv.append(f"calyx_{device}-target_files-{BUILD_NUMBER}.zip")
    elif target_files_arg is not None:
        argv.append(target_files_arg)
    runner = run_cli if python else run
    return runner(argv, cwd=release_tree, env=variables, check=False)


def _command_line(stderr: str, tool: str) -> str:
    return next(line for line in stderr.splitlines() if f"/bin/{tool}" in line)


def strip_bash_only_keymapper_noise(stderr: str) -> str:
    """
    Bash's id2b keymapper warns about the unpopulated devices array, which
    this fixture tree never sets, and Id2bKeymapper has no such check.
    """
    lines = stderr.splitlines(keepends=True)
    return "".join(
        line
        for line in lines
        if not line.startswith("cat: ")
        and "Keymapper initialization cannot validate" not in line
        and "because devices array is not yet populated" not in line
    )


def normalize_command_line(stderr: str) -> str:
    return re.sub(
        r"^Command: \S+ ",
        "Command: <script> ",
        stderr,
        flags=re.MULTILINE,
    )


@implementations
def test_release_dry_run_builds_plaintext_command_graph(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(release_tree, "bramble", python=python)

    assert result.returncode == 0, result.stderr
    commands = result.stderr
    assert "/bin/sign_target_files_apks" in commands
    assert "/bin/ota_from_target_files" in commands
    assert "--package_key keys/0x2000" in commands
    assert "--avb_vbmeta_key keys/0x2000.pem" in commands
    assert "--avb_vbmeta_algorithm SHA256_RSA4096" in commands
    assert (
        "-k build/make/target/product/security/platform=keys/0x1103" in commands
    )
    assert "--payload_signer_maximum_signature_size 512" in commands
    assert "Not creating factory image due to OTA_ONLY=y" in result.stdout


def test_python_release_names_the_script_it_ran_as(release_tree: Path) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"USE_PYTHON_RELEASE_ORCHESTRATION": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert f"Command: {SCRIPTS_DIR / 'release.sh'} bramble " in result.stderr


def test_release_dry_run_leaves_the_files_release_sh_leaves(
    tmp_path: Path,
) -> None:
    created: dict[str, list[str]] = {}
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        before = set(_manifest(tree))
        result = run_release(
            tree,
            "bramble",
            environment={"OTA_ONLY": ""},
            python=python,
        )
        assert result.returncode == 0, result.stderr
        created[label] = sorted(set(_manifest(tree)) - before)

    assert created["python"] == created["bash"]


def test_release_orchestration_tool_execution_matches_bash_bytes(
    tmp_path: Path,
) -> None:
    environment = {"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""}
    manifests: dict[str, dict[str, bytes]] = {}
    steps: dict[str, list[str]] = {}
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        _write_target_files_zip(
            tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        )
        result = run_release(
            tree,
            "bramble",
            environment=environment,
            dry_run=False,
            python=python,
        )
        assert result.returncode == 0, result.stderr
        manifests[label] = _manifest(
            tree / f"out/release-bramble-{BUILD_NUMBER}",
        )
        steps[label] = [
            Path(line.split()[1]).name
            for line in result.stderr.splitlines()
            if line.startswith("Running: ")
        ]

    assert manifests["python"] == manifests["bash"]
    assert steps["python"] == steps["bash"]
    bash = manifests["bash"]
    assert bash[f"bramble-factory-{BUILD_NUMBER}.zip"] == b"factory-img-zip"
    assert f"bramble-img-{BUILD_NUMBER}.zip" not in bash
    assert bash[f"bramble-ota_update-{BUILD_NUMBER}.zip"] == b"ota-update-zip"
    assert bash[f"bramble-factory-{BUILD_NUMBER}.zip.sha256sum"].endswith(
        f"  bramble-factory-{BUILD_NUMBER}.zip\n".encode(),
    )
    assert bash[f"bramble-ota_update-{BUILD_NUMBER}.zip.sha256sum"].endswith(
        f"  bramble-ota_update-{BUILD_NUMBER}.zip\n".encode(),
    )


def test_release_orchestration_skip_signing_matches_bash_bytes(
    tmp_path: Path,
) -> None:
    environment = {"OTA_ONLY": "", "ANDROID_BUILD_TOP": "", "SKIP_SIGNING": "y"}
    manifests: dict[str, dict[str, bytes]] = {}
    outputs: dict[str, str] = {}
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        unsigned = tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip"
        _write_target_files_zip(unsigned)
        result = run_release(
            tree,
            "bramble",
            environment=environment,
            dry_run=False,
            python=python,
        )
        assert result.returncode == 0, result.stderr
        assert "sign_target_files_apks" not in result.stderr
        assert "ota_from_target_files" not in result.stderr
        out = tree / f"out/release-bramble-{BUILD_NUMBER}"
        manifests[label] = _manifest(out)
        outputs[label] = result.stdout
        assert (
            out / f"bramble-target_files-{BUILD_NUMBER}.zip"
        ).read_bytes() == unsigned.read_bytes()

    assert manifests["python"] == manifests["bash"]
    assert all(
        "Skipping signing and OTA generation" in output
        for output in outputs.values()
    )
    assert f"bramble-factory-{BUILD_NUMBER}.zip" in manifests["bash"]


def test_release_orchestration_skip_signing_dry_run_keeps_target_files(
    tmp_path: Path,
) -> None:
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        _write_target_files_zip(
            tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        )
        out = tree / f"out/release-bramble-{BUILD_NUMBER}"
        out.mkdir(parents=True)
        signed = out / f"bramble-target_files-{BUILD_NUMBER}.zip"
        signed.write_bytes(b"signed earlier")

        result = run_release(
            tree,
            "bramble",
            environment={"OTA_ONLY": "", "SKIP_SIGNING": "y"},
            python=python,
        )

        assert result.returncode == 0, result.stderr
        assert signed.read_bytes() == b"signed earlier", label


@pytest.mark.parametrize(
    ("device", "environment"),
    (
        ("bramble", {}),
        ("devon", {"OTA_ONLY": "y", "AVB_ROLLBACK_INDEX_OVERRIDE": "42"}),
    ),
    ids=("factory-image", "rollback"),
)
def test_release_orchestration_refuses_a_missing_avb_custom_key(
    tmp_path: Path,
    device: str,
    environment: dict[str, str],
) -> None:
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        key = tree / f"keys/{device}/avb_custom_key.img"
        key.unlink(missing_ok=True)
        _write_target_files_zip(
            tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
        )

        result = run_release(
            tree,
            device,
            environment={
                "KEYMAPPER": "legacy",
                "OTA_ONLY": "",
                "ANDROID_BUILD_TOP": "",
                **environment,
            },
            dry_run=False,
            python=python,
        )

        assert result.returncode != 0, label
        assert f"AVB custom key {key} does not exist" in result.stderr, label
        assert "sign_target_files_apks" not in result.stderr, label


@pytest.mark.parametrize(
    ("device", "environment"),
    (("bramble", {"OTA_ONLY": "y"}), ("otter", {})),
    ids=("ota-only", "otter"),
)
def test_release_orchestration_releases_without_an_avb_custom_key_it_skips(
    tmp_path: Path,
    device: str,
    environment: dict[str, str],
) -> None:
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        (tree / f"keys/{device}/avb_custom_key.img").unlink(missing_ok=True)
        _write_target_files_zip(
            tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
        )

        result = run_release(
            tree,
            device,
            environment={
                "KEYMAPPER": "legacy",
                "OTA_ONLY": "",
                "ANDROID_BUILD_TOP": "",
                **environment,
            },
            dry_run=False,
            python=python,
        )

        assert result.returncode == 0, (label, result.stderr)


def test_release_orchestration_ignores_an_inherited_skip_avb_custom_key(
    tmp_path: Path,
) -> None:
    tree = make_release_tree(tmp_path)
    key = tree / "keys/bramble/avb_custom_key.img"
    key.unlink()
    _write_target_files_zip(
        tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        tree,
        "bramble",
        environment={
            "KEYMAPPER": "legacy",
            "OTA_ONLY": "",
            "ANDROID_BUILD_TOP": "",
            "SKIP_AVB_CUSTOM_KEY": "true",
        },
        dry_run=False,
        python=True,
    )

    assert result.returncode != 0
    assert f"AVB custom key {key} does not exist" in result.stderr


def test_release_orchestration_skip_signing_honors_ota_only(
    tmp_path: Path,
) -> None:
    outputs: dict[str, str] = {}
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        _write_target_files_zip(
            tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        )
        result = run_release(
            tree,
            "bramble",
            environment={"SKIP_SIGNING": "y"},
            dry_run=False,
            python=python,
        )
        assert result.returncode == 0, result.stderr
        outputs[label] = result.stdout
        out = tree / f"out/release-bramble-{BUILD_NUMBER}"
        assert not list(out.iterdir())

    assert outputs["python"] == outputs["bash"]
    assert "Not creating factory image due to OTA_ONLY=y" in outputs["bash"]


def test_release_orchestration_in_tree_layout_matches_bash_bytes(
    tmp_path: Path,
) -> None:
    manifests: dict[str, dict[str, bytes]] = {}
    for label, python in (("bash", False), ("python", True)):
        tree = make_release_tree(tmp_path / label)
        product = tree / "out/target/product/bramble"
        product.mkdir(parents=True)
        _write_target_files_zip(
            product / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        )
        soong = tree / "out/soong/.intermediates/build/make/tools/releasetools"
        for tool in (
            "sign_target_files_apks",
            "ota_from_target_files",
            "img_from_target_files",
        ):
            host = soong / tool / "linux_glibc_x86_64"
            host.mkdir(parents=True)
            (tree / "bin" / tool).rename(host / tool)
        result = run_release(
            tree,
            "bramble",
            environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": str(tree)},
            dry_run=False,
            python=python,
            target_files_arg=None,
        )
        assert result.returncode == 0, result.stderr
        manifests[label] = _manifest(
            tree / f"out/release/release-bramble-{BUILD_NUMBER}",
        )

    assert manifests["python"] == manifests["bash"]
    assert (
        manifests["bash"][f"bramble-factory-{BUILD_NUMBER}.zip"]
        == b"factory-img-zip"
    )
    assert f"bramble-ota_update-{BUILD_NUMBER}.zip" in manifests["bash"]


@implementations
def test_release_honors_keep_target_files_directly(
    release_tree: Path,
    python: bool,
) -> None:
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out_dir.mkdir(parents=True)
    signed_target_files = out_dir / f"bramble-target_files-{BUILD_NUMBER}.zip"
    signed_target_files.write_bytes(b"already-signed")
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"KEEP_TARGET_FILES": "y", "OTA_ONLY": "y"},
        dry_run=False,
        python=python,
    )

    assert result.returncode == 0, result.stderr
    assert "Creating signed targetfiles zip" not in result.stdout
    assert signed_target_files.read_bytes() == b"already-signed"


@implementations
def test_release_treats_an_empty_keep_target_files_as_n(
    release_tree: Path,
    python: bool,
) -> None:
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out_dir.mkdir(parents=True)
    signed_target_files = out_dir / f"bramble-target_files-{BUILD_NUMBER}.zip"
    signed_target_files.write_bytes(b"already-signed")
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"KEEP_TARGET_FILES": "", "OTA_ONLY": "y"},
        dry_run=False,
        python=python,
    )

    assert result.returncode == 0, result.stderr
    assert "Creating signed targetfiles zip" in result.stdout


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
    tmp_path: Path,
    device: str,
    expected: dict[str, str],
) -> None:
    for implementation in ("bash", "python"):
        tree = make_release_tree(tmp_path / implementation)
        (tree / "device/common/generate-factory-images-common.sh").write_text(
            f"for name in {' '.join(FAMILY_VARIABLES)}; do\n"
            '  [ -z "${!name+set}" ] || printf "%s=%s\\n" "$name" "${!name}"\n'
            "done > family-environment\n"
            'cat "$DEVICE-img-$BUILD.zip"'
            ' > "$DEVICE-$VERSION-factory-fake.zip"\n',
        )
        _write_target_files_zip(
            tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
        )

        result = run_release(
            tree,
            device,
            environment={
                **{name: "" for name in FAMILY_VARIABLES},
                "OTA_ONLY": "",
                "ANDROID_BUILD_TOP": "",
            },
            dry_run=False,
            python=implementation == "python",
        )

        assert result.returncode == 0, (implementation, result.stderr)
        out_dir = tree / f"out/release-{device}-{BUILD_NUMBER}"
        recorded = dict(
            line.split("=", 1)
            for line in (out_dir / "family-environment")
            .read_text()
            .splitlines()
        )
        assert {
            name: value for name, value in recorded.items() if value
        } == expected, implementation


@pytest.mark.parametrize(
    "environment",
    (
        {"KEYMAPPER": "legacy"},
        {"KEYMAPPER": "id2b"},
        {
            "KEYMAPPER": "static",
            "KEYMAP_FILE": str(
                Path(__file__).parent / "fixtures" / "id2b-bramble-redfin.tsv",
            ),
        },
    ),
    ids=("legacy", "id2b", "static"),
)
def test_release_passes_the_avb_custom_key_to_the_factory_image_script(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    recorded: dict[str, str] = {}
    for implementation in ("bash", "python"):
        tree = make_release_tree(tmp_path / implementation)
        (tree / "device/common/generate-factory-images-common.sh").write_text(
            'printf "%s" "${AVB_CUSTOM_KEY:-}" > avb-custom-key\n'
            'cat "$DEVICE-img-$BUILD.zip"'
            ' > "$DEVICE-$VERSION-factory-fake.zip"\n',
        )
        _write_target_files_zip(
            tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
        )
        result = run_release(
            tree,
            "bramble",
            environment={
                **environment,
                "OTA_ONLY": "",
                "ANDROID_BUILD_TOP": "",
            },
            dry_run=False,
            python=implementation == "python",
        )
        assert result.returncode == 0, result.stderr
        out_dir = tree / f"out/release-bramble-{BUILD_NUMBER}"
        recorded[implementation] = (
            (out_dir / "avb-custom-key")
            .read_text()
            .replace(str(SCRIPTS_DIR), "<scripts>")
            .replace(str(tree), "<tree>")
        )

    assert recorded["bash"].startswith("<tree>/")
    assert recorded["python"] == recorded["bash"]


@implementations
def test_release_fails_with_the_factory_image_script_status(
    release_tree: Path,
    python: bool,
) -> None:
    (
        release_tree / "device/common/generate-factory-images-common.sh"
    ).write_text("false\ntouch kept-going\n(exit 7)\n")
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": "", "ANDROID_BUILD_TOP": ""},
        dry_run=False,
        python=python,
    )

    assert result.returncode == 7, result.stderr
    assert "Traceback" not in result.stderr
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert (out_dir / "kept-going").exists()


@implementations
def test_release_normalizes_key_dir_for_child_processes(
    release_tree: Path,
    python: bool,
) -> None:
    """
    payload_signer.openssl.sh reads KEY_DIR from the environment it
    inherits through ota_from_target_files, and strips it from key paths
    with ${key#$KEY_DIR*}, which needs exactly one trailing slash.
    """
    _install_tool(
        release_tree / "bin" / "ota_from_target_files",
        '#!/bin/sh\neval "out=\\${$#}"\n'
        'printf "KEY_DIR=[%s]" "$KEY_DIR" > "$out"\n',
    )
    out_dir = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    out_dir.mkdir(parents=True)
    (out_dir / f"bramble-target_files-{BUILD_NUMBER}.zip").write_bytes(
        b"already-signed",
    )
    _write_target_files_zip(
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
        python=python,
    )

    assert result.returncode == 0, result.stderr
    ota_zip = out_dir / f"bramble-ota_update-{BUILD_NUMBER}.zip"
    assert ota_zip.read_text() == "KEY_DIR=[/some/key/dir/]"


@implementations
def test_release_rejects_unrecognized_device_by_default(
    release_tree: Path,
    python: bool,
) -> None:
    device = "unlisteddevice"
    _write_target_files_zip(
        release_tree / f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        device,
        dry_run=False,
        environment={"KEYMAPPER": "legacy"},
        python=python,
    )

    assert result.returncode != 0
    assert f"Unsupported device {device}" in result.stderr
    assert not (release_tree / f"out/release-{device}-{BUILD_NUMBER}").exists()


def test_release_orchestration_reports_vendor_initialization_failure(
    release_tree: Path,
) -> None:
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"PKCS11_VENDOR": "acme"},
        python=True,
    )

    assert result.returncode == 1
    assert "PKCS11_VENDOR='acme' is not supported" in result.stderr


@implementations
def test_release_reports_a_wrong_argument_count_as_release_sh_does(
    release_tree: Path,
    python: bool,
) -> None:
    result = (run_cli if python else run)(
        [
            *(
                ["release-orchestrate", "release.sh"]
                if python
                else [SCRIPTS_DIR / "release.sh"]
            ),
            "bramble",
            "--help",
            "-x",
        ],
        cwd=release_tree,
        env={"PYTHONPATH": str(SCRIPTS_DIR), "BUILD_NUMBER": BUILD_NUMBER},
        check=False,
    )

    assert result.returncode == 1
    assert "error: incorrect number of arguments, please try again" in (
        result.stderr
    )
    assert "device [target-files.zip]" in result.stdout


@implementations
def test_release_prints_its_usage_on_stdout(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"BUILD_NUMBER": ""},
        python=python,
    )

    assert result.returncode == 1
    assert "BUILD_NUMBER not set" in result.stderr
    assert "device [target-files.zip]" in result.stdout


@implementations
def test_release_refuses_an_unknown_keymapper(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"KEYMAPPER": "nope"},
        python=python,
    )

    assert result.returncode == 1
    assert "Could not find keymapper 'nope'." in result.stderr
    assert "Traceback" not in result.stderr


def test_release_orchestration_refuses_keymapper_file(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"KEYMAPPER_FILE": str(release_tree / "keymapper.sh")},
        python=True,
    )

    assert result.returncode == 1
    assert "does not support KEYMAPPER_FILE" in result.stderr


@implementations
@pytest.mark.parametrize("keymapper", ("legacy", "id2b"))
def test_release_allows_extra_device_via_environment(
    release_tree: Path,
    python: bool,
    keymapper: str,
) -> None:
    device = "unlisteddevice"
    _write_target_files_zip(
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
        python=python,
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


@implementations
def test_release_honors_extra_signing_args_from_environment(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            "EXTRA_SIGNING_ARGS": "-k some/extra/path=some/other/path",
        },
        python=python,
    )

    assert result.returncode == 0, result.stderr
    signing_command = _command_line(result.stderr, "sign_target_files_apks")
    assert "-k some/extra/path=some/other/path" in signing_command


@implementations
def test_release_dry_run_builds_pkcs11_command_graph(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            **PKCS11_ENVIRONMENT,
            "SIGNING_HELPER_TOOL": "pkcs11-tool",
        },
        python=python,
    )

    assert result.returncode == 0, result.stderr
    commands = result.stderr
    assert "--pkcs11_config " in commands
    assert "--extra_avbtool_signing_args" in commands
    assert "signing_helper.pkcs11-tool.sh" in commands
    assert "--payload_signer" in commands
    assert "payload_signer.pkcs11-tool.sh" in commands
    assert "test-only" not in result.stdout
    assert "test-only" not in result.stderr


@implementations
def test_release_vendor_keymapper_sets_payload_signature_size(
    release_tree: Path,
    python: bool,
) -> None:
    """
    The vendor file exports KEYMAPPER before the keymapper file sets
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
        python=python,
    )

    assert result.returncode == 0, result.stderr
    assert "--payload_signer_maximum_signature_size 512" in result.stderr


@implementations
@pytest.mark.parametrize("opted_in", (True, False), ids=("opt-in", "default"))
def test_release_signs_ota_package_with_the_payload_signer(
    release_tree: Path,
    python: bool,
    opted_in: bool,
) -> None:
    environment = dict(PKCS11_ENVIRONMENT)
    if opted_in:
        environment["USE_SIGNAPK_EXTERNAL_SIGNER"] = "y"

    result = run_release(
        release_tree,
        "bramble",
        environment=environment,
        python=python,
    )

    assert result.returncode == 0, result.stderr
    ota_command = _command_line(result.stderr, "ota_from_target_files")
    assert (
        f"--payload_signer {SCRIPTS_DIR}/pkcs11/payload_signer.openssl.sh"
        in ota_command
    )
    assert ("--signapk_external_signer" in ota_command) is opted_in


@pytest.mark.parametrize(
    ("environment", "helper", "payload_signer"),
    (
        (
            {"AVB_SIGNING_HELPER_TOOL": "python"},
            "signing_helper.py",
            "payload_signer.openssl.sh",
        ),
        (
            {"PAYLOAD_SIGNER_TOOL": "python"},
            "signing_helper.openssl.sh",
            "payload_signer.py",
        ),
        (
            {"SIGNING_HELPER_TOOL": "python"},
            "signing_helper.py",
            "payload_signer.py",
        ),
    ),
    ids=("avb-helper", "payload-signer", "both"),
)
def test_release_can_select_python_signing_helpers(
    release_tree: Path,
    environment: dict[str, str],
    helper: str,
    payload_signer: str,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={**PKCS11_ENVIRONMENT, **environment},
    )

    assert result.returncode == 0, result.stderr
    assert helper in _command_line(result.stderr, "sign_target_files_apks")
    assert payload_signer in _command_line(
        result.stderr,
        "ota_from_target_files",
    )
    assert "test-only" not in result.stdout
    assert "test-only" not in result.stderr


@implementations
@pytest.mark.parametrize("device", ROLLBACK_DEVICES)
def test_release_dry_run_applies_rollback_override(
    release_tree: Path,
    python: bool,
    device: str,
) -> None:
    result = run_release(
        release_tree,
        device,
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
        python=python,
    )

    assert result.returncode == 0, result.stderr
    commands = result.stderr
    assert f"out/release-{device}-{int(BUILD_NUMBER) + 1}" in commands
    assert (
        "--avb_rollback_index_override 42 --bump_date_and_version 1"
        in _command_line(commands, "sign_target_files_apks")
    )
    assert "/bin/ota_from_target_files" not in commands
    assert "Skipping OTA update zip for AVB Rollback Index override build" in (
        result.stdout
    )


@implementations
@pytest.mark.parametrize(
    ("build_number", "rollback_build"),
    (("0042", "43"), ("0089", "90")),
)
def test_release_dry_run_adds_one_to_a_zero_padded_build_in_base_10(
    release_tree: Path,
    python: bool,
    build_number: str,
    rollback_build: str,
) -> None:
    result = run_release(
        release_tree,
        "devon",
        environment={
            "AVB_ROLLBACK_INDEX_OVERRIDE": "42",
            "BUILD_NUMBER": build_number,
        },
        python=python,
        target_files_arg=f"calyx_devon-target_files-{build_number}.zip",
    )

    assert result.returncode == 0, result.stderr
    assert f"out/release-devon-{rollback_build}" in result.stderr


@implementations
def test_release_stops_when_target_files_signing_fails(
    release_tree: Path,
    python: bool,
) -> None:
    _install_tool(
        release_tree / "bin" / "sign_target_files_apks",
        "#!/bin/sh\nexit 23\n",
    )
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )

    result = run_release(
        release_tree,
        "bramble",
        environment={"OTA_ONLY": ""},
        dry_run=False,
        python=python,
    )

    assert result.returncode != 0
    assert "Running:" in result.stderr
    assert "sign_target_files_apks" in result.stderr
    assert "Creating OTA update zip" not in result.stdout
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert not list(out.glob("*.zip"))


@implementations
def test_release_supports_otatest(release_tree: Path, python: bool) -> None:
    otatest = "2026081501"
    _write_target_files_zip(
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
        python=python,
    )

    assert result.returncode == 0, result.stderr
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    ota = out / f"bramble-ota_update-{otatest}.zip"
    assert ota.read_bytes() == b"ota-update-zip"
    assert (
        out / f"bramble-ota_update-{otatest}.zip.sha256sum"
    ).read_text() == (f"{sha256(ota)}  bramble-ota_update-{otatest}.zip\n")


@implementations
@pytest.mark.parametrize("device", ("bramble", "FP5"))
def test_release_rejects_rollback_override_on_unsupported_device(
    release_tree: Path,
    python: bool,
    device: str,
) -> None:
    result = run_release(
        release_tree,
        device,
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
        python=python,
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
            {**PKCS11_ENVIRONMENT, "SIGNING_HELPER_TOOL": "pkcs11-tool"},
        ),
        ("devon", {"AVB_ROLLBACK_INDEX_OVERRIDE": "42"}),
        ("bramble", {"KEY_SUFFIX": ""}),
        ("bramble", {"KEY_SUFFIX": ".key"}),
        ("bramble", {"KEYMAPPER": "legacy", "KEY_SUFFIX": ".key"}),
        ("bramble", {"BUILD_NUMBER": "eng.user"}),
        ("bramble", {"BUILD_NUMBER": "0042"}),
        ("bramble", {"KEYMAPPER": "legacy", "RSA_KEY_SIZE": "2048"}),
        ("bramble", {**PKCS11_ENVIRONMENT, "AVB_RSA_KEY_SIZE": "2048"}),
        ("bramble", {"AVB_RSA_KEY_SIZE": "", "RSA_KEY_SIZE": "2048"}),
    ),
    ids=(
        "plaintext",
        "pkcs11",
        "rollback-override",
        "empty-key-suffix",
        "key-suffix",
        "legacy-key-suffix",
        "text-build-number",
        "zero-padded-build-number",
        "legacy-rsa-key-size",
        "pkcs11-avb-rsa-key-size",
        "empty-avb-rsa-key-size",
    ),
)
def test_release_orchestration_matches_bash_byte_for_byte(
    release_tree: Path,
    device: str,
    environment: dict[str, str],
) -> None:
    """
    DRY_RUN output is the operator's preview of what a live run executes,
    so every rendered command must match Bash exactly, argument order
    included.
    """
    bash_result = run_release(release_tree, device, environment=environment)
    python_result = run_release(
        release_tree,
        device,
        environment=environment,
        python=True,
    )

    assert bash_result.returncode == 0, bash_result.stderr
    assert python_result.returncode == 0, python_result.stderr
    assert python_result.stdout == bash_result.stdout
    assert normalize_command_line(
        _normalize_rendered_commands(python_result.stderr),
    ) == normalize_command_line(
        _normalize_rendered_commands(
            strip_bash_only_keymapper_noise(bash_result.stderr),
        ),
    )


_PRINT_AND_RUN = r"""
source "$1"
shift
print_and_run "$@"
"""


@pytest.mark.parametrize("status", (0, 23))
def test_run_release_tool_matches_print_and_run(
    tmp_path: Path,
    status: int,
) -> None:
    results: dict[str, subprocess.CompletedProcess[str]] = {}
    outputs: dict[str, str] = {}
    for label in ("bash", "python"):
        root = tmp_path / label
        root.mkdir()
        tool = root / "tool"
        _install_tool(
            tool,
            f'#!/bin/sh\neval "out=\\${{$#}}"\nprintf %s "$*" > "$out"\n'
            f"exit {status}\n",
        )
        argv = [str(tool), "-k", "keys/0x2000", "in.zip", "out.zip"]
        command: list[str | Path]
        if label == "bash":
            command = [
                "bash",
                "-c",
                _PRINT_AND_RUN,
                "print-and-run",
                str(SCRIPTS_DIR / "common.include.sh"),
                *argv,
            ]
        else:
            command = [
                "run-release-tool",
                "--",
                *argv,
            ]
        results[label] = (run if label == "bash" else run_cli)(
            command,
            cwd=root,
            env={"PYTHONPATH": str(SCRIPTS_DIR)},
            check=False,
        )
        outputs[label] = (root / "out.zip").read_text()

    assert results["bash"].returncode == results["python"].returncode == status
    assert outputs["bash"] == outputs["python"]
    assert outputs["python"].endswith("-k keys/0x2000 in.zip out.zip")
    assert results["bash"].stderr.replace(
        str(tmp_path / "bash"),
        "<root>",
    ) == results["python"].stderr.replace(str(tmp_path / "python"), "<root>")


def test_compute_sha256sum_matches_sha256sum(tmp_path: Path) -> None:
    target = tmp_path / "artifact.zip"
    target.write_bytes(b"release artifact bytes\n" * 100_000)

    bash_result = run(["sha256sum", target.name], cwd=tmp_path)
    python_result = run_cli(["compute-sha256sum", target.name], cwd=tmp_path)

    assert python_result.stdout == bash_result.stdout


@implementations
@pytest.mark.parametrize("pkcs11", (False, True), ids=("plaintext", "pkcs11"))
@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_release_removes_its_temporaries(
    release_tree: Path,
    python: bool,
    pkcs11: bool,
    fails: bool,
) -> None:
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    if fails:
        _install_tool(
            release_tree / "bin" / "sign_target_files_apks",
            "#!/bin/sh\nexit 23\n",
        )

    result = run_release(
        release_tree,
        "bramble",
        environment=PKCS11_ENVIRONMENT if pkcs11 else {},
        dry_run=False,
        python=python,
    )

    assert (result.returncode != 0) == fails, result.stderr
    assert list((release_tree / "tmp").iterdir()) == []


def test_use_python_release_orchestration_reports_its_vendor_limit(
    release_tree: Path,
) -> None:
    """
    The Python orchestrator supports only the softhsm and yubihsm
    vendors and says so, where release.sh looks for a vendor include.
    """
    results = {
        flag: run_release(
            release_tree,
            "bramble",
            environment={
                "PKCS11_VENDOR": "acme",
                "USE_PYTHON_RELEASE_ORCHESTRATION": flag,
            },
        )
        for flag in ("", "y")
    }

    assert results[""].returncode == results["y"].returncode == 1
    assert "Could not find PKCS#11 vendor include script for 'acme'" in (
        results[""].stderr
    )
    assert (
        "PKCS11_VENDOR='acme' is not supported by the Python orchestrator. "
        "Unset USE_PYTHON_RELEASE_ORCHESTRATION"
    ) in results["y"].stderr


@pytest.mark.parametrize("flag", ("", "y"))
def test_use_python_release_tools_checksums_without_sha256sum(
    release_tree: Path,
    flag: str,
) -> None:
    stubs = release_tree / "stubs"
    _install_tool(stubs / "sha256sum", "#!/bin/sh\nexit 127\n")
    _write_target_files_zip(
        release_tree / f"calyx_bramble-target_files-{BUILD_NUMBER}.zip",
    )
    result = run_release(
        release_tree,
        "bramble",
        environment={
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "USE_PYTHON_RELEASE_TOOLS": flag,
        },
        dry_run=False,
    )

    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    ota = out / f"bramble-ota_update-{BUILD_NUMBER}.zip"
    checksum = out / f"bramble-ota_update-{BUILD_NUMBER}.zip.sha256sum"
    if not flag:
        assert result.returncode != 0
        assert ota.exists()
        return
    assert result.returncode == 0, result.stderr
    assert checksum.read_text() == f"{sha256(ota)}  {ota.name}\n"


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
    _install_tool(
        release_tree / "bin" / "sign_target_files_apks",
        f'#!/bin/sh\ntouch "{started}"\nsleep 30\n',
    )
    _write_target_files_zip(
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


@implementations
def test_release_requires_yubihsm_credentials(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"PKCS11_VENDOR": "yubihsm"},
        python=python,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "YUBIHSM_AUTHKEY" in result.stderr


@implementations
def test_release_stops_before_signing_without_the_factory_variables(
    release_tree: Path,
    python: bool,
) -> None:
    (release_tree / "device/common/clear-factory-images-variables.sh").unlink()

    result = run_release(release_tree, "bramble", python=python)

    assert result.returncode == 1
    assert "clear-factory-images-variables.sh" in result.stderr
    assert "sign_target_files_apks" not in result.stderr


def _release_session(
    release_tree: Path,
    environment: dict[str, str],
) -> ReleaseOrchestrator:
    return ReleaseOrchestrator(
        environment,
        cwd=release_tree,
        metadata=load_metadata(TEST_METADATA),
        device="bramble",
        target_files_arg=None,
    )


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
    session = _release_session(
        release_tree,
        {**PKCS11_ENVIRONMENT, "KEYMAPPER": "id2b", "TMPDIR": ""},
    )

    with pytest.raises(ReleaseAbort):
        session.prepare_for_signing_full(
            device="bramble",
            build_number=BUILD_NUMBER,
            command_argv=[],
        )

    assert parents == ["/dev/shm"]


def test_run_release_tool_reports_a_tool_it_cannot_start(
    tmp_path: Path,
) -> None:
    result = run_cli(
        ["run-release-tool", "--", str(tmp_path / "missing-tool")],
        check=False,
    )

    assert result.returncode == 127
    assert "Traceback" not in result.stderr


def _signing_arguments(stderr: str) -> list[str]:
    line = _command_line(stderr, "sign_target_files_apks")
    return shlex.split(re.sub(r"/signing\.\w+/", "/signing.X/", line))


@pytest.mark.parametrize(
    "flags",
    ({}, {"USE_PYTHON_RELEASE_ARGS": "y"}),
    ids=("bash", "python"),
)
def test_release_leaves_out_the_metadata_placeholders(
    release_tree: Path,
    tmp_path: Path,
    flags: dict[str, str],
) -> None:
    from test_generate_keymap import metadata_with_placeholders

    metadata = metadata_with_placeholders(
        TEST_METADATA,
        tmp_path / "metadata.py",
    )

    full = run_release(release_tree, "bramble", environment=flags)
    placeholders = run_release(
        release_tree,
        "bramble",
        environment={**flags, "METADATA_FILE": str(metadata)},
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


@implementations
def test_release_signs_plain_keys_without_its_tmpdir(
    release_tree: Path,
    python: bool,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"TMPDIR": str(release_tree / "missing")},
        python=python,
    )

    assert result.returncode == 0, result.stderr


def test_python_release_dry_run_warns_of_kms_without_the_server(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={"USE_APKSIGNER_KMS": "y"},
        python=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Warning: USE_APKSIGNER_KMS=y signs through the signing" in (
        result.stderr
    )
