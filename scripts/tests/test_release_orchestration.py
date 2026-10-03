#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import re
import shlex
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, TEST_METADATA, run, sha256


@pytest.fixture(autouse=True)
def _small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


BUILD_NUMBER = "2026081500"
ROLLBACK_DEVICES = ("devon", "hawao", "rhode", "fogos", "bangkk", "fogo")

PKCS11_ENVIRONMENT = {
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
    for key in (
        "0x2000.avbpubkey",
        "bramble/avb_custom_key.img",
    ):
        path = root / "keys" / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("avb custom key\n")


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


def run_release(
    release_tree: Path,
    device: str,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
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
    return run(
        [
            SCRIPTS_DIR / "release.sh",
            device,
            f"calyx_{device}-target_files-{BUILD_NUMBER}.zip",
        ],
        cwd=release_tree,
        env=variables,
        check=False,
    )


def _command_line(stderr: str, tool: str) -> str:
    return next(line for line in stderr.splitlines() if f"/bin/{tool}" in line)


def test_release_dry_run_builds_plaintext_command_graph(
    release_tree: Path,
) -> None:
    result = run_release(release_tree, "bramble")

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


def test_release_honors_extra_signing_args_from_environment(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            "EXTRA_SIGNING_ARGS": "-k some/extra/path=some/other/path",
        },
    )

    assert result.returncode == 0, result.stderr
    signing_command = _command_line(result.stderr, "sign_target_files_apks")
    assert "-k some/extra/path=some/other/path" in signing_command


def test_release_dry_run_builds_pkcs11_command_graph(
    release_tree: Path,
) -> None:
    result = run_release(
        release_tree,
        "bramble",
        environment={
            **PKCS11_ENVIRONMENT,
            "SIGNING_HELPER_TOOL": "pkcs11-tool",
        },
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


@pytest.mark.parametrize("device", ROLLBACK_DEVICES)
def test_release_dry_run_applies_rollback_override(
    release_tree: Path,
    device: str,
) -> None:
    result = run_release(
        release_tree,
        device,
        environment={"AVB_ROLLBACK_INDEX_OVERRIDE": "42"},
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


def test_release_stops_when_target_files_signing_fails(
    release_tree: Path,
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
    )

    assert result.returncode != 0
    assert "Running:" in result.stderr
    assert "sign_target_files_apks" in result.stderr
    assert "Creating OTA update zip" not in result.stdout
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    assert not list(out.glob("*.zip"))


def test_release_supports_otatest(release_tree: Path) -> None:
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
    )

    assert result.returncode == 0, result.stderr
    out = release_tree / f"out/release-bramble-{BUILD_NUMBER}"
    ota = out / f"bramble-ota_update-{otatest}.zip"
    assert ota.read_bytes() == b"ota-update-zip"
    assert (
        out / f"bramble-ota_update-{otatest}.zip.sha256sum"
    ).read_text() == (f"{sha256(ota)}  bramble-ota_update-{otatest}.zip\n")


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
