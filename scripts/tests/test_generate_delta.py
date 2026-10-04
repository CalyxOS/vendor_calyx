#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import zipfile
from pathlib import Path

import pytest
from conftest import (
    SCRIPTS_DIR,
    TEST_METADATA,
    install_executable,
    parameter_id,
    run,
)
from test_release_orchestration import (
    DRY_RUN_FIXTURES,
    normalize_command_line,
)


@pytest.fixture(autouse=True)
def _small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


SOONG_OTA_FROM_TARGET_FILES = (
    "out/soong/.intermediates/build/make/tools/releasetoo"
    "ls/ota_from_target_files/linux_glibc_x86_64/ota_from_target_files"
)
DEVICE = "bramble"
BUILD_OLD = "2026080100"
BUILD_NEW = "2026081500"


def _target_files_path(root: Path, build: str) -> Path:
    return (
        root
        / f"archive/release-{DEVICE}-{build}/{DEVICE}-target_files-{build}.zip"
    )


def _incremental_out_dir(root: Path) -> Path:
    return root / f"archive/release-{DEVICE}-{BUILD_NEW}"


def _write_target_files_zip(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("SYSTEM/build.prop", "ro.build.id=TestBuild\n")


def _install_fake_ota_tool(root: Path) -> None:
    tool_directory = root / "bin"
    tool_directory.mkdir(exist_ok=True)
    install_executable(
        tool_directory / "ota_from_target_files",
        '#!/bin/sh\neval "out=\\${$#}"\n'
        'printf %s "incremental-ota-bytes" > "$out"\n',
    )


@pytest.fixture
def delta_tree(tmp_path: Path) -> Path:
    _write_target_files_zip(_target_files_path(tmp_path, BUILD_OLD))
    _write_target_files_zip(_target_files_path(tmp_path, BUILD_NEW))
    return tmp_path


def run_generate_delta(
    root: Path,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
    arguments: tuple[str, ...] = (DEVICE, BUILD_OLD, BUILD_NEW),
) -> subprocess.CompletedProcess[str]:
    variables = {
        "KEYMAPPER": "id2b",
        "TMPDIR": str(root),
        **(environment or {}),
    }
    if dry_run:
        variables["DRY_RUN"] = "y"
    return run(
        [SCRIPTS_DIR / "generate_delta.sh", *arguments],
        cwd=root,
        env=variables,
        check=False,
    )


@pytest.mark.parametrize("built", (True, False), ids=("built", "missing"))
def test_generate_delta_finds_its_ota_tool_in_a_source_tree(
    delta_tree: Path,
    built: bool,
) -> None:
    (delta_tree / "build/tools/releasetools").mkdir(parents=True)
    tool = delta_tree / SOONG_OTA_FROM_TARGET_FILES
    if built:
        tool.parent.mkdir(parents=True)
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)

    result = run_generate_delta(delta_tree)

    if built:
        assert result.returncode == 0, result.stderr
        assert SOONG_OTA_FROM_TARGET_FILES in result.stderr
        assert "-p ." not in result.stderr
    else:
        assert result.returncode == 1
        assert "couldn't find releasetools binary 'ota_from_target_files'" in (
            result.stderr
        )


def test_generate_delta_creates_incremental_and_checksum(
    delta_tree: Path,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(delta_tree, dry_run=False)

    assert result.returncode == 0, result.stderr
    out = _incremental_out_dir(delta_tree)
    incremental_name = f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip"
    incremental = out / incremental_name
    checksum = out / f"{incremental_name}.sha256sum"
    assert incremental.read_bytes() == b"incremental-ota-bytes"
    digest = hashlib.sha256(b"incremental-ota-bytes").hexdigest()
    assert checksum.read_text() == f"{digest}  {incremental_name}\n"


def test_generate_delta_stops_when_ota_tool_fails(delta_tree: Path) -> None:
    install_executable(
        delta_tree / "bin" / "ota_from_target_files",
        "#!/bin/sh\nexit 23\n",
    )

    result = run_generate_delta(delta_tree, dry_run=False)

    assert result.returncode == 23
    out = _incremental_out_dir(delta_tree)
    assert not list(out.glob(f"{DEVICE}-incremental-*"))


@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_generate_delta_removes_its_temporaries(
    delta_tree: Path,
    fails: bool,
) -> None:
    if fails:
        install_executable(
            delta_tree / "bin" / "ota_from_target_files",
            "#!/bin/sh\nexit 23\n",
        )
    else:
        _install_fake_ota_tool(delta_tree)
    tmpdir = delta_tree / "tmp"
    tmpdir.mkdir()

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={
            "TMPDIR": str(tmpdir),
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
            "PKCS11_PIN": "test-only",
        },
    )

    assert (result.returncode != 0) == fails, result.stderr
    assert list(tmpdir.iterdir()) == []


def test_generate_delta_checksums_without_sha256sum(
    delta_tree: Path,
) -> None:
    _install_fake_ota_tool(delta_tree)
    stubs = delta_tree / "stubs"
    stubs.mkdir()
    install_executable(stubs / "sha256sum", "#!/bin/sh\nexit 127\n")
    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={
            "PATH": f"{stubs}:{os.environ['PATH']}",
        },
    )

    incremental = _incremental_out_dir(delta_tree) / (
        f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip"
    )
    checksum = incremental.with_name(incremental.name + ".sha256sum")
    assert result.returncode == 0, result.stderr
    digest = hashlib.sha256(incremental.read_bytes()).hexdigest()
    assert checksum.read_text() == f"{digest}  {incremental.name}\n"


def _normalized(stderr: str, tree: Path) -> str:
    return (
        normalize_command_line(stderr)
        .replace(str(SCRIPTS_DIR), "<scripts>")
        .replace(str(tree), "<tree>")
    )


@pytest.mark.parametrize(
    "environment",
    (
        {},
        {
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
            "PKCS11_PIN": "test-only",
        },
        {"KEY_SUFFIX": "", "EXTRA_RELEASETOOLS_ARGS": "--verbose"},
    ),
    ids=("plaintext", "pkcs11", "key-suffix"),
)
def test_generate_delta_dry_run_renders_the_expected_commands(
    delta_tree: Path,
    environment: dict[str, str],
    request: pytest.FixtureRequest,
) -> None:
    name = parameter_id(request)

    result = run_generate_delta(delta_tree, environment=environment)

    assert result.returncode == 0, result.stderr
    assert (
        result.stdout
        == (DRY_RUN_FIXTURES / f"generate-delta-{name}.stdout").read_text()
    )
    assert (
        _normalized(result.stderr, delta_tree)
        == (DRY_RUN_FIXTURES / f"generate-delta-{name}.stderr").read_text()
    )


def test_generate_delta_refuses_a_wrong_argument_count(
    delta_tree: Path,
) -> None:
    result = run_generate_delta(delta_tree, arguments=(DEVICE, "--help"))

    assert result.returncode == 1
    assert "error: incorrect number of arguments" in result.stderr
    assert "generate_delta.sh device oldversion newversion" in result.stdout


def test_generate_delta_with_a_vendor_needs_a_build_number(
    delta_tree: Path,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={
            "PKCS11_VENDOR": "softhsm",
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_PIN": "test-only",
            "SOFTHSM_LOGS_DIR": str(delta_tree / "logs"),
        },
    )

    assert result.returncode != 0
    assert "BUILD_NUMBER" in result.stderr
    assert not list((delta_tree / "logs").glob("*-exec.log"))


def test_generate_delta_needs_no_build_number_once_initialized(
    delta_tree: Path,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={
            "PKCS11_VENDOR": "softhsm",
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_PIN": "test-only",
            "PKCS11_VENDOR_INITIALIZED_RELEASE": "y",
        },
    )

    assert result.returncode == 0, result.stderr


def test_generate_delta_names_the_softhsm_logs_after_itself(
    delta_tree: Path,
) -> None:
    _install_fake_ota_tool(delta_tree)
    logs = delta_tree / "logs"

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={
            "PKCS11_VENDOR": "softhsm",
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
            "PKCS11_PIN": "test-only",
            "SOFTHSM_LOGS_DIR": str(logs),
            "BUILD_NUMBER": f"{BUILD_NEW}_{BUILD_OLD}",
        },
    )

    assert result.returncode == 0, result.stderr
    (exec_log,) = logs.glob("*-exec.log")
    assert re.fullmatch(
        rf"{BUILD_NEW}_{BUILD_OLD}-{DEVICE}-\d{{8}}-\d{{6}}"
        r"-generate_delta-exec\.log",
        exec_log.name,
    )
    assert "Calculating sha256sum for incremental" in exec_log.read_text()


def test_generate_delta_dry_run_leaves_only_an_empty_checksum(
    delta_tree: Path,
) -> None:
    before = {path for path in delta_tree.rglob("*") if path.is_file()}

    result = run_generate_delta(delta_tree)

    assert result.returncode == 0, result.stderr
    created = {
        path for path in delta_tree.rglob("*") if path.is_file()
    } - before
    checksum = delta_tree / (
        f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip.sha256sum"
    )
    assert created == {checksum}
    assert checksum.read_bytes() == b""


def test_generate_delta_names_the_script_it_ran_as(delta_tree: Path) -> None:
    result = run_generate_delta(delta_tree)

    assert result.returncode == 0, result.stderr
    assert f"Command: {SCRIPTS_DIR / 'generate_delta.sh'} {DEVICE} " in (
        result.stderr
    )


def test_generate_delta_refuses_an_unknown_vendor_first(
    delta_tree: Path,
) -> None:
    result = run_generate_delta(
        delta_tree,
        environment={"PKCS11_VENDOR": "nope"},
    )

    assert result.returncode == 1
    assert "BUILD_NUMBER not set" not in result.stderr
    assert "nope" in result.stderr


def test_generate_delta_refuses_an_unmapped_device_first(
    delta_tree: Path,
) -> None:
    result = run_generate_delta(
        delta_tree,
        arguments=("nosuch", BUILD_OLD, BUILD_NEW),
    )

    assert result.returncode == 1
    assert "failed to prepare for signing" in result.stderr
    assert "Command:" not in result.stderr
