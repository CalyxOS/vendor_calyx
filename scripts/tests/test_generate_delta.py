#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, TEST_METADATA, run
from test_release_orchestration import (
    normalize_command_line,
    strip_bash_only_keymapper_noise,
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
    tool = tool_directory / "ota_from_target_files"
    tool.write_text(
        '#!/bin/sh\neval "out=\\${$#}"\n'
        'printf %s "incremental-ota-bytes" > "$out"\n',
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def delta_tree(tmp_path: Path) -> Path:
    _write_target_files_zip(_target_files_path(tmp_path, BUILD_OLD))
    _write_target_files_zip(_target_files_path(tmp_path, BUILD_NEW))
    return tmp_path


implementations = pytest.mark.parametrize(
    "python",
    (False, True),
    ids=("bash", "python"),
)


def run_generate_delta(
    root: Path,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
    python: bool = False,
    arguments: tuple[str, ...] = (DEVICE, BUILD_OLD, BUILD_NEW),
) -> subprocess.CompletedProcess[str]:
    variables = {"KEYMAPPER": "id2b", **(environment or {})}
    if dry_run:
        variables["DRY_RUN"] = "y"
    if python:
        variables["USE_PYTHON_GENERATE_DELTA"] = "y"
    return run(
        [SCRIPTS_DIR / "generate_delta.sh", *arguments],
        cwd=root,
        env=variables,
        check=False,
    )


def _files(root: Path) -> set[str]:
    return {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
    }


def test_generate_delta_dry_run_leaves_the_files_bash_leaves(
    tmp_path: Path,
) -> None:
    created: dict[str, set[str]] = {}
    for label, python in (("bash", False), ("python", True)):
        root = tmp_path / label
        _write_target_files_zip(_target_files_path(root, BUILD_OLD))
        _write_target_files_zip(_target_files_path(root, BUILD_NEW))
        before = _files(root)
        result = run_generate_delta(root, python=python)
        assert result.returncode == 0, result.stderr
        created[label] = _files(root) - before

    assert created["python"] == created["bash"]


@implementations
def test_generate_delta_dry_run_renders_ota_command(
    delta_tree: Path,
    python: bool,
) -> None:
    result = run_generate_delta(delta_tree, python=python)

    assert result.returncode == 0, result.stderr
    assert "/bin/ota_from_target_files" in result.stderr
    assert "-k keys/0x2000" in result.stderr
    assert f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip" in result.stderr


@pytest.mark.parametrize("built", (True, False), ids=("built", "missing"))
@implementations
def test_generate_delta_finds_its_ota_tool_in_a_source_tree(
    delta_tree: Path,
    python: bool,
    built: bool,
) -> None:
    (delta_tree / "build/tools/releasetools").mkdir(parents=True)
    tool = delta_tree / SOONG_OTA_FROM_TARGET_FILES
    if built:
        tool.parent.mkdir(parents=True)
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)

    result = run_generate_delta(delta_tree, python=python)

    if built:
        assert result.returncode == 0, result.stderr
        assert SOONG_OTA_FROM_TARGET_FILES in result.stderr
        assert "-p ." not in result.stderr
    else:
        assert result.returncode == 1
        assert "couldn't find releasetools binary 'ota_from_target_files'" in (
            result.stderr
        )


@implementations
def test_generate_delta_creates_incremental_and_checksum(
    delta_tree: Path,
    python: bool,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(delta_tree, dry_run=False, python=python)

    assert result.returncode == 0, result.stderr
    out = _incremental_out_dir(delta_tree)
    incremental_name = f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip"
    incremental = out / incremental_name
    checksum = out / f"{incremental_name}.sha256sum"
    assert incremental.read_bytes() == b"incremental-ota-bytes"
    digest = hashlib.sha256(b"incremental-ota-bytes").hexdigest()
    assert checksum.read_text() == f"{digest}  {incremental_name}\n"


@implementations
def test_generate_delta_stops_when_ota_tool_fails(
    delta_tree: Path,
    python: bool,
) -> None:
    tool_directory = delta_tree / "bin"
    tool_directory.mkdir()
    tool = tool_directory / "ota_from_target_files"
    tool.write_text("#!/bin/sh\nexit 23\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    result = run_generate_delta(delta_tree, dry_run=False, python=python)

    assert result.returncode == 23
    out = _incremental_out_dir(delta_tree)
    assert not list(out.glob(f"{DEVICE}-incremental-*"))


@implementations
@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_generate_delta_removes_its_temporaries(
    delta_tree: Path,
    fails: bool,
    python: bool,
) -> None:
    if fails:
        tool = delta_tree / "bin" / "ota_from_target_files"
        tool.parent.mkdir()
        tool.write_text("#!/bin/sh\nexit 23\n")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    else:
        _install_fake_ota_tool(delta_tree)
    tmpdir = delta_tree / "tmp"
    tmpdir.mkdir()

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        python=python,
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
    stub = stubs / "sha256sum"
    stub.write_text("#!/bin/sh\nexit 127\n")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
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


def _normalized(stderr: str) -> str:
    return re.sub(
        r"/signing\.\w+/",
        "/signing.XXXXXXXX/",
        normalize_command_line(strip_bash_only_keymapper_noise(stderr)),
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
def test_python_generate_delta_dry_run_matches_bash_byte_for_byte(
    delta_tree: Path,
    environment: dict[str, str],
) -> None:
    bash = run_generate_delta(delta_tree, environment=environment)
    python = run_generate_delta(
        delta_tree,
        environment=environment,
        python=True,
    )

    assert bash.returncode == 0, bash.stderr
    assert python.returncode == 0, python.stderr
    assert _normalized(python.stderr) == _normalized(bash.stderr)


@implementations
def test_generate_delta_refuses_a_wrong_argument_count(
    delta_tree: Path,
    python: bool,
) -> None:
    result = run_generate_delta(
        delta_tree,
        python=python,
        arguments=(DEVICE, "--help"),
    )

    assert result.returncode == 1
    assert "error: incorrect number of arguments" in result.stderr
    assert "generate_delta.sh device oldversion newversion" in result.stdout


@implementations
def test_generate_delta_with_a_vendor_needs_a_build_number(
    delta_tree: Path,
    python: bool,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        python=python,
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


@implementations
def test_generate_delta_needs_no_build_number_once_initialized(
    delta_tree: Path,
    python: bool,
) -> None:
    _install_fake_ota_tool(delta_tree)

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        python=python,
        environment={
            "PKCS11_VENDOR": "softhsm",
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_PIN": "test-only",
            "PKCS11_VENDOR_INITIALIZED_RELEASE": "y",
        },
    )

    assert result.returncode == 0, result.stderr


@implementations
def test_generate_delta_names_the_softhsm_logs_after_itself(
    delta_tree: Path,
    python: bool,
) -> None:
    _install_fake_ota_tool(delta_tree)
    logs = delta_tree / "logs"

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        python=python,
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
