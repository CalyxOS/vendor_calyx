#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, TEST_METADATA, run


@pytest.fixture(autouse=True)
def _small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


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


def run_generate_delta(
    root: Path,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
) -> subprocess.CompletedProcess[str]:
    variables = {"KEYMAPPER": "id2b", **(environment or {})}
    if dry_run:
        variables["DRY_RUN"] = "y"
    return run(
        [SCRIPTS_DIR / "generate_delta.sh", DEVICE, BUILD_OLD, BUILD_NEW],
        cwd=root,
        env=variables,
        check=False,
    )


def test_generate_delta_dry_run_renders_ota_command(delta_tree: Path) -> None:
    result = run_generate_delta(delta_tree)

    assert result.returncode == 0, result.stderr
    assert "/bin/ota_from_target_files" in result.stderr
    assert "-k keys/0x2000" in result.stderr
    assert f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip" in result.stderr


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
    tool_directory = delta_tree / "bin"
    tool_directory.mkdir()
    tool = tool_directory / "ota_from_target_files"
    tool.write_text("#!/bin/sh\nexit 23\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

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
        environment={
            "TMPDIR": str(tmpdir),
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
            "PKCS11_PIN": "test-only",
        },
    )

    assert (result.returncode != 0) == fails, result.stderr
    assert list(tmpdir.iterdir()) == []


@pytest.mark.parametrize("flag", ("", "y"))
def test_use_python_release_tools_checksums_without_sha256sum(
    delta_tree: Path,
    flag: str,
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
            "USE_PYTHON_RELEASE_TOOLS": flag,
        },
    )

    incremental = _incremental_out_dir(delta_tree) / (
        f"{DEVICE}-incremental-{BUILD_OLD}-{BUILD_NEW}.zip"
    )
    checksum = incremental.with_name(incremental.name + ".sha256sum")
    if not flag:
        assert result.returncode != 0
        assert incremental.exists()
        return
    assert result.returncode == 0, result.stderr
    digest = hashlib.sha256(incremental.read_bytes()).hexdigest()
    assert checksum.read_text() == f"{digest}  {incremental.name}\n"
