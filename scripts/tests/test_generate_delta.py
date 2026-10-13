#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest
from conftest import (
    SCRIPTS_DIR,
    install_executable,
    parameter_id,
    run,
)
from test_release_orchestration import (
    DRY_RUN_FIXTURES,
    PKCS11_ENVIRONMENT,
    normalize_dry_run,
    write_target_files_zip,
)

pytestmark = pytest.mark.usefixtures("small_metadata")


SOONG_OTA_FROM_TARGET_FILES = (
    "out/soong/.intermediates/build/make/tools/releasetoo"
    "ls/ota_from_target_files/linux_glibc_x86_64/ota_from_target_files"
)
DEVICE = "bramble"
BUILD_OLD = "2026080100"
BUILD_NEW = "2026081500"
DELTA_PKCS11_ENVIRONMENT = {
    **PKCS11_ENVIRONMENT,
    "BUILD_NUMBER": f"{BUILD_NEW}_{BUILD_OLD}",
}


def _target_files_path(root: Path, build: str) -> Path:
    return (
        root
        / f"archive/release-{DEVICE}-{build}/{DEVICE}-target_files-{build}.zip"
    )


def _incremental_out_dir(root: Path) -> Path:
    return root / f"archive/release-{DEVICE}-{BUILD_NEW}"


def _install_fake_ota_tool(
    root: Path,
    script: str = '#!/bin/sh\neval "out=\\${$#}"\n'
    'printf %s "incremental-ota-bytes" > "$out"\n',
) -> None:
    install_executable(root / "bin" / "ota_from_target_files", script)


@pytest.fixture
def delta_tree(tmp_path: Path) -> Path:
    for build in (BUILD_OLD, BUILD_NEW):
        target_files = _target_files_path(tmp_path, build)
        target_files.parent.mkdir(parents=True)
        write_target_files_zip(target_files)
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


@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_generate_delta_removes_its_temporaries(
    delta_tree: Path,
    fails: bool,
) -> None:
    if fails:
        _install_fake_ota_tool(delta_tree, "#!/bin/sh\nexit 23\n")
    else:
        _install_fake_ota_tool(delta_tree)
    tmpdir = delta_tree / "tmp"
    tmpdir.mkdir()

    result = run_generate_delta(
        delta_tree,
        dry_run=False,
        environment={**DELTA_PKCS11_ENVIRONMENT, "TMPDIR": str(tmpdir)},
    )

    assert result.returncode == (23 if fails else 0), result.stderr
    assert list(tmpdir.iterdir()) == []
    incrementals = _incremental_out_dir(delta_tree).glob(
        f"{DEVICE}-incremental-*",
    )
    assert bool(list(incrementals)) != fails


@pytest.mark.parametrize(
    "environment",
    (
        {},
        DELTA_PKCS11_ENVIRONMENT,
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
        normalize_dry_run(result.stderr, delta_tree)
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
        environment={**DELTA_PKCS11_ENVIRONMENT, "SOFTHSM_LOGS_DIR": str(logs)},
    )

    assert result.returncode == 0, result.stderr
    (exec_log,) = logs.glob("*-exec.log")
    assert re.fullmatch(
        rf"{BUILD_NEW}_{BUILD_OLD}-{DEVICE}-\d{{8}}-\d{{6}}"
        r"-generate_delta-exec\.log",
        exec_log.name,
    )
    assert "Calculating sha256sum for incremental" in exec_log.read_text()


def test_generate_delta_dry_run_writes_no_files(delta_tree: Path) -> None:
    before = {path for path in delta_tree.rglob("*") if path.is_file()}

    result = run_generate_delta(delta_tree)

    assert result.returncode == 0, result.stderr
    assert {path for path in delta_tree.rglob("*") if path.is_file()} == before


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
