#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import REPO_ROOT, SCRIPTS_DIR, TEST_METADATA, run, sha256

pytestmark = [pytest.mark.aosp, pytest.mark.usefixtures("aosp_top")]
SUBJECT = "/C=US/O=Calyx Institute/CN=updatekeys integration test"
AOSP_TOP = REPO_ROOT.parents[1]
AVBTOOL = AOSP_TOP / "out" / "host" / "linux-x86" / "bin" / "avbtool"


@pytest.fixture(params=("make_key", "python"))
def signing_mode(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def updatekeys_tree(tmp_path: Path) -> Path:
    (tmp_path / "keys" / "bramble").mkdir(parents=True)
    return tmp_path


def run_updatekeys(
    root: Path,
    signing_mode: str,
) -> subprocess.CompletedProcess[str]:
    environment = {
        "KEYMAPPER": "id2b",
        "METADATA_FILE": str(TEST_METADATA),
        "AVBTOOL_BIN": str(AVBTOOL),
        "GENERATE_VERITY_KEY_BIN": "/bin/true",
    }
    input_text = None
    if signing_mode == "python":
        environment["USE_PYTHON_SIGNING"] = "y"
        environment["MAKE_KEY_BIN"] = str(root / "missing-make_key")
    else:
        environment["MAKE_KEY_BIN"] = str(
            AOSP_TOP / "development" / "tools" / "make_key",
        )
        input_text = "\n" * 32
    return run(
        [SCRIPTS_DIR / "updatekeys.sh", "keys/bramble", SUBJECT],
        cwd=root,
        env=environment,
        input_text=input_text,
        check=False,
    )


def assert_avb_public_key_matches(
    root: Path,
    key_name: str,
    private_suffix: str,
    public_suffix: str,
) -> None:
    key = root / "keys" / f"{key_name}{private_suffix}"
    stored_public_key = root / "keys" / f"{key_name}{public_suffix}"
    extracted_public_key = root / "keys" / f"{key_name}.expected.avbpubkey"
    run(
        [
            AVBTOOL,
            "extract_public_key",
            "--key",
            key,
            "--output",
            extracted_public_key,
        ],
    )
    assert stored_public_key.read_bytes() == extracted_public_key.read_bytes()


def test_updatekeys_generates_complete_id2b_key_set(
    updatekeys_tree: Path,
    signing_mode: str,
) -> None:
    result = run_updatekeys(updatekeys_tree, signing_mode)
    assert result.returncode == 0, result.stderr
    keys = updatekeys_tree / "keys"

    for key_id in range(0x1100, 0x1108):
        assert (keys / f"0x{key_id:04x}.pk8").is_file()
        assert (keys / f"0x{key_id:04x}.x509.pem").is_file()
    for key_name in ("0x1200",):
        assert (keys / f"{key_name}.pk8").is_file()
        assert (keys / f"{key_name}.x509.pem").is_file()
    suffixes = (
        ("0x2000", ".pem", ".avbpubkey"),
        ("0x1300", ".pem", ".avbpubkey"),
    )
    for key_name, private_suffix, public_suffix in suffixes:
        assert (keys / f"{key_name}{private_suffix}").is_file()
        assert (keys / f"{key_name}{public_suffix}").is_file()
        assert_avb_public_key_matches(
            updatekeys_tree,
            key_name,
            private_suffix,
            public_suffix,
        )


def test_updatekeys_is_idempotent(
    updatekeys_tree: Path,
    signing_mode: str,
) -> None:
    first = run_updatekeys(updatekeys_tree, signing_mode)
    assert first.returncode == 0, first.stderr
    keys = updatekeys_tree / "keys"
    before = {
        path.relative_to(keys): sha256(path)
        for path in keys.iterdir()
        if path.is_file()
    }

    second = run_updatekeys(updatekeys_tree, signing_mode)
    assert second.returncode == 0, second.stderr
    after = {
        path.relative_to(keys): sha256(path)
        for path in keys.iterdir()
        if path.is_file()
    }
    assert after == before
