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
LEGACY_METADATA = """KEYS_AVB = ("vbmeta", "vbmeta_system")
KEYS_OTHER = ()
KEYS_CORE = ("build/make/target/product/security/testkey",)
KEYS_APEX = ("com.android.adbd",)
KEYS_APEX_APK = ()
KEYS_APP = ()
KEYS_REPO = ()
KEY_TYPES = ("avb", "core", "apex_container", "apex_payload", "apex_apk")
MAPPED_KEY_TYPES = ("core",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "core": "keys_core",
    "apex_container": "keys_apex",
    "apex_payload": "keys_apex",
    "apex_apk": "keys_apex_apk",
}
"""


@pytest.fixture(params=("make_key", "python", "updatekeys"))
def signing_mode(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def updatekeys_tree(tmp_path: Path) -> Path:
    (tmp_path / "keys" / "bramble").mkdir(parents=True)
    return tmp_path


def run_updatekeys(
    root: Path,
    signing_mode: str,
    *,
    keymapper: str = "id2b",
    metadata: Path = TEST_METADATA,
    subject: str = SUBJECT,
) -> subprocess.CompletedProcess[str]:
    environment = {
        "KEYMAPPER": keymapper,
        "METADATA_FILE": str(metadata),
        "AVBTOOL_BIN": str(AVBTOOL),
        "GENERATE_VERITY_KEY_BIN": "/bin/true",
    }
    input_text = None
    if signing_mode == "updatekeys":
        environment["USE_PYTHON_UPDATEKEYS"] = "y"
        environment["MAKE_KEY_BIN"] = str(root / "missing-make_key")
    elif signing_mode == "python":
        environment["USE_PYTHON_SIGNING"] = "y"
        environment["MAKE_KEY_BIN"] = str(root / "missing-make_key")
    else:
        environment["MAKE_KEY_BIN"] = str(
            AOSP_TOP / "development" / "tools" / "make_key",
        )
        input_text = "\n" * 32
    return run(
        [SCRIPTS_DIR / "updatekeys.sh", "keys/bramble", subject],
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


@pytest.mark.parametrize("signing_mode", ("updatekeys",))
def test_full_updatekeys_with_legacy_keymapper(
    updatekeys_tree: Path,
    signing_mode: str,
) -> None:
    metadata = updatekeys_tree / "metadata.py"
    metadata.write_text(LEGACY_METADATA)

    result = run_updatekeys(
        updatekeys_tree,
        signing_mode,
        keymapper="legacy",
        metadata=metadata,
    )

    assert result.returncode == 0, result.stderr
    keys = updatekeys_tree / "keys/bramble"
    assert (keys / "releasekey.pk8").is_file()
    assert (keys / "releasekey.x509.pem").is_file()
    assert (keys / "com.android.adbd.pk8").is_file()
    assert (keys / "com.android.adbd.x509.pem").is_file()
    expected_vbmeta = keys / "expected-vbmeta.avbpubkey"
    expected_payload = keys / "expected-payload.avbpubkey"
    run(
        [
            AVBTOOL,
            "extract_public_key",
            "--key",
            keys / "avb.pem",
            "--output",
            expected_vbmeta,
        ],
    )
    run(
        [
            AVBTOOL,
            "extract_public_key",
            "--key",
            keys / "com.android.adbd.pem",
            "--output",
            expected_payload,
        ],
    )
    assert (keys / "avb_custom_key.img").read_bytes() == (
        expected_vbmeta.read_bytes()
    )
    assert (keys / "com.android.adbd.avbpubkey").read_bytes() == (
        expected_payload.read_bytes()
    )


def test_updatekeys_writes_the_subject_as_given(
    updatekeys_tree: Path,
    signing_mode: str,
) -> None:
    result = run_updatekeys(
        updatekeys_tree,
        signing_mode,
        subject="/O=Calyx Institute/CN=_KEY_LABEL_",
    )

    assert result.returncode == 0, result.stderr
    certificates = sorted((updatekeys_tree / "keys").rglob("*.x509.pem"))
    assert certificates
    for certificate in certificates:
        subject = run(
            ["openssl", "x509", "-noout", "-subject", "-in", certificate],
        ).stdout
        assert "CN=_KEY_LABEL_" in subject


def test_updatekeys_refuses_a_key_whose_pem_exists(
    updatekeys_tree: Path,
    signing_mode: str,
) -> None:
    metadata = updatekeys_tree / "metadata.py"
    metadata.write_text(LEGACY_METADATA)
    payload = updatekeys_tree / "keys/bramble/com.android.adbd.pem"
    payload.write_text("payload key\n")

    result = run_updatekeys(
        updatekeys_tree,
        signing_mode,
        keymapper="legacy",
        metadata=metadata,
    )

    assert result.returncode != 0
    assert "com.android.adbd already exists" in result.stderr
    assert not (updatekeys_tree / "keys/bramble/com.android.adbd.pk8").exists()
    assert payload.read_text() == "payload key\n"
