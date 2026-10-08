#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from conftest import REPO_ROOT, SCRIPTS_DIR, TEST_METADATA, run, sha256
from signing.keymap import Id2bKeymapper
from signing.metadata import load_metadata
from signing.release_arguments import build_release_arguments, make_get_key

pytestmark = [pytest.mark.aosp, pytest.mark.usefixtures("aosp_top")]
SUBJECT = "/C=US/O=Calyx Institute/CN=updatekeys integration test"
AOSP_TOP = REPO_ROOT.parents[1]
AVBTOOL = AOSP_TOP / "out" / "host" / "linux-x86" / "bin" / "avbtool"
MODES_FIXTURE = Path(__file__).parent / "fixtures" / "updatekeys-modes.json"
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


@pytest.fixture
def updatekeys_tree(tmp_path: Path) -> Path:
    (tmp_path / "keys" / "bramble").mkdir(parents=True)
    return tmp_path


def run_updatekeys(
    root: Path,
    *,
    keymapper: str = "id2b",
    metadata: Path = TEST_METADATA,
    subject: str = SUBJECT,
) -> subprocess.CompletedProcess[str]:
    return run(
        [SCRIPTS_DIR / "updatekeys.sh", "keys/bramble", subject],
        cwd=root,
        env={
            "KEYMAPPER": keymapper,
            "METADATA_FILE": str(metadata),
            "AVBTOOL_BIN": str(AVBTOOL),
            "GENERATE_VERITY_KEY_BIN": "/bin/true",
        },
        check=False,
    )


def assert_avb_public_key_matches(root: Path, key_name: str) -> None:
    stored_public_key = root / "keys" / f"{key_name}.avbpubkey"
    extracted_public_key = root / "keys" / f"{key_name}.expected.avbpubkey"
    run(
        [
            AVBTOOL,
            "extract_public_key",
            "--key",
            root / "keys" / f"{key_name}.pem",
            "--output",
            extracted_public_key,
        ],
    )
    assert stored_public_key.read_bytes() == extracted_public_key.read_bytes()


def test_updatekeys_is_idempotent(updatekeys_tree: Path) -> None:
    first = run_updatekeys(updatekeys_tree)
    assert first.returncode == 0, first.stderr
    keys = updatekeys_tree / "keys"
    before = {
        path.name: sha256(path) for path in keys.iterdir() if path.is_file()
    }
    assert sorted(before) == sorted(json.loads(MODES_FIXTURE.read_text()))

    second = run_updatekeys(updatekeys_tree)
    assert second.returncode == 0, second.stderr
    after = {
        path.name: sha256(path) for path in keys.iterdir() if path.is_file()
    }
    assert after == before
    assert_avb_public_key_matches(updatekeys_tree, "0x2000")
    assert_avb_public_key_matches(updatekeys_tree, "0x1300")


def test_updatekeys_avb_key_paths_match_release_signing_expectation(
    updatekeys_tree: Path,
) -> None:
    """
    build_release_arguments() looks up the AVB keys updatekeys.sh
    generates, so every path it requests must exist after a run.
    """
    result = run_updatekeys(updatekeys_tree)
    assert result.returncode == 0, result.stderr

    metadata = load_metadata(TEST_METADATA)
    keymapper = Id2bKeymapper(metadata)
    get_key = make_get_key(keymapper, {}, device="bramble")
    release_args = build_release_arguments(metadata, get_key, device="bramble")

    avb_key_paths = [
        release_args.signing_args[index + 1]
        for index, arg in enumerate(release_args.signing_args)
        if arg.startswith("--avb_") and arg.endswith("_key")
    ]
    assert avb_key_paths
    for path in avb_key_paths:
        assert (updatekeys_tree / path).is_file(), (
            f"release.sh's own AVB signing invocation would look for "
            f"{path!r}, which updatekeys.sh never created"
        )


def test_full_updatekeys_with_legacy_keymapper(
    updatekeys_tree: Path,
) -> None:
    metadata = updatekeys_tree / "metadata.py"
    metadata.write_text(LEGACY_METADATA)

    result = run_updatekeys(
        updatekeys_tree,
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
) -> None:
    result = run_updatekeys(
        updatekeys_tree,
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
) -> None:
    metadata = updatekeys_tree / "metadata.py"
    metadata.write_text(LEGACY_METADATA)
    payload = updatekeys_tree / "keys/bramble/com.android.adbd.pem"
    payload.write_text("payload key\n")

    result = run_updatekeys(
        updatekeys_tree,
        keymapper="legacy",
        metadata=metadata,
    )

    assert result.returncode != 0
    assert "com.android.adbd already exists" in result.stderr
    assert not (updatekeys_tree / "keys/bramble/com.android.adbd.pk8").exists()
    assert payload.read_text() == "payload key\n"
