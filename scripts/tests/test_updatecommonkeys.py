#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

SUBJECT = "/C=US/O=Calyx Institute/CN=Test app signing key"


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


METADATA = """KEYS_AVB = ()
KEYS_OTHER = ()
KEYS_CORE = ()
KEYS_APEX = ()
KEYS_APEX_APK = ()
KEYS_APP = ("testapp",)
KEYS_REPO = ()
KEY_TYPES = ("app",)
MAPPED_KEY_TYPES = ("app",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {"app": "keys_app"}
"""


@pytest.fixture
def updatecommonkeys_environment(tmp_path: Path) -> dict[str, str]:
    """
    Run updatecommonkeys.sh in place against metadata with a single app
    key and a make_key stand-in, since this only needs one app key to
    exercise the recovery loop.
    """
    metadata = tmp_path / "metadata.py"
    metadata.write_text(METADATA)
    make_key = tmp_path / "make_key"
    _write_executable(
        make_key,
        """#!/bin/bash
set -euo pipefail
mkdir -p "$(dirname "$1")"
printf 'PRIVATE KEY\n' > "$1.pk8"
chmod 0600 "$1.pk8"
printf 'CERTIFICATE subject=%s\n' "$2" > "$1.x509.pem"
""",
    )
    return {
        "METADATA_FILE": str(metadata),
        "MAKE_KEY_BIN": str(make_key),
        "KEYMAPPER": "legacy",
    }


def test_updatecommonkeys_generates_app_key(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    script = SCRIPTS_DIR / "updatecommonkeys.sh"

    result = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (key_dir / "testapp.pk8").exists()
    assert (key_dir / "testapp.x509.pem").exists()


def test_updatecommonkeys_refuses_a_key_without_its_certificate(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    """
    A private key without its certificate must stop the run instead of
    getting a new certificate, which would be a different signer.
    """
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    script = SCRIPTS_DIR / "updatecommonkeys.sh"

    generated = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    (key_dir / "testapp.x509.pem").unlink()

    refused = run(
        [script, key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert refused.returncode != 0
    assert "exists without testapp.x509.pem" in refused.stderr
    assert not (key_dir / "testapp.x509.pem").exists()


def test_updatecommonkeys_skips_a_metadata_placeholder(
    updatecommonkeys_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    metadata = Path(updatecommonkeys_environment["METADATA_FILE"])
    metadata.write_text(
        METADATA.replace(
            'KEYS_APP = ("testapp",)',
            'KEYS_APP = ("testapp", "", "otherapp")',
        ),
    )
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    result = run(
        [SCRIPTS_DIR / "updatecommonkeys.sh", key_dir, SUBJECT],
        env=updatecommonkeys_environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    for name in ("testapp", "otherapp"):
        assert (key_dir / f"{name}.pk8").exists()
        assert (key_dir / f"{name}.x509.pem").exists()
    assert not [path for path in key_dir.rglob(".*")]
