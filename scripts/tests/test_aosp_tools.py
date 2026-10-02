#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

pytestmark = [pytest.mark.aosp, pytest.mark.usefixtures("aosp_top")]
SUBJECT = "/C=US/O=Calyx Institute/CN=AOSP integration test"


def test_mkkey_with_aosp_make_key(tmp_path: Path) -> None:
    work = tmp_path / "keys"
    work.mkdir()
    run(
        [SCRIPTS_DIR / "mkkey.sh", "releasekey", SUBJECT],
        cwd=work,
        input_text="\n",
        check=False,
    )

    assert {path.name for path in work.iterdir()} == {
        "releasekey.pk8",
        "releasekey.x509.pem",
    }
    pkcs8 = work / "releasekey.pk8"
    certificate = work / "releasekey.x509.pem"
    private_key = run(
        ["openssl", "pkey", "-inform", "DER", "-in", pkcs8, "-text", "-noout"],
    )
    assert "Private-Key: (2048 bit" in private_key.stdout

    subject = run(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
    )
    assert (
        subject.stdout.strip()
        == "subject=CN=AOSP integration test,O=Calyx Institute,C=US"
    )

    private_public_key = run(
        ["openssl", "pkey", "-inform", "DER", "-in", pkcs8, "-pubout"],
    )
    certificate_public_key = run(
        ["openssl", "x509", "-in", certificate, "-pubkey", "-noout"],
    )
    assert private_public_key.stdout == certificate_public_key.stdout
