#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import assert_certificate_of
from cryptography.hazmat.primitives import serialization
from signing.plaintext import generate_certified_key

SUBJECT = "/C=US/O=Calyx Institute/CN=Plaintext backend"


def test_plaintext_backend_refuses_to_overwrite_keys(tmp_path: Path) -> None:
    generate_certified_key(tmp_path / "keys", "bramble/releasekey", SUBJECT)

    with pytest.raises(FileExistsError):
        generate_certified_key(
            tmp_path / "keys",
            "bramble/releasekey",
            SUBJECT,
        )


def test_plaintext_backend_rejects_escaping_labels(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes"):
        generate_certified_key(tmp_path / "keys", "../releasekey", SUBJECT)


def test_plaintext_backend_certifies_the_generated_key(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "keys/bramble/releasekey.pk8"
    certificate = tmp_path / "keys/bramble/releasekey.x509.pem"

    generate_certified_key(tmp_path / "keys", "bramble/releasekey", SUBJECT)

    assert_certificate_of(
        serialization.load_der_private_key(
            private_key.read_bytes(),
            None,
        ).public_key(),
        certificate,
        "CN=Plaintext backend,O=Calyx Institute,C=US",
    )
