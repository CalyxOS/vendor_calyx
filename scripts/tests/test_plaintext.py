#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import run
from signing.models import (
    KeyReference,
    KeySpec,
)
from signing.plaintext import PlaintextBackend


@pytest.fixture
def reference() -> KeyReference:
    return KeyReference("0x2000", "bramble/releasekey")


@pytest.fixture
def backend(tmp_path: Path) -> PlaintextBackend:
    return PlaintextBackend(tmp_path / "keys")


def test_plaintext_backend_refuses_to_overwrite_keys(
    backend: PlaintextBackend,
    reference: KeyReference,
) -> None:
    spec = KeySpec(reference, 2048)
    backend.generate_key(spec)

    with pytest.raises(FileExistsError):
        backend.generate_key(spec)


def test_plaintext_backend_rejects_escaping_labels(
    backend: PlaintextBackend,
) -> None:
    reference = KeyReference("0x2000", "../releasekey")

    with pytest.raises(ValueError, match="escapes"):
        backend.key_exists(reference)


def test_plaintext_backend_certifies_the_generated_key(
    backend: PlaintextBackend,
    reference: KeyReference,
    tmp_path: Path,
) -> None:
    spec = KeySpec(reference, 2048)
    private_key = tmp_path / "keys/bramble/releasekey.pk8"
    certificate = tmp_path / "keys/bramble/releasekey.x509.pem"

    backend.generate_key(spec)
    backend.generate_certificate(
        spec,
        "/C=US/O=Calyx Institute/CN=Plaintext backend",
    )

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
    assert subject.stdout.strip() == (
        "subject=CN=Plaintext backend,O=Calyx Institute,C=US"
    )
    private_public_key = run(
        ["openssl", "pkey", "-inform", "DER", "-in", private_key, "-pubout"],
    )
    certificate_public_key = run(
        ["openssl", "x509", "-in", certificate, "-pubkey", "-noout"],
    )
    assert private_public_key.stdout == certificate_public_key.stdout
