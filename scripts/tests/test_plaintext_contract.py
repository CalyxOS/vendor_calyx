#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest
from conftest import SCRIPTS_DIR, run
from signing.models import KeyReference, KeySpec
from signing.plaintext import PlaintextBackend

SUBJECT = "/C=US/O=Calyx Institute/CN=Shared plaintext contract"


class GenerationRejected(Exception):
    """
    Normalized rejection raised by a plaintext implementation adapter.
    """


@dataclass(frozen=True, slots=True)
class PlaintextArtifacts:
    """
    AOSP key artifacts produced by a plaintext implementation.
    """

    private_key: Path
    certificate: Path


class PlaintextImplementation(Protocol):
    """
    Minimal behavior shared by Bash and Python plaintext key generators.
    """

    def generate(self) -> PlaintextArtifacts:
        """
        Generate one RSA key and its self-signed certificate.

        Returns:
            Paths to the generated AOSP artifacts.

        Raises:
            GenerationRejected: If destination artifacts already exist.
        """
        ...


class BashPlaintextImplementation:
    """
    Exercise plaintext generation through the ``mkkey.sh`` entry point.
    """

    def __init__(self, tools: Path, work: Path) -> None:
        """
        Install a cryptographic AOSP ``make_key`` test dependency.

        Args:
            tools: Directory to install the ``make_key`` stand-in in.
            work: Directory in which key artifacts should be generated.

        Returns:
            None.
        """
        self.work = work
        self.make_key = tools / "make_key"
        self.make_key.write_text(
            """#!/bin/bash
set -euo pipefail
openssl genrsa -out "$1.pem" 2048
openssl req -new -x509 -sha256 -key "$1.pem" -out "$1.x509.pem" \
  -subj "$2" -days 10000
openssl pkcs8 -in "$1.pem" -topk8 -outform DER -out "$1.pk8" -nocrypt
""",
        )
        self.make_key.chmod(self.make_key.stat().st_mode | stat.S_IXUSR)

    def generate(self) -> PlaintextArtifacts:
        """
        Generate artifacts through ``mkkey.sh``.

        Returns:
            Paths to the generated AOSP artifacts.

        Raises:
            GenerationRejected: If ``mkkey.sh`` rejects generation.
        """
        result = run(
            [SCRIPTS_DIR / "mkkey.sh", "releasekey", SUBJECT],
            cwd=self.work,
            env={"MAKE_KEY_BIN": str(self.make_key)},
            check=False,
        )
        if result.returncode:
            raise GenerationRejected(result.stderr)
        return PlaintextArtifacts(
            self.work / "releasekey.pk8",
            self.work / "releasekey.x509.pem",
        )


class PythonPlaintextImplementation:
    """
    Exercise plaintext generation through ``PlaintextBackend``.
    """

    def __init__(self, work: Path) -> None:
        """
        Configure a Python plaintext backend in a temporary directory.

        Args:
            work: Directory in which key artifacts should be generated.

        Returns:
            None.
        """
        self.work = work
        self.backend = PlaintextBackend(work)
        reference = KeyReference("0x2000", "releasekey")
        self.spec = KeySpec(reference, 2048)

    def generate(self) -> PlaintextArtifacts:
        """
        Generate artifacts through ``PlaintextBackend``.

        Returns:
            Paths to the generated AOSP artifacts.

        Raises:
            GenerationRejected: If the backend rejects existing artifacts.
        """
        try:
            self.backend.generate_key(self.spec)
            self.backend.generate_certificate(self.spec, SUBJECT)
        except FileExistsError as error:
            raise GenerationRejected(str(error)) from error
        return PlaintextArtifacts(
            self.work / "releasekey.pk8",
            self.work / "releasekey.x509.pem",
        )


@pytest.fixture(params=("bash", "python"))
def plaintext_implementation(
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> PlaintextImplementation:
    work = tmp_path / f"{request.param}-keys"
    work.mkdir()
    if request.param == "bash":
        return BashPlaintextImplementation(tmp_path, work)
    return PythonPlaintextImplementation(work)


def test_plaintext_generation_contract(
    plaintext_implementation: PlaintextImplementation,
) -> None:
    artifacts = plaintext_implementation.generate()

    private_key = run(
        [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            artifacts.private_key,
            "-text",
            "-noout",
        ],
    )
    assert "Private-Key: (2048 bit" in private_key.stdout
    subject = run(
        [
            "openssl",
            "x509",
            "-in",
            artifacts.certificate,
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
    )
    assert subject.stdout.strip() == (
        "subject=CN=Shared plaintext contract,O=Calyx Institute,C=US"
    )
    private_public_key = run(
        [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            artifacts.private_key,
            "-pubout",
        ],
    )
    certificate_public_key = run(
        ["openssl", "x509", "-in", artifacts.certificate, "-pubkey", "-noout"],
    )
    assert private_public_key.stdout == certificate_public_key.stdout


def test_plaintext_generation_contract_refuses_overwrite(
    plaintext_implementation: PlaintextImplementation,
) -> None:
    plaintext_implementation.generate()

    with pytest.raises(GenerationRejected):
        plaintext_implementation.generate()
