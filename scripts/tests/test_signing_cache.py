#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run

SIGNING_CACHE = SCRIPTS_DIR / "pkcs11" / "signing_cache.py"


def kms_command(
    certificate: Path,
    *,
    alias: str = "0x1100",
    min_sdk_version: str = "30",
) -> list[str]:
    return [
        "java",
        "-jar",
        "apksigner.jar",
        "sign",
        "--min-sdk-version",
        min_sdk_version,
        "--kms-type",
        "calyx",
        "--kms-key-alias",
        alias,
        "--cert",
        str(certificate),
        "--out",
        "out.apk",
        "in.apk",
    ]


def cache(tmp_path: Path, operation: str, command: list[str]) -> int:
    return run(
        [SIGNING_CACHE, operation, *command],
        cwd=tmp_path,
        env={"YUBIHSM_SIGNING_CACHE": str(tmp_path / "cache")},
        check=False,
    ).returncode


def write_certificate(directory: Path, contents: bytes) -> Path:
    directory.mkdir(exist_ok=True)
    certificate = directory / "releasekey.x509.pem"
    certificate.write_bytes(contents)
    return certificate


def kms_cached(tmp_path: Path) -> Path:
    (tmp_path / "cache").mkdir()
    (tmp_path / "in.apk").write_bytes(b"unsigned")
    (tmp_path / "out.apk").write_bytes(b"signed")
    certificate = write_certificate(tmp_path / "first", b"certificate")
    assert cache(tmp_path, "--to-cache", kms_command(certificate)) == 0
    (tmp_path / "out.apk").unlink()
    return certificate


def test_kms_from_cache_hits_with_the_same_certificate_elsewhere(
    tmp_path: Path,
) -> None:
    kms_cached(tmp_path)
    certificate = write_certificate(tmp_path / "second", b"certificate")

    assert cache(tmp_path, "--from-cache", kms_command(certificate)) == 0
    assert (tmp_path / "out.apk").read_bytes() == b"signed"


@pytest.mark.parametrize(
    ("options", "replaced"),
    (
        ({"alias": "0x1200"}, None),
        ({}, "first/releasekey.x509.pem"),
        ({}, "in.apk"),
        ({"min_sdk_version": "31"}, None),
    ),
    ids=("key-alias", "certificate", "input", "min-sdk-version"),
)
def test_kms_from_cache_misses_for_a_changed_signing_input(
    tmp_path: Path,
    options: dict[str, str],
    replaced: str | None,
) -> None:
    certificate = kms_cached(tmp_path)
    if replaced:
        (tmp_path / replaced).write_bytes(b"other")
    command = kms_command(certificate, **options)

    assert cache(tmp_path, "--from-cache", command) == 1
