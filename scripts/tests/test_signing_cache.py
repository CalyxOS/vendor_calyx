#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest
from conftest import PKCS11_DIR, load_script


@pytest.fixture
def signing_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ModuleType:
    module = load_script(PKCS11_DIR / "signing_cache.py")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("YUBIHSM_SIGNING_CACHE", str(tmp_path / "cache"))
    return module


def kms_command(certificate: Path, *, alias: str = "0x1100") -> list[str]:
    return [
        "java",
        "-jar",
        "apksigner.jar",
        "sign",
        "--kms-type",
        "external",
        "--kms-key-alias",
        alias,
        "--cert",
        str(certificate),
        "--out",
        "out.apk",
        "in.apk",
    ]


def write_certificate(directory: Path, contents: bytes) -> Path:
    directory.mkdir(exist_ok=True)
    certificate = directory / "releasekey.x509.pem"
    certificate.write_bytes(contents)
    return certificate


def kms_cached(signing_cache: ModuleType, tmp_path: Path) -> Path:
    (tmp_path / "cache").mkdir()
    (tmp_path / "in.apk").write_bytes(b"unsigned")
    (tmp_path / "out.apk").write_bytes(b"signed")
    certificate = write_certificate(tmp_path / "first", b"certificate")
    signing_cache.to_cache(kms_command(certificate))
    (tmp_path / "out.apk").unlink()
    return certificate


def test_kms_from_cache_hits_with_the_same_certificate_elsewhere(
    signing_cache: ModuleType,
    tmp_path: Path,
) -> None:
    kms_cached(signing_cache, tmp_path)
    certificate = write_certificate(tmp_path / "second", b"certificate")

    assert signing_cache.from_cache(kms_command(certificate))
    assert (tmp_path / "out.apk").read_bytes() == b"signed"


@pytest.mark.parametrize(
    ("options", "replaced"),
    (
        ({"alias": "0x1200"}, None),
        ({}, "first/releasekey.x509.pem"),
        ({}, "in.apk"),
    ),
    ids=("key-alias", "certificate", "input"),
)
def test_kms_from_cache_misses_for_a_changed_signing_input(
    signing_cache: ModuleType,
    tmp_path: Path,
    options: dict[str, str],
    replaced: str | None,
) -> None:
    certificate = kms_cached(signing_cache, tmp_path)
    if replaced:
        (tmp_path / replaced).write_bytes(b"other")
    command = kms_command(certificate, **options)

    assert not signing_cache.from_cache(command)
    assert not (tmp_path / "out.apk").exists()
