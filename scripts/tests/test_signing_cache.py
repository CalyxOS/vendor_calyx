#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import SCRIPTS_DIR


@pytest.fixture
def signing_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "signing_cache_under_test",
        SCRIPTS_DIR / "pkcs11" / "signing_cache.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("YUBIHSM_SIGNING_CACHE", str(tmp_path / "cache"))
    return module


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
        ({"min_sdk_version": "31"}, None),
    ),
    ids=("key-alias", "certificate", "input", "min-sdk-version"),
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
