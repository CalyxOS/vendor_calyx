#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

from conftest import SCRIPTS_DIR, run

SIGNING_CACHE = SCRIPTS_DIR / "pkcs11" / "signing_cache.py"


def apksigner_command(*, alias: str = "0x1100") -> list[str]:
    return [
        "java",
        "-jar",
        "apksigner.jar",
        "sign",
        "--min-sdk-version",
        "30",
        "--ks",
        "NONE",
        "--ks-type",
        "PKCS11",
        "--provider-class",
        "sun.security.pkcs11.SunPKCS11",
        "--provider-arg",
        "sunpkcs11.cfg",
        "--ks-key-alias",
        alias,
        "--out",
        "out.apk",
        "in.apk",
    ]


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


def cache(tmp_path: Path, operation: str, command: list[str]) -> int:
    return run(
        [SIGNING_CACHE, operation, *command],
        cwd=tmp_path,
        env={"YUBIHSM_SIGNING_CACHE": str(tmp_path / "cache")},
        check=False,
    ).returncode


def cached(tmp_path: Path) -> None:
    (tmp_path / "cache").mkdir()
    (tmp_path / "in.apk").write_bytes(b"unsigned")
    (tmp_path / "out.apk").write_bytes(b"signed")
    assert cache(tmp_path, "--to-cache", apksigner_command()) == 0
    (tmp_path / "out.apk").unlink()


def test_from_cache_hits_for_the_same_input_and_key_alias(
    tmp_path: Path,
) -> None:
    cached(tmp_path)

    assert cache(tmp_path, "--from-cache", apksigner_command()) == 0
    assert (tmp_path / "out.apk").read_bytes() == b"signed"


def test_from_cache_misses_for_unseen_input(tmp_path: Path) -> None:
    cached(tmp_path)
    (tmp_path / "in.apk").write_bytes(b"other input")

    assert cache(tmp_path, "--from-cache", apksigner_command()) == 1


def test_from_cache_misses_for_different_key_alias(tmp_path: Path) -> None:
    cached(tmp_path)
    command = apksigner_command(alias="0x1200")

    assert cache(tmp_path, "--from-cache", command) == 1


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


def test_kms_from_cache_misses_for_different_key_alias(
    tmp_path: Path,
) -> None:
    certificate = kms_cached(tmp_path)
    command = kms_command(certificate, alias="0x1200")

    assert cache(tmp_path, "--from-cache", command) == 1


def test_kms_from_cache_misses_for_a_replaced_certificate(
    tmp_path: Path,
) -> None:
    certificate = kms_cached(tmp_path)
    certificate.write_bytes(b"other certificate")

    assert cache(tmp_path, "--from-cache", kms_command(certificate)) == 1
