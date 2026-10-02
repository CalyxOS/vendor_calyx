#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

from conftest import SCRIPTS_DIR, run

SIGNING_CACHE = SCRIPTS_DIR / "pkcs11" / "signing_cache.py"


def apksigner_command(
    config: Path,
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
        "--ks",
        "NONE",
        "--ks-type",
        "PKCS11",
        "--provider-class",
        "sun.security.pkcs11.SunPKCS11",
        "--provider-arg",
        str(config),
        "--ks-key-alias",
        alias,
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


def write_config(directory: Path, library: str) -> Path:
    directory.mkdir()
    config = directory / "sunpkcs11.cfg"
    config.write_text(f"library = {library}\n")
    return config


def cached(tmp_path: Path) -> Path:
    (tmp_path / "cache").mkdir()
    (tmp_path / "in.apk").write_bytes(b"unsigned")
    (tmp_path / "out.apk").write_bytes(b"signed")
    config = write_config(tmp_path / "first", "/usr/lib/module.so")
    assert cache(tmp_path, "--to-cache", apksigner_command(config)) == 0
    (tmp_path / "out.apk").unlink()
    return config


def test_from_cache_hits_with_the_same_config_in_another_directory(
    tmp_path: Path,
) -> None:
    cached(tmp_path)
    config = write_config(tmp_path / "second", "/usr/lib/module.so")

    assert cache(tmp_path, "--from-cache", apksigner_command(config)) == 0
    assert (tmp_path / "out.apk").read_bytes() == b"signed"


def test_from_cache_misses_for_unseen_input(tmp_path: Path) -> None:
    config = cached(tmp_path)
    (tmp_path / "in.apk").write_bytes(b"other input")

    assert cache(tmp_path, "--from-cache", apksigner_command(config)) == 1


def test_from_cache_misses_for_different_min_sdk_version(
    tmp_path: Path,
) -> None:
    config = cached(tmp_path)
    command = apksigner_command(config, min_sdk_version="31")

    assert cache(tmp_path, "--from-cache", command) == 1


def test_from_cache_misses_for_different_key_alias(tmp_path: Path) -> None:
    config = cached(tmp_path)
    command = apksigner_command(config, alias="0x1200")

    assert cache(tmp_path, "--from-cache", command) == 1


def test_from_cache_misses_for_different_config_contents(
    tmp_path: Path,
) -> None:
    cached(tmp_path)
    config = write_config(tmp_path / "second", "/usr/lib/other.so")

    assert cache(tmp_path, "--from-cache", apksigner_command(config)) == 1
