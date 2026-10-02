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
