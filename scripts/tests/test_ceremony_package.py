#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import signal
import zipfile
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, prepare_ceremony_package, sha256

FAKE_CURL = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -L) shift ;;
    *) link=$1; shift ;;
  esac
done
printf "downloaded %s\\n" "${link##*/}" > "$out"
"""


def _downloaded_sha(name: str) -> str:
    return hashlib.sha256(f"downloaded {name}\n".encode()).hexdigest()


SMALL_MANIFEST = (
    "filename\tsha256sum\tfilesize\tlink\n"
    "start.sh\n"
    "vendor/calyx/scripts/hsm_provisioning/audit.py\n"
    "vendor/calyx/scripts/hsm_provisioning/provision.py\n"
    "vendor/calyx/scripts/hsm_provisioning/keys/1.pub\n"
    "vendor/calyx/scripts/hsm_provisioning/calyx-shamir-split\t"
    f"{_downloaded_sha('calyx-shamir-split')}\t100\t"
    "https://example.invalid/calyx-shamir-split\n"
    f"sdk/sdk.tar.gz\t{_downloaded_sha('sdk.tar.gz')}\t100\t"
    "https://example.invalid/sdk.tar.gz\n"
)


def _outcome(
    tmp_path: Path,
    manifest: str | None,
) -> tuple[int, str, str, bytes | None]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    environment: dict[str, str] = {}
    if manifest is not None:
        (tmp_path / "manifest.tsv").write_text(manifest)
        environment["MANIFEST_FILE"] = str(tmp_path / "manifest.tsv")
    result = prepare_ceremony_package(tmp_path, FAKE_CURL, environment)
    zip_path = tmp_path / "out" / "ceremony.zip"
    return (
        result.returncode,
        result.stdout,
        result.stderr,
        zip_path.read_bytes() if zip_path.exists() else None,
    )


def test_package_holds_the_manifest_files(tmp_path: Path) -> None:
    returncode, stdout, stderr, data = _outcome(tmp_path, SMALL_MANIFEST)

    assert returncode == 0, stderr
    assert data is not None
    archive = tmp_path / "ceremony.zip"
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        assert package.read("ceremony/sdk/sdk.tar.gz") == (
            b"downloaded sdk.tar.gz\n"
        )
        modes = {
            info.filename: (info.external_attr >> 16) & 0o777
            for info in package.infolist()
        }
        assert {info.date_time for info in package.infolist()} == {
            (2010, 1, 1, 0, 0, 0),
        }
    assert names == sorted(
        names,
        key=lambda name: name.removesuffix("/").encode(),
    )
    assert "ceremony/scripts/audit.py" in names
    assert "ceremony/scripts/calyx-shamir-split" in names
    assert not any(name.startswith("ceremony/vendor") for name in names)
    assert "ceremony/manifest.tsv" not in names
    assert modes["ceremony/start.sh"] == 0o755
    assert modes["ceremony/scripts/audit.py"] == 0o755
    assert modes["ceremony/scripts/calyx-shamir-split"] == 0o755
    assert modes["ceremony/scripts/keys/1.pub"] == 0o644
    assert modes["ceremony/scripts/"] == 0o755
    assert f"{hashlib.sha256(data).hexdigest()}  " in stdout


def test_package_is_reproducible(tmp_path: Path) -> None:
    first = _outcome(tmp_path / "first", SMALL_MANIFEST)
    second = _outcome(tmp_path / "second", SMALL_MANIFEST)

    assert first[0] == second[0] == 0, first[2]
    assert first[3] == second[3]


def test_package_refuses_files_that_fail_verification(tmp_path: Path) -> None:
    returncode, _, stderr, data = _outcome(tmp_path, None)

    assert returncode == 1
    assert data is None
    assert "The following files FAILED sha256sum verification:" in stderr
    assert "  sdk/yubihsm2-sdk-2025-06-debian12-amd64.tar.gz\n" in stderr


@pytest.mark.parametrize(
    ("line", "message"),
    (
        (
            "vendor/calyx/scripts/hsm_provisioning/missing.py\n",
            "Cannot find vendor/calyx/scripts/hsm_provisioning/missing.py.\n",
        ),
        ("../escape\n", "Unacceptable path traversal in ../escape\n"),
    ),
    ids=("missing-file", "traversal"),
)
def test_package_refuses_a_bad_manifest_line(
    tmp_path: Path,
    line: str,
    message: str,
) -> None:
    returncode, _, stderr, data = _outcome(tmp_path, SMALL_MANIFEST + line)

    assert returncode == 1
    assert data is None
    assert stderr.startswith(message)


def test_package_reports_a_download_killed_by_a_signal(tmp_path: Path) -> None:
    manifest = SMALL_MANIFEST.replace(
        "\t100\thttps://example.invalid/sdk",
        "\t0\thttps://example.invalid/sdk",
    )

    returncode, _, _, data = _outcome(tmp_path, manifest)

    assert returncode == 128 + signal.SIGXFSZ
    assert data is None


@pytest.mark.parametrize("matches", (True, False))
def test_package_checks_a_local_file_against_its_checksum(
    tmp_path: Path,
    matches: bool,
) -> None:
    provision = SCRIPTS_DIR / "hsm_provisioning" / "provision.py"
    checksum = sha256(provision) if matches else "0" * 64
    manifest = SMALL_MANIFEST.replace(
        "vendor/calyx/scripts/hsm_provisioning/provision.py\n",
        f"vendor/calyx/scripts/hsm_provisioning/provision.py\t{checksum}\n",
    )

    _, _, stderr, _ = _outcome(tmp_path, manifest)

    warned = "does not match expected sha256sum and no link provided!"
    assert (warned in stderr) is not matches, stderr
