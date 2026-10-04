#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import os
import re
import signal
import stat
import sys
import zipfile
from pathlib import Path

import pytest
from conftest import REPO_ROOT, SCRIPTS_DIR, run

PACKAGE_DIR = SCRIPTS_DIR / "hsm_provisioning"
IMPLEMENTATIONS = ["bash", "python"]
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


def _source_directory(root: Path) -> Path:
    source = root / "source"
    (source / "vendor").mkdir(parents=True)
    (source / "vendor" / "calyx").symlink_to(REPO_ROOT)
    return source


def _outcome(
    tmp_path: Path,
    implementation: str,
    manifest: str | None,
) -> tuple[int, str, str, bytes | None]:
    root = tmp_path / implementation
    root.mkdir()
    environment = {"SOURCE_DIRECTORY": str(_source_directory(root))}
    if manifest is not None:
        (root / "manifest.tsv").write_text(manifest)
        environment["MANIFEST_FILE"] = str(root / "manifest.tsv")
    fake_bin = root / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
    out = root / "out"
    out.mkdir()
    result = run(
        ["bash", PACKAGE_DIR / "prepare.package.sh"],
        cwd=out,
        env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "TMPDIR": str(root),
            **environment,
            "USE_PYTHON_PREPARE_PACKAGE": (
                "y" if implementation == "python" else ""
            ),
        },
        check=False,
    )
    zip_path = out / "ceremony.zip"

    def normalize(text: str) -> str:
        return re.sub(
            r"/tmp\.\w+/",
            "/tmp.X/",
            text.replace(str(root), "<root>"),
        )

    return (
        result.returncode,
        normalize(result.stdout),
        normalize(result.stderr),
        zip_path.read_bytes() if zip_path.exists() else None,
    )


@pytest.mark.parametrize(
    "manifest",
    [
        SMALL_MANIFEST,
        None,
        SMALL_MANIFEST + "vendor/calyx/scripts/hsm_provisioning/missing.py\n",
        SMALL_MANIFEST + "../escape\n",
    ],
    ids=["small", "shipped", "missing-file", "traversal"],
)
def test_python_package_matches_bash(
    tmp_path: Path,
    manifest: str | None,
) -> None:
    bash, python = (
        _outcome(tmp_path, implementation, manifest)
        for implementation in IMPLEMENTATIONS
    )

    assert python == bash


def test_package_holds_the_manifest_files(tmp_path: Path) -> None:
    returncode, stdout, stderr, data = _outcome(
        tmp_path,
        "python",
        SMALL_MANIFEST,
    )

    assert returncode == 0, stderr
    assert data is not None
    archive = tmp_path / "ceremony.zip"
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        assert package.read("ceremony/sdk/sdk.tar.gz") == (
            b"downloaded sdk.tar.gz\n"
        )
    assert "ceremony/scripts/audit.py" in names
    assert "ceremony/scripts/calyx-shamir-split" in names
    assert not any(name.startswith("ceremony/vendor") for name in names)
    assert "ceremony/manifest.tsv" not in names
    assert f"{hashlib.sha256(data).hexdigest()}  " in stdout


def test_package_flag_routes_through_python(tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-path-bin"
    fake_bin.mkdir()
    fake_python3 = fake_bin / "python3"
    fake_python3.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" prepare-ceremony-package "*)\n'
        "  echo FAKE_PYTHON3_INVOKED >&2\n"
        "  exit 1\n"
        "esac\n"
        f'exec {sys.executable} "$@"\n',
    )
    fake_python3.chmod(fake_python3.stat().st_mode | stat.S_IXUSR)
    manifest = tmp_path / "manifest.tsv"
    manifest.write_text("filename\tsha256sum\tfilesize\tlink\n")
    results = {
        flag: run(
            ["bash", PACKAGE_DIR / "prepare.package.sh"],
            cwd=tmp_path,
            env={
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "MANIFEST_FILE": str(manifest),
                "USE_PYTHON_PREPARE_PACKAGE": flag,
            },
            check=False,
        )
        for flag in ("", "y")
    }

    assert "FAKE_PYTHON3_INVOKED" in results["y"].stderr
    assert "FAKE_PYTHON3_INVOKED" not in results[""].stderr


def test_package_reports_a_download_killed_by_a_signal(tmp_path: Path) -> None:
    manifest = SMALL_MANIFEST.replace(
        "\t100\thttps://example.invalid/sdk",
        "\t0\thttps://example.invalid/sdk",
    )

    returncode, _, _, data = _outcome(tmp_path, "python", manifest)

    assert returncode == 128 + signal.SIGXFSZ
    assert data is None
