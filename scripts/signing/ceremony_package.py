#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Build the provisioning ceremony's ceremony.zip for
hsm_provisioning/prepare.package.sh.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

MANIFEST_FILENAME = "manifest.tsv"
TIMESTAMP = datetime.datetime(2010, 1, 1, tzinfo=datetime.UTC).timestamp()
START_SCRIPT = """#!/bin/bash
our_path=$(cd "$(dirname "$0")";pwd -P)
SOURCE_DIRECTORY="$our_path" exec "$our_path/scripts/provision.py" "$@"
"""


class PackageError(Exception):
    """Preparing the package failed with an exit status."""

    def __init__(self, code: int = 1) -> None:
        super().__init__(code)
        self.code = code


def _manifest_entries(path: Path) -> list[list[str]]:
    entries: list[list[str]] = []
    for index, line in enumerate(path.read_text().splitlines()):
        fields = [field for field in line.split("\t") if field]
        if index == 0 and fields[:1] == ["filename"]:
            continue
        entries.append(fields)
    return entries


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reset(path: Path, mode: int) -> None:
    os.utime(path, (TIMESTAMP, TIMESTAMP), follow_symlinks=False)
    path.chmod(mode)


def _download(destination: Path, link: str, file_size: str) -> None:
    def limit_file_size() -> None:
        try:
            limit = int(file_size) * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        except (ValueError, OSError):
            pass

    code = subprocess.run(
        ["curl", "-L", "-o", str(destination), link],
        preexec_fn=limit_file_size,
    ).returncode
    if code:
        raise PackageError(code=code if code > 0 else 128 - code)


def prepare_files(
    output_directory: Path,
    script_dir: Path,
    source_directory: str,
    manifest_file: Path,
) -> list[str]:
    """
    Download or copy every file the manifest lists into the output
    directory, and check each one against the SHA-256 its row gives.

    Args:
        output_directory: Directory to fill.
        script_dir: Directory of prepare.package.sh, named in the error
            for a missing source file.
        source_directory: Tree that the manifest's local files are
            copied from.
        manifest_file: Manifest listing the files.

    Returns:
        The files whose SHA-256 differs from their row's, in manifest
        order.

    Raises:
        PackageError: If a file escapes the output directory, a local
            file is missing or a download fails.
    """
    output_directory = Path(os.path.abspath(output_directory))
    mismatched: list[str] = []
    for fields in _manifest_entries(manifest_file):
        filename, sha256sum, file_size, link = (fields + ["", "", "", ""])[:4]
        destination = Path(f"{output_directory}/{filename}")
        if not os.path.normpath(destination).startswith(f"{output_directory}/"):
            print(f"Unacceptable path traversal in {filename}", file=sys.stderr)
            raise PackageError
        destination.parent.mkdir(parents=True, exist_ok=True)

        if link:
            print(f"Downloading {destination}...")
            sys.stdout.flush()
            _download(destination, link, file_size)
        else:
            generated = filename == "start.sh"
            source = Path(f"{source_directory}/{filename}")
            if not generated and not source.exists():
                print(f"Cannot find {filename}.", file=sys.stderr)
                for line in (
                    "Run this script from a lunch'd Android build "
                    "environment, or run it from",
                    "an extracted otatools-keys.zip directory:",
                    "  unzip otatools-keys.zip -d otatools-keys",
                    "  cd otatools-keys",
                    f"  {script_dir}/prepare.package.sh",
                    "(otatools-keys.zip is built with: "
                    "m otatools-keys-package)",
                ):
                    print(line, file=sys.stderr)
                raise PackageError
            if not generated:
                shutil.copy2(source, destination)
        if (
            filename.endswith(".py")
            or filename.endswith("calyx-shamir-split")
            or filename == "start.sh"
        ):
            _reset(destination, 0o755)
        else:
            _reset(destination, 0o644)
        _reset(destination.parent, 0o755)
        if not sha256sum:
            continue
        if _sha256(destination) != sha256sum:
            if not link:
                print(
                    f"{destination} does not match expected sha256sum and no "
                    "link provided!",
                    file=sys.stderr,
                )
            mismatched.append(filename)
    return mismatched


def _zip(tmp_dir: Path, zip_file: Path) -> None:
    names: list[str] = []
    for directory, subdirectories, files in os.walk(tmp_dir / "ceremony"):
        relative = os.path.relpath(directory, tmp_dir)
        names.append(relative)
        names.extend(
            os.path.join(relative, name)
            for name in files
            + [d for d in subdirectories if (Path(directory) / d).is_symlink()]
        )
    sys.stdout.flush()
    code = subprocess.run(
        ["zip", "-@", "-X", str(zip_file)],
        cwd=tmp_dir,
        env={**os.environ, "TZ": "UTC"},
        input="".join(f"{name}\n" for name in sorted(names)),
        text=True,
    ).returncode
    if code:
        raise PackageError(code=code if code > 0 else 128 - code)


def prepare_package(
    environment: Mapping[str, str],
    script_dir: Path,
    cwd: Path,
) -> int:
    """
    Build ceremony.zip in cwd from the files manifest.tsv in script_dir
    lists, and print its SHA-256.

    Args:
        environment: Process environment to read SOURCE_DIRECTORY and
            MANIFEST_FILE from.
        script_dir: The directory holding prepare.package.sh and its
            manifest.tsv.
        cwd: Directory to write ceremony.zip into.

    Returns:
        0 on success, or the exit status of the step that failed.

    Raises:
        OSError: If a file cannot be read, written or downloaded.
    """
    source_directory = environment.get("SOURCE_DIRECTORY", "")
    if not source_directory:
        ourpath = str(script_dir)
        index = ourpath.rfind("vendor/calyx/")
        source_directory = (
            ourpath[:index] if index >= 0 else ourpath
        ).removesuffix("/")
    tmp_dir = Path(tempfile.mkdtemp(prefix="tmp."))
    try:
        output_directory = tmp_dir / "ceremony"
        zip_file = cwd / "ceremony.zip"
        print(
            f"We will now prepare {zip_file} with the files needed for "
            "provisioning.",
        )
        print()
        output_directory.mkdir(parents=True, exist_ok=True)
        start = output_directory / "start.sh"
        start.write_text(START_SCRIPT)
        _reset(start, 0o755)
        mismatched = prepare_files(
            output_directory,
            script_dir,
            source_directory,
            Path(
                environment.get("MANIFEST_FILE")
                or script_dir / MANIFEST_FILENAME,
            ),
        )
        if mismatched:
            print(file=sys.stderr)
            print(
                "The following files FAILED sha256sum verification:",
                file=sys.stderr,
            )
            for filename in mismatched:
                print(f"  {filename}", file=sys.stderr)
            return 1
        print("All files verified successfully.")
        (output_directory / "vendor/calyx/scripts/hsm_provisioning").rename(
            output_directory / "scripts",
        )
        for directory in ("vendor/calyx/scripts", "vendor/calyx", "vendor"):
            (output_directory / directory).rmdir()
        _reset(output_directory, 0o755)
        zip_file.unlink(missing_ok=True)
        _zip(tmp_dir, zip_file)
        print(f"{_sha256(zip_file)}  {zip_file}")
        return 0
    except PackageError as error:
        return error.code
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
