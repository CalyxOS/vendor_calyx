#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

apksigner_parser = argparse.ArgumentParser(allow_abbrev=False)
apksigner_parser.add_argument("--out", nargs=2)
apksigner_parser.add_argument("--ks-key-alias", dest="key")

use_log = False


def main() -> None:
    # define command line arguments
    parser = argparse.ArgumentParser(description="signing cache test")
    parser.add_argument(
        "--from-cache",
        nargs="+",
        metavar=("command", "arguments"),
        help="use to check cache and use cached file if available",
    )
    parser.add_argument(
        "--to-cache",
        nargs="+",
        metavar=("command", "arguments"),
        help="save output file to cache if there was a cache miss",
    )
    args = parser.parse_known_args()[0]
    if args.from_cache:
        from_cache(sys.argv[2:])
    elif args.to_cache:
        to_cache(sys.argv[2:])
    else:
        parser.print_help()


def from_cache(args: list[str]) -> NoReturn:
    # parse command line
    signing_obj = apksigner_get_apks(args)

    # calculate hash of input file and use it for hash key
    with open(signing_obj.in_file, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    key = cache_key(signing_obj, digest.hexdigest())

    # check if hash key is in cache, if so copy to output file
    cache_dir = Path(os.environ.get("YUBIHSM_SIGNING_CACHE", ""))
    out_file = Path(signing_obj.out_file).name
    if (cache_dir / key).is_file():
        log(cache_dir, f"Cache hit for {key} copying to {out_file}")
        link_or_copy(cache_dir / key, Path(signing_obj.out_file))
        sys.exit(0)

    log(cache_dir, f"Cache miss for {key} {out_file}")
    sys.exit(1)


# Called if there is a cache miss, to save the new output file to the cache
def to_cache(args: list[str]) -> None:
    # parse command line
    signing_obj = apksigner_get_apks(args)

    # calculate hash of input file and use it for hash key
    with open(signing_obj.in_file, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    key = cache_key(signing_obj, digest.hexdigest())

    cache_dir = Path(os.environ.get("YUBIHSM_SIGNING_CACHE", ""))
    if (cache_dir / key).is_file():
        log(cache_dir, f"WARNING: {key} was in cache, but we had a miss before")
    else:
        link_or_copy(Path(signing_obj.out_file), cache_dir / key)
        in_file = Path(signing_obj.in_file).name
        out_file = Path(signing_obj.out_file).name
        log(cache_dir, f"Saving {key} from {out_file} for {in_file}")


def apksigner_get_apks(arg_str: list[str]) -> SigningObj:
    args, extra_args = apksigner_parser.parse_known_args(arg_str)
    return SigningObj(
        in_file=args.out[1],
        out_file=args.out[0],
        key_id=args.key,
        extra_args=tuple(extra_args),
    )


def file_digest_or_path(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
    except OSError:
        return path


# The --provider-arg configuration is written to a new temporary
# directory for every release, so it is keyed by its contents.
def cache_key(signing_obj: SigningObj, input_digest: str) -> str:
    parameters = [signing_obj.key_id or ""]
    is_file = False
    for arg in signing_obj.extra_args:
        parameters.append(file_digest_or_path(arg) if is_file else arg)
        is_file = arg == "--provider-arg"
    parameters_digest = hashlib.sha256(
        "\x1f".join(parameters).encode(),
    ).hexdigest()
    return f"{input_digest}-{parameters_digest}"


def link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def log(cache_dir: Path, msg: str) -> None:
    if use_log:
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with (cache_dir / "signing_cache.log").open("a") as f:
            f.write(f"{time} {msg}\n")
    print(msg)


@dataclass
class SigningObj:
    in_file: str
    out_file: str
    key_id: str | None
    extra_args: tuple[str, ...] = ()


if __name__ == "__main__":
    main()
