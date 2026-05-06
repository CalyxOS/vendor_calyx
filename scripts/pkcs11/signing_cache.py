#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import hashlib
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

apksigner_parser = argparse.ArgumentParser()
apksigner_parser.add_argument("--out", nargs=2)
apksigner_parser.add_argument("--ks-key-alias", dest="key")

use_log = False


def main():
    # define command line arguments
    parser = argparse.ArgumentParser(description="signing cache test")
    parser.add_argument('--from-cache', nargs='+', metavar=("command", "arguments"),
                        help="use to check cache and use cached file if available")
    parser.add_argument('--to-cache', nargs='+', metavar=("command", "arguments"),
                        help="save output file to cache if there was a cache miss")
    print(sys.argv)
    args = parser.parse_known_args()[0]
    if args.from_cache:
        from_cache(sys.argv[2:])
    elif args.to_cache:
        to_cache(sys.argv[2:])
    else:
        parser.print_help()


def from_cache(args):
    # parse command line
    signing_obj = apksigner_get_apks(args)

    # calculate hash of input file and use it for hash key
    with open(signing_obj.in_file, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    key = f"{digest.hexdigest()}-{signing_obj.key_id}"

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
def to_cache(args):
    # parse command line
    signing_obj = apksigner_get_apks(args)

    # calculate hash of input file and use it for hash key
    with open(signing_obj.in_file, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    key = f"{digest.hexdigest()}-{signing_obj.key_id}"

    cache_dir = Path(os.environ.get("YUBIHSM_SIGNING_CACHE", ""))
    if (cache_dir / key).is_file():
        log(cache_dir, f"WARNING: {key} was in cache, but we had a miss before")
    else:
        link_or_copy(Path(signing_obj.out_file), cache_dir / key)
        in_file = Path(signing_obj.in_file).name
        out_file = Path(signing_obj.out_file).name
        log(cache_dir, f"Saving {key} from {out_file} for {in_file}")


def apksigner_get_apks(arg_str):
    args = apksigner_parser.parse_known_args(arg_str)[0]
    return SigningObj(in_file=args.out[1], out_file=args.out[0], key_id=args.key)


def link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def log(cache_dir, msg):
    if use_log:
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with(cache_dir / "signing_cache.log").open("a") as f:
            f.write(f"{time} {msg}\n")
    print(msg)


@dataclass
class SigningObj:
    in_file: str
    out_file: str
    key_id: str


if __name__ == "__main__":
    main()
