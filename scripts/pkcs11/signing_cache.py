#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

apksigner_parser = argparse.ArgumentParser(exit_on_error=False)
apksigner_parser.add_argument("--out", nargs=2)
apksigner_parser.add_argument("--kms-key-alias", dest="key")
apksigner_parser.add_argument("--cert")


def from_cache(args: list[str]) -> bool:
    """
    Copy a cached signed output into place for an apksigner invocation.

    Args:
        args: The apksigner command line.

    Returns:
        Whether the cache held the output, which is then in place.

    Raises:
        argparse.ArgumentError: If the --out argument is malformed.
    """
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
        print(f"Cache hit for {key} copying to {out_file}")
        link_or_copy(cache_dir / key, Path(signing_obj.out_file))
        return True

    print(f"Cache miss for {key} {out_file}")
    return False


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
        print(f"WARNING: {key} was in cache, but we had a miss before")
    else:
        link_or_copy(Path(signing_obj.out_file), cache_dir / key)
        in_file = Path(signing_obj.in_file).name
        out_file = Path(signing_obj.out_file).name
        print(f"Saving {key} from {out_file} for {in_file}")


def apksigner_get_apks(arg_str: list[str]) -> SigningObj:
    args = apksigner_parser.parse_known_args(arg_str)[0]
    return SigningObj(
        in_file=args.out[1],
        out_file=args.out[0],
        key_id=args.key,
        cert=args.cert,
    )


# A certificate can be replaced in place, so it is keyed by its contents.
def cache_key(signing_obj: SigningObj, input_digest: str) -> str:
    with open(signing_obj.cert, "rb") as f:
        cert_digest = hashlib.file_digest(f, "sha256").hexdigest()
    return f"{input_digest}-{signing_obj.key_id}-{cert_digest}"


def link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


@dataclass
class SigningObj:
    in_file: str
    out_file: str
    key_id: str
    cert: str
