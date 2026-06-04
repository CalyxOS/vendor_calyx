#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2018 Daniel Micay
# SPDX-FileCopyrightText: 2020-2026 The Calyx Institute
# SPDX-License-Identifier: MIT OR Apache-2.0
#

from argparse import ArgumentParser
from zipfile import ZipFile

parser = ArgumentParser(description="Generate update server metadata")
parser.add_argument("zip", help="ota_update or target_files")
parser.add_argument("channel", default="testing", nargs='?', help="ota channel (default: testing)")

# From build/make/tools/releasetools/common.py
def LoadBuildProp(input_file, prop_file):
    lines = input_file.read(prop_file).decode().split("\n")
    d = {}
    for line in lines:
      line = line.strip()
      if not line or line.startswith("#"):
        continue
      if "=" in line:
        name, value = line.split("=", 1)
        d[name] = value
    return d

with ZipFile(parser.parse_args().zip) as f:
    if "META-INF/com/android/metadata" in f.namelist():
        with f.open("META-INF/com/android/metadata") as metadata:
            data = dict(line[:-1].decode().split("=") for line in metadata)
            with open(data["pre-device"] + "-" + parser.parse_args().channel, "w") as output:
                incremental = data["post-build"].split("/")[4].split(":")[0]
                sdk_to_android = {
                    "36": "16",
                }
                version = sdk_to_android.get(data.get("post-sdk-level", ""), "")
                print(incremental, data["post-timestamp"], version, file=output)
    elif "PRODUCT/etc/build.prop" in f.namelist():
        data = LoadBuildProp(f, "PRODUCT/etc/build.prop")
        with open(data["ro.product.product.device"] + "-" + parser.parse_args().channel, "w") as output:
            incremental = data["ro.build.version.incremental"]
            timestamp = data["ro.build.date.utc"]
            version = data["ro.build.version.release"]
            print(incremental, timestamp, version, file=output)
    else:
        print("Unsupported file: " + parser.parse_args().zip)
        parser.print_help()
