#!/usr/bin/env python3

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
                build_id = data["post-build"].split("/")[3]
                incremental = data["post-build"].split("/")[4].split(":")[0]
                print(incremental, data["post-timestamp"], build_id, file=output)
    elif "SYSTEM/build.prop" in f.namelist():
        data = LoadBuildProp(f, "SYSTEM/build.prop")
        with open(data["ro.build.product"] + "-" + parser.parse_args().channel, "w") as output:
            build_id = data["ro.build.id"]
            incremental = data["ro.build.version.incremental"]
            timestamp = data["ro.build.date.utc"]
            print(incremental, timestamp, build_id, file=output)
    else:
        print("Unsupported file: " + parser.parse_args().zip)
        parser.print_help()
