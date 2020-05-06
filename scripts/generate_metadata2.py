#!/usr/bin/env python3

from argparse import ArgumentParser
from zipfile import ZipFile

parser = ArgumentParser(description="Generate update server metadata")
parser.add_argument("zip")

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
    data = LoadBuildProp(f, "SYSTEM/build.prop")
    with open(data["ro.product.system.device"] + "-testing", "w") as output:
        build_id = data["ro.build.id"]
        incremental = data["ro.build.version.incremental"]
        timestamp = data["ro.build.date.utc"]
        print(incremental, timestamp, build_id, file=output)
