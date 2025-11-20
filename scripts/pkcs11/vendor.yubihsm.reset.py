#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import os
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from yubihsm import YubiHsm


def main():
    parser = argparse.ArgumentParser(description="Resets YubiHSM 2")
    parser.add_argument("-f", "--key-file", help="File to private auth key", required=True)
    args = parser.parse_args()

    reset = input("Are you sure you want to RESET the YubiHSM? Re-type capital letters: ")
    if reset != "RESET":
        print("Aborting reset", file=sys.stderr)
        sys.exit(1)

    print("Resetting HSM")

    with open(args.key_file, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # connect to the YubiHSM via the connector
    connector_url = os.getenv("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = YubiHsm.connect(connector_url)
    session = hsm.create_session_asymmetric(0x00ad, private_key)
    try:
        session.reset_device()
        print("HSM was reset!")
    finally:
        session.close()


if __name__ == "__main__":
    main()
