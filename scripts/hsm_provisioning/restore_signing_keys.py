#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import base64
import glob
import os
import pathlib
import sys

import setup
import yubihsm.exceptions
from audit import extract_and_save_logs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from setup import (
    ADMIN_AUTHKEY_ID,
    WRAP_KEY_ID,
    audit_log_file,
    print_and_get_info,
)
from yubihsm.core import YubiHsm
from yubihsm.defs import ERROR
from yubihsm.objects import WrapKey

KEEP_PATH = os.getenv(
    "KEEP_PATH",
    os.path.join(pathlib.Path.home(), "CalyxBackupHSM"),
)
setup.KEEP_PATH = KEEP_PATH

#
# TODO this is just a quick dummy script to demonstrate feasibility
#  If used for actual restore operation, it would need some polishing
#


def main() -> None:
    parser = argparse.ArgumentParser(description="Imports wrapped signing keys")
    parser.add_argument(
        "-k",
        "--key-file",
        help="File to private admin auth key",
        required=True,
    )
    args = parser.parse_args()

    # Load private key for auth
    with open(args.key_file, "rb") as f:
        admin_private_key = load_pem_private_key(f.read(), password=None)
    if not isinstance(admin_private_key, ec.EllipticCurvePrivateKey):
        sys.exit(f"{args.key_file} does not hold an EC private key")

    # check if we can find key dir
    key_dir = os.path.join(os.getcwd(), "keys")
    if not os.path.isfile(os.path.join(key_dir, "0x1100-asymmetric-key.yhw")):
        print(
            f"Could not find keys in {key_dir}. "
            "Are you in ota-tools root folder?",
            file=sys.stderr,
        )
        sys.exit(1)

    # connect
    connector_url = os.getenv("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = YubiHsm.connect(connector_url)
    session = hsm.create_session_asymmetric(ADMIN_AUTHKEY_ID, admin_private_key)
    hsm_name = print_and_get_info(hsm, session)
    log_file = audit_log_file(hsm_name)
    try:
        # import all signing keys
        wrap_key = WrapKey(session, WRAP_KEY_ID)
        key_files = sorted(
            glob.glob("0x*-asymmetric-key.yhw", root_dir=key_dir),
        )
        for key_file in key_files:
            key = os.path.join(key_dir, key_file)
            with open(key) as f:
                wrapped_key_base64 = f.read()
            wrapped_key_bytes = base64.b64decode(wrapped_key_base64)
            print(f"Importing {key_file} ...")
            try:
                wrap_key.import_wrapped(wrapped_key_bytes)
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code != ERROR.OBJECT_EXISTS:
                    raise
                print("  Key was already imported, skipping...")
            finally:
                extract_and_save_logs(session, log_file, f"restore: {key_file}")
        print(f"Successfully imported {len(key_files)} signing keys.")
    finally:
        extract_and_save_logs(session, log_file, "restore: done")
        session.close()


if __name__ == "__main__":
    main()
