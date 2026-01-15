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

import cryptography.hazmat._oid
import cryptography.x509
import yubihsm
import yubihsm.exceptions
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from yubihsm.defs import CAPABILITY
from yubihsm.objects import WrapKey

from setup import print_and_get_info, save_audit_log, ADMIN_AUTHKEY_ID, WRAP_KEY_ID

KEEP_PATH = os.getenv("KEEP_PATH", os.path.join(pathlib.Path.home(), "CalyxBackupHSM"))

#
# TODO this is just a quick dummy script to demonstrate feasibility
#  If used for actual restore operation, it would need some polishing
#

def main():
    parser = argparse.ArgumentParser(description="Imports wrapped signing keys")
    parser.add_argument("-k", "--key-file", help="File to private admin auth key", required=True)
    args = parser.parse_args()

    # Load private key for auth
    with open(args.key_file, "rb") as f:
        admin_private_key = load_pem_private_key(f.read(), password=None)

    # check if we can find key dir
    key_dir = os.path.join(os.getcwd(), "keys")
    if not os.path.isfile(os.path.join(key_dir, "0x1100-asymmetric-key.yhw")):
        print(f"Could not find keys in {key_dir}. Are you in ota-tools root folder?", file=sys.stderr)
        sys.exit(1)

    # connect
    connector_url = os.getenv("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = yubihsm.YubiHsm.connect(connector_url)
    session = hsm.create_session_asymmetric(ADMIN_AUTHKEY_ID, admin_private_key)
    hsm_name = print_and_get_info(hsm, session)
    try:
        # import all signing keys
        wrap_key = WrapKey(session, WRAP_KEY_ID)
        key_files = sorted(glob.glob("0x*-asymmetric-key.yhw", root_dir=key_dir))
        for key_file in key_files:
            key = os.path.join(key_dir, key_file)
            with open(key, 'r') as f:
                wrapped_key_base64 = f.read()
            wrapped_key_bytes = base64.b64decode(wrapped_key_base64)
            print(f"Importing {key_file} ...")
            # wrap_key.import_wrapped(wrapped_key_bytes)
        print(f"Successfully imported {len(key_files)} signing keys.")
        save_audit_log(session, hsm_name)

        # import all key certs
        cert_files = sorted(glob.glob("0x*attestation.pem", root_dir=key_dir))
        for cert_file in cert_files:
            cert = os.path.join(key_dir, cert_file)
            with open(cert, 'rb') as f:
                pem_cert_bytes = f.read()
            pem = cryptography.x509.load_pem_x509_certificate(pem_cert_bytes)
            subject = pem.subject.rfc4514_string()
            key_id_index = subject.find("id:")
            key_id = subject[key_id_index + 3:]
            label_bytes = pem.extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.4.1.41482.4.9")).value.value
            label = label_bytes.decode().lstrip()
            print(f"Importing {cert_file} {key_id} {label} ...")
            try:
                yubihsm.objects.Opaque.put_certificate(
                    session=session,
                    object_id=int(key_id, 16),
                    label=label,
                    domains=4,  # TODO
                    capabilities=CAPABILITY.NONE,  # TODO
                    certificate=pem,
                    compress=True,
                )
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code == int("0x11", 16):
                    print("  Cert was already imported, skipping...")
                    continue
                else:
                    raise e
        print(f"Successfully imported {len(cert_files)} signing key certificates.")
    finally:
        save_audit_log(session, hsm_name)
        session.close()


if __name__ == "__main__":
    main()
