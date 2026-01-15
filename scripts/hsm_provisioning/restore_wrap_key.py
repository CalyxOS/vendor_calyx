#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
import os
import pathlib
import sys

from setup import create_auth_password, create_auth_key, provision_hsm, provision_wrap_key

KEEP_PATH = os.getenv("KEEP_PATH", os.path.join(pathlib.Path.home(), "CalyxBackupHSM"))


#
# TODO this is just a quick dummy script to demonstrate feasibility
#  If used for actual restore operation, it would need some polishing
#

def main():
    # receive wrap key via STDIN
    wrap_key_hex = sys.stdin.readline().rstrip()
    wrap_key_bytes = bytes.fromhex(wrap_key_hex)

    # ensure auth key dir exists
    auth_key_dir = os.path.join(KEEP_PATH, "auth-keys")
    os.makedirs(auth_key_dir, exist_ok=True)

    # create and get auth keys
    # TODO adjust key IDs
    password_signing = create_auth_password(auth_key_dir, "signing", "4")
    admin_private_key, admin_public_key = create_auth_key(auth_key_dir, "admin", "4")
    _, audit_public_key = create_auth_key(auth_key_dir, "audit", "4")

    # provision backup HSM
    provision_hsm(admin_private_key, admin_public_key, password_signing, audit_public_key,
                  lambda s: provision_wrap_key(s, wrap_key_bytes))


if __name__ == "__main__":
    main()
