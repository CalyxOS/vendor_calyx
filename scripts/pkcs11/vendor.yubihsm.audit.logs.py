#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import os
import time

from yubihsm import YubiHsm


def main():
    # define command line arguments
    parser = argparse.ArgumentParser(description="Extracts, saves and uploads YubiHSM 2 audit logs.")
    parser.add_argument("--log-file", help="File to append audit log to", required=True)
    parser.add_argument("--comment", help="Comment for all log entries that will get saved")
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    # connect to the YubiHSM via the connector
    connector_url = os.getenv("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = YubiHsm.connect(connector_url)
    # Reading an empty log on a new session right after SET_LOG_INDEX can make
    # the YubiHSM 2 reboot, so leave the log unread when it holds no entries.
    if hsm.get_device_info().log_used == 0:
        save_logs([], args.log_file, args.comment, args.verbose)
        return
    # establish session
    auth_key = int(os.getenv("YUBIHSM_AUTHKEY", "0x0001"), 16)
    password = os.getenv("YUBIHSM_PASSWORD", "password")
    session = hsm.create_session_derived(auth_key, password)
    try:
        extract_and_save_logs(session, args.log_file, args.comment, args.verbose)
    finally:
        session.close()


def extract_and_save_logs(session, log_file, comment, verbose=False):
    entries = session.get_log_entries().entries
    save_logs(entries, log_file, comment, verbose)
    if len(entries) > 0:
        session.set_log_index(entries[-1].number)


def save_logs(entries, log_file, comment, verbose=False):
    if comment is None:
        c = ""
    else:
        c = comment.replace('\n', '').replace('\r', '')
    if len(entries) <= 0 and c == "":
        print("No logs to extract and no comment to write.")
        return
    # Ensure directory for log file exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    # Write log entries to file including the comment
    with open(log_file, "a") as file:
        comment_line = f"# {round(time.time() * 1000)} {c}"
        file.write(comment_line + "\n")
        if verbose:
            print(comment_line)
        for entry in entries:
            entry_str = f"{entry.number:>{5}} cmd: {entry.command:#0{4}x} len: {entry.length:>{5}} sKey: {entry.session_key:#0{6}x} tKey: {entry.target_key:#0{6}x} 2Key: {entry.second_key:#0{6}x} res: {entry.result:#0{4}x} tick: {entry.tick:>{10}} hash: {entry.digest.hex()}"
            file.write(entry_str + "\n")
            if verbose:
                print(entry_str)


if __name__ == "__main__":
    main()
