#!/usr/bin/env python3

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
    # establish session
    auth_key = int(os.getenv("YUBIHSM_AUTHKEY", "0x0001"), 16)
    password = os.getenv("YUBIHSM_PASSWORD", "password")
    session = hsm.create_session_derived(auth_key, password)
    try:
        extract_and_save_logs(session, args.log_file, args.comment, args.verbose)
    finally:
        session.close()


def extract_and_save_logs(session, log_file, comment, verbose=False):
    log_data = session.get_log_entries()
    if comment is None:
        c = ""
    else:
        c = comment.replace('\n', '').replace('\r', '')
    if len(log_data.entries) <= 0 and c == "":
        print("No logs to extract and no comment to write.")
        return
    with open(log_file, "a") as file:
        comment_line = f"# {round(time.time() * 1000)} {c}"
        file.write(comment_line + "\n")
        if verbose:
            print(comment_line)
        for entry in log_data.entries:
            entry_str = f"{entry.number:>{5}} cmd: {entry.command:#0{4}x} len: {entry.length:>{5}} sKey: {entry.session_key:#0{6}x} tKey: {entry.target_key:#0{6}x} 2Key: {entry.second_key:#0{6}x} res: {entry.result:#0{4}x} tick: {entry.tick:>{10}} hash: {entry.digest.hex()}"
            file.write(entry_str + "\n")
            if verbose:
                print(entry_str)
    if len(log_data.entries) > 0:
        last_entry = log_data.entries[-1].number
        session.set_log_index(last_entry)


if __name__ == "__main__":
    main()
