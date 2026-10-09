#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

from conftest import yubihsm_config
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    extract_and_save_audit_log,
)
from yubihsm_emulator import Connector


def _drained_audit_log(yubihsm: Connector) -> YubiHsmConfig:
    yubihsm.device.log_index = yubihsm.device.log[-1][0]
    return yubihsm_config(yubihsm)


def test_extract_and_save_audit_log_writes_comment_with_no_entries(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    log_file = tmp_path / "audit.log"

    extract_and_save_audit_log(
        _drained_audit_log(yubihsm),
        log_file,
        "just a comment",
    )

    (line,) = log_file.read_text().splitlines()
    assert line.endswith(" just a comment")


def test_extract_and_save_audit_log_leaves_an_empty_log_unread(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    extract_and_save_audit_log(
        _drained_audit_log(yubihsm),
        tmp_path / "audit.log",
        "comment",
    )

    assert yubihsm.device.sessions_opened == 0


def test_extract_and_save_audit_log_reads_and_acknowledges_in_one_session(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    config = yubihsm_config(yubihsm)
    log_file = tmp_path / "audit.log"

    extract_and_save_audit_log(config, log_file, "comment")

    assert len(log_file.read_text().splitlines()) == 2
    assert yubihsm.device.unread_log() == []
    assert yubihsm.device.sessions_opened == 1
