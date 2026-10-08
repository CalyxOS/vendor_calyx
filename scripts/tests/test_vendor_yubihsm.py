#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import yubihsm_config
from signing.vendor_yubihsm import (
    AuditLogNotAcknowledged,
    YubiHsmConfig,
    extract_and_save_audit_log,
)
from yubihsm.defs import COMMAND
from yubihsm_emulator import Connector


def _drained_audit_log(yubihsm: Connector) -> YubiHsmConfig:
    yubihsm.device.log_index = yubihsm.device.log[-1][0]
    return yubihsm_config(yubihsm)


def test_extract_and_save_audit_log_skips_write_with_no_entries_or_comment(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    log_file = tmp_path / "audit.log"

    entries = extract_and_save_audit_log(
        _drained_audit_log(yubihsm),
        log_file,
        None,
    )

    assert entries == ()
    assert not log_file.exists()


def test_extract_and_save_audit_log_writes_comment_with_no_entries(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    log_file = tmp_path / "audit.log"

    entries = extract_and_save_audit_log(
        _drained_audit_log(yubihsm),
        log_file,
        "just a comment",
    )

    assert entries == ()
    assert "just a comment" in log_file.read_text()


def test_extract_and_save_audit_log_reads_and_acknowledges_in_one_session(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    config = yubihsm_config(yubihsm)
    log_file = tmp_path / "audit.log"

    entries = extract_and_save_audit_log(config, log_file, "comment")

    assert len(entries) == 1
    assert yubihsm.device.unread_log() == []
    assert yubihsm.device.sessions_opened == 1


def test_extract_and_save_audit_log_writes_an_unacknowledged_entry_once(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    config = yubihsm_config(yubihsm)
    log_file = tmp_path / "audit.log"
    yubihsm.device.fail_next(COMMAND.SET_LOG_INDEX)

    with pytest.raises(AuditLogNotAcknowledged):
        extract_and_save_audit_log(config, log_file, "first")
    extract_and_save_audit_log(config, log_file, "second")

    entries = [
        line
        for line in log_file.read_text().splitlines()
        if not line.startswith("#")
    ]
    assert len(entries) == len(set(entries)) == 1
    assert yubihsm.device.unread_log() == []
