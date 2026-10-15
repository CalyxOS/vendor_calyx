#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
import signing.vendor_yubihsm as vendor_yubihsm
from conftest import yubihsm_config
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    audit_logged,
    extract_and_save_audit_log,
)
from yubihsm.core import YubiHsm
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


def test_extract_and_save_audit_log_connects_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    connect = YubiHsm.connect
    urls: list[str | None] = []

    def counted(url: str | None = None) -> YubiHsm:
        urls.append(url)
        return connect(url)

    monkeypatch.setattr(YubiHsm, "connect", staticmethod(counted))

    extract_and_save_audit_log(
        yubihsm_config(yubihsm),
        tmp_path / "audit.log",
        "comment",
    )

    assert len(urls) == 1
    assert yubihsm.device.unread_log() == []


def _failing_extraction(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    comments: list[str] = []

    def extract(config: YubiHsmConfig, log_file: Path, comment: str) -> None:
        comments.append(comment)
        raise OSError("audit log unavailable")

    monkeypatch.setattr(vendor_yubihsm, "extract_and_save_audit_log", extract)
    return comments


def test_audit_logged_raises_a_log_failure_after_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    comments = _failing_extraction(monkeypatch)
    config = YubiHsmConfig("http://127.0.0.1:1", "0x0001", "password")

    with (
        pytest.raises(OSError, match="audit log unavailable"),
        audit_logged(config, tmp_path / "audit.log", "Operation: x"),
    ):
        pass

    assert comments == ["Operation: x Result: 0"]


def test_audit_logged_raises_the_block_failure_over_a_log_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    comments = _failing_extraction(monkeypatch)
    config = YubiHsmConfig("http://127.0.0.1:1", "0x0001", "password")

    with (
        pytest.raises(ValueError, match="block failed"),
        audit_logged(config, tmp_path / "audit.log", "Operation: x"),
    ):
        raise ValueError("block failed")

    assert comments == ["Operation: x Result: 1"]
    assert "Failed to extract logs" in capsys.readouterr().err
