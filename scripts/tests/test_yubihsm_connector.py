#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest
from conftest import process_alive, wait_until
from signing.vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)


@pytest.fixture
def fake_connector_binary(tmp_path: Path) -> Path:
    """
    Create a long-lived process to stand in for yubihsm-connector.
    """
    binary = tmp_path / "fake-yubihsm-connector"
    binary.write_text('#!/bin/bash\nexec -a "$0" sleep 300\n')
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def config(
    binary: Path,
    pid_file: Path,
    connector_url: str = "http://127.0.0.1:12345",
) -> YubiHsmConnectorConfig:
    return YubiHsmConnectorConfig(
        connector_url=connector_url,
        pid_file=pid_file,
        binary=str(binary),
    )


def test_restart_launches_process_and_writes_pidfile(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))

    connector.restart()

    assert pid_file.exists()
    pid = int(pid_file.read_text().strip())
    assert process_alive(pid)

    connector.stop()
    assert wait_until(lambda: not process_alive(pid))
    assert not pid_file.exists()


def test_restart_replaces_a_running_process(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))
    connector.restart()
    first_pid = int(pid_file.read_text().strip())

    connector.restart()

    second_pid = int(pid_file.read_text().strip())
    assert second_pid != first_pid
    assert wait_until(lambda: not process_alive(first_pid))
    assert process_alive(second_pid)

    connector.stop()
    assert wait_until(lambda: not process_alive(second_pid))


def test_stop_kills_a_connector_outside_its_own_process_group(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    process = subprocess.Popen(["sleep", "300"])
    pid_file.write_text(f"{process.pid}\n")
    connector = YubiHsmConnector(config(Path("sleep"), pid_file))

    connector.stop()

    process.wait(timeout=5)
    assert not pid_file.exists()


def test_usb_connector_is_never_managed(tmp_path: Path) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(
        config(
            Path("/does/not/matter"),
            pid_file,
            connector_url="yhusb://",
        ),
    )

    connector.restart()

    assert not pid_file.exists()
    connector.stop()


def test_stop_removes_stale_pidfile_for_dead_process(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    pid_file.write_text("999999999\n")
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))

    connector.stop()

    assert not pid_file.exists()
