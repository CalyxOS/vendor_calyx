#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import install_executable, process_alive, wait_until
from signing.vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)


@pytest.fixture
def fake_connector_binary(tmp_path: Path) -> Path:
    """
    Create a long-lived process to stand in for yubihsm-connector.

    It keeps its own path as its command line, which is what
    is_running() looks for.
    """
    binary = install_executable(
        tmp_path / "fake-yubihsm-connector",
        '#!/bin/bash\nexec -a "$0" sleep 300\n',
    )
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


def test_start_launches_process_and_writes_pidfile(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))

    connector.start()

    assert pid_file.exists()
    pid = int(pid_file.read_text().strip())
    assert process_alive(pid)

    connector.stop()
    assert wait_until(lambda: not process_alive(pid))
    assert not pid_file.exists()


def test_start_is_a_noop_when_already_running(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))
    connector.start()
    first_pid = int(pid_file.read_text().strip())

    connector.start()

    assert int(pid_file.read_text().strip()) == first_pid
    connector.stop()
    assert wait_until(lambda: not process_alive(first_pid))


def test_restart_replaces_a_running_process(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))
    connector.start()
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

    connector.start()

    assert not pid_file.exists()
    connector.stop()


def test_is_running_finds_the_connector_it_started(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))
    assert not connector.is_running()

    connector.start()

    assert connector.is_running()
    connector.stop()


def test_is_running_ignores_a_command_that_names_the_connector(
    tmp_path: Path,
) -> None:
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            'exec -a "journalctl -fu yubihsm-connector" sleep 300',
        ],
    )
    try:
        connector = YubiHsmConnector(
            config(
                tmp_path / "yubihsm-connector",
                tmp_path / "connector.pid",
            ),
        )
        cmdline = Path(f"/proc/{process.pid}/cmdline")
        assert wait_until(
            lambda: cmdline.read_bytes().startswith(b"journalctl"),
        )

        assert not connector.is_running()
    finally:
        process.kill()
        process.wait()


def test_stop_removes_stale_pidfile_for_dead_process(
    fake_connector_binary: Path,
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    pid_file.write_text("999999999\n")
    connector = YubiHsmConnector(config(fake_connector_binary, pid_file))

    connector.stop()

    assert not pid_file.exists()
