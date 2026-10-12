#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import socket
import subprocess
import sys
import time
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


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port: int = listener.getsockname()[1]
        return port


def test_restart_waits_until_the_connector_listens(tmp_path: Path) -> None:
    port = _free_port()
    binary = install_executable(
        tmp_path / "slow-yubihsm-connector",
        f"#!{sys.executable}\n"
        "import socket, time\n"
        "time.sleep(0.5)\n"
        "listener = socket.create_server(('127.0.0.1', "
        f"{port}))\n"
        "time.sleep(300)\n",
    )
    pid_file = tmp_path / "connector.pid"
    connector = YubiHsmConnector(
        config(binary, pid_file, f"http://127.0.0.1:{port}"),
    )

    try:
        connector.restart()
        connector.wait_until_listening()

        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    finally:
        connector.stop()


def test_restart_refuses_a_connector_that_exits(tmp_path: Path) -> None:
    binary = install_executable(
        tmp_path / "failing-yubihsm-connector",
        "#!/bin/sh\nexit 1\n",
    )
    connector = YubiHsmConnector(
        config(
            binary,
            tmp_path / "connector.pid",
            f"http://127.0.0.1:{_free_port()}",
        ),
    )

    connector.restart()
    with pytest.raises(RuntimeError, match="exited"):
        connector.wait_until_listening()


def test_wait_probes_the_https_port_of_a_url_without_one(
    fake_connector_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], timeout: float) -> socket.socket:
        probed.append(address)
        return socket.socket()

    connector = YubiHsmConnector(
        config(
            fake_connector_binary,
            tmp_path / "connector.pid",
            "https://127.0.0.1",
        ),
    )
    connector.restart()
    monkeypatch.setattr(socket, "create_connection", connect)
    try:
        connector.wait_until_listening()
    finally:
        connector.stop()

    assert probed == [("127.0.0.1", 443)]


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


def test_stop_finishes_on_a_connector_another_process_has_not_reaped(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "connector.pid"
    owner = subprocess.Popen(
        [
            "python3",
            "-c",
            "import subprocess, time\n"
            "print(subprocess.Popen(['sleep', '300']).pid, flush=True)\n"
            "time.sleep(300)\n",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert owner.stdout is not None
        pid_file.write_text(owner.stdout.readline())
        connector = YubiHsmConnector(config(Path("sleep"), pid_file))
        started = time.monotonic()

        connector.stop()

        assert time.monotonic() - started < 5
        assert not pid_file.exists()
    finally:
        owner.kill()
        owner.wait()


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
