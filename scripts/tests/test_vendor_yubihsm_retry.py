#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path

import pytest
import signing.vendor_yubihsm as vendor_yubihsm
from conftest import process_alive
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from signing.vendor_yubihsm import YubiHsmConfig, attest_key
from yubihsm.defs import COMMAND, OBJECT
from yubihsm.exceptions import YubiHsmConnectionError, YubiHsmDeviceError
from yubihsm_emulator import Connector, EmulatedYubiHsm

KEY_ID = "2000"


def config(yubihsm: Connector) -> YubiHsmConfig:
    return YubiHsmConfig(
        connector_url=yubihsm.url,
        auth_key="0x0001",
        password="password",
    )


def _unplug(
    yubihsm: Connector,
    monkeypatch: pytest.MonkeyPatch,
) -> EmulatedYubiHsm:
    """
    Take the device away from the connector, so that the SDK fails with a
    connection error, after giving it a key to attest.
    """
    device = yubihsm.device
    device.put_asymmetric_key(0x2000)
    yubihsm.plug(None)
    sleep = time.sleep

    def fast_sleep(seconds: float) -> None:
        sleep(min(seconds, 0.05))

    monkeypatch.setattr(time, "sleep", fast_sleep)
    return device


def _issued_for_the_key(certificate: bytes, device: EmulatedYubiHsm) -> bool:
    attestation = x509.load_pem_x509_certificate(certificate)
    key = device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert key is not None
    expected = serialization.load_der_private_key(key.data, None).public_key()
    public = attestation.public_key()
    assert isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
    assert isinstance(expected, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
    return public.public_numbers() == expected.public_numbers()


def _read_pid(pid_file: Path) -> int:
    return int(pid_file.read_text().strip().partition(":")[0])


def test_restarts_the_connector_and_retries_after_connection_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = _unplug(yubihsm, monkeypatch)
    binary = tmp_path / "retry-yubihsm-connector"
    binary.write_text("#!/bin/sh\nsleep 300\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    launcher = subprocess.run(
        ["sh", "-c", 'setsid "$1" >/dev/null 2>&1 & echo $!', "sh", binary],
        check=True,
        capture_output=True,
        text=True,
    )
    first_pid = int(launcher.stdout)
    pid_file = tmp_path / "connector.pid"
    pid_file.write_text(f"{first_pid}\n")
    monkeypatch.setenv("YUBIHSM_CONNECTOR_PIDFILE", str(pid_file))
    monkeypatch.setenv("YUBIHSM_CONNECTOR_BIN", str(binary))
    monkeypatch.setenv("YUBIHSM_CONNECTOR", yubihsm.url)

    restart = vendor_yubihsm.restart_connector

    def restart_and_plug() -> None:
        restart()
        yubihsm.plug(device)

    monkeypatch.setattr(vendor_yubihsm, "restart_connector", restart_and_plug)
    try:
        result = attest_key(config(yubihsm), KEY_ID)

        second_pid = _read_pid(pid_file)
        assert _issued_for_the_key(result, device)
        assert not process_alive(first_pid)
        assert second_pid != first_pid
        assert process_alive(second_pid)
    finally:
        for pid in {first_pid, _read_pid(pid_file)}:
            if process_alive(pid):
                os.killpg(pid, 9)


def test_does_not_retry_without_connector_pidfile(
    monkeypatch: pytest.MonkeyPatch,
    yubihsm: Connector,
) -> None:
    _unplug(yubihsm, monkeypatch)
    monkeypatch.delenv("YUBIHSM_CONNECTOR_PIDFILE", raising=False)

    with pytest.raises(YubiHsmConnectionError):
        attest_key(config(yubihsm), KEY_ID)


def test_does_not_retry_on_a_device_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000)
    yubihsm.device.fail_next(COMMAND.SIGN_ATTESTATION_CERTIFICATE)
    monkeypatch.setenv(
        "YUBIHSM_CONNECTOR_PIDFILE",
        str(tmp_path / "connector.pid"),
    )

    with pytest.raises(YubiHsmDeviceError):
        attest_key(config(yubihsm), KEY_ID)

    assert yubihsm.device.sessions_opened == 1


def test_propagates_failure_if_retry_also_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    _unplug(yubihsm, monkeypatch)
    monkeypatch.setenv(
        "YUBIHSM_CONNECTOR_PIDFILE",
        str(tmp_path / "connector.pid"),
    )
    monkeypatch.setenv("YUBIHSM_CONNECTOR_BIN", "true")

    with pytest.raises(YubiHsmConnectionError):
        attest_key(config(yubihsm), KEY_ID)


def test_restart_connector_leaves_a_user_connector_alone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(config: object) -> None:
        raise AssertionError("the connector must not be restarted")

    monkeypatch.setenv("NEVER_START_YUBIHSM_CONNECTOR", "y")
    monkeypatch.setenv("YUBIHSM_CONNECTOR_PIDFILE", str(tmp_path / "pid"))
    monkeypatch.setattr(vendor_yubihsm, "YubiHsmConnector", refuse)

    vendor_yubihsm.restart_connector()
