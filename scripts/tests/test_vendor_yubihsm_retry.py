#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import datetime
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import signing.vendor_yubihsm as vendor_yubihsm
from conftest import install_executable, process_alive, stub, yubihsm_config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    attest_key,
    connect_yubihsm_session,
    extract_and_save_audit_log,
)
from yubihsm.core import AuthSession
from yubihsm.defs import COMMAND, OBJECT
from yubihsm.exceptions import YubiHsmConnectionError, YubiHsmDeviceError
from yubihsm.objects import AsymmetricKey, Opaque, YhsmObject
from yubihsm_emulator import Connector, EmulatedYubiHsm

KEY_ID = "2000"


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
    binary = install_executable(
        tmp_path / "retry-yubihsm-connector",
        "#!/bin/sh\nsleep 300\n",
    )
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
        result = attest_key(yubihsm_config(yubihsm), KEY_ID)

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
        attest_key(yubihsm_config(yubihsm), KEY_ID)


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
        attest_key(yubihsm_config(yubihsm), KEY_ID)

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
    monkeypatch.setenv("YUBIHSM_CONNECTOR", yubihsm.url)

    with pytest.raises(YubiHsmConnectionError):
        attest_key(yubihsm_config(yubihsm), KEY_ID)


def _plug_on_restart(
    yubihsm: Connector,
    device: EmulatedYubiHsm,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "YUBIHSM_CONNECTOR_PIDFILE",
        str(tmp_path / "connector.pid"),
    )
    monkeypatch.setattr(
        vendor_yubihsm,
        "restart_connector",
        lambda: yubihsm.plug(device),
    )


def test_audit_log_extraction_retries_after_connection_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = _unplug(yubihsm, monkeypatch)
    _plug_on_restart(yubihsm, device, monkeypatch, tmp_path)
    log_file = tmp_path / "audit.log"

    entries = extract_and_save_audit_log(
        yubihsm_config(yubihsm),
        log_file,
        "Finished",
    )

    assert entries
    assert device.unread_log() == []
    assert "Finished" in log_file.read_text()


def test_audit_log_extraction_reopens_its_shared_session_on_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = _unplug(yubihsm, monkeypatch)
    yubihsm.plug(device)
    _plug_on_restart(yubihsm, device, monkeypatch, tmp_path)

    def connect_then_unplug(hsm_config: YubiHsmConfig) -> AuthSession:
        session = connect_yubihsm_session(hsm_config)
        if device.sessions_opened == 1:
            yubihsm.plug(None)
        return session

    monkeypatch.setattr(
        vendor_yubihsm,
        "connect_yubihsm_session",
        connect_then_unplug,
    )
    entries = extract_and_save_audit_log(
        yubihsm_config(yubihsm),
        tmp_path / "audit.log",
        "Finished",
    )

    assert entries
    assert device.unread_log() == []
    assert device.sessions_opened == 2


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


def test_restart_connector_waits_until_the_new_connector_listens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    binary = install_executable(
        tmp_path / "slow-yubihsm-connector",
        f"#!{sys.executable}\n"
        "import socket, time\n"
        "time.sleep(0.5)\n"
        f"listener = socket.create_server(('127.0.0.1', {port}))\n"
        "time.sleep(300)\n",
    )
    pid_file = tmp_path / "connector.pid"
    monkeypatch.setenv("YUBIHSM_CONNECTOR_PIDFILE", str(pid_file))
    monkeypatch.setenv("YUBIHSM_CONNECTOR_BIN", str(binary))
    monkeypatch.setenv("YUBIHSM_CONNECTOR", f"http://127.0.0.1:{port}")
    monkeypatch.delenv("NEVER_START_YUBIHSM_CONNECTOR", raising=False)

    try:
        vendor_yubihsm.restart_connector()
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    finally:
        os.kill(_read_pid(pid_file), 9)


def _lose_the_first_answer(
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    name: str,
) -> None:
    """
    Make the first call of a device write take effect and then fail with
    a connection error, as when the connector dies before it answers.
    """
    original = getattr(owner, name)
    calls = 0

    def lose_answer(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        result = original(*args, **kwargs)
        if calls == 1:
            raise YubiHsmConnectionError("connection lost")
        return result

    monkeypatch.setattr(owner, name, lose_answer)


def _retry_without_a_connector(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "YUBIHSM_CONNECTOR_PIDFILE",
        str(tmp_path / "connector.pid"),
    )
    monkeypatch.setattr(vendor_yubihsm, "restart_connector", lambda: None)
    monkeypatch.setattr(time, "sleep", stub(None))


def test_a_retried_delete_takes_an_object_already_gone_as_done(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000)
    _retry_without_a_connector(monkeypatch, tmp_path)
    _lose_the_first_answer(monkeypatch, YhsmObject, "delete")

    vendor_yubihsm.delete_object(
        yubihsm_config(yubihsm),
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    )

    assert yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is None


def test_a_retried_generate_takes_a_key_already_there_as_done(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    _retry_without_a_connector(monkeypatch, tmp_path)
    _lose_the_first_answer(monkeypatch, AsymmetricKey, "generate")

    vendor_yubihsm.generate_asymmetric_key(
        yubihsm_config(yubihsm),
        key_id="0x2000",
        label="bramble",
        domains="2",
        capabilities="sign-pkcs",
        algorithm="RSA:2048",
    )

    assert yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is not None


def test_a_retried_certificate_import_takes_one_already_there_as_done(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "bramble")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    _retry_without_a_connector(monkeypatch, tmp_path)
    _lose_the_first_answer(monkeypatch, Opaque, "put_certificate")

    vendor_yubihsm.import_certificate(
        yubihsm_config(yubihsm),
        key_id="0x2000",
        domains="2",
        capabilities="get-opaque",
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
    )

    assert yubihsm.device.get(0x2000, OBJECT.OPAQUE) is not None
