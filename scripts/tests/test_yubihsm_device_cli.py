#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import datetime
from pathlib import Path

from conftest import SCRIPTS_DIR, run_cli
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from yubihsm_emulator import Connector

PASSWORD_ENV = "YUBIHSM_DEVICE_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def _command(yubihsm: Connector, command: str) -> list[str | Path]:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    return [
        command,
        "--connector",
        yubihsm.url,
        "--password-env",
        PASSWORD_ENV,
    ]


def test_get_device_identity_cli_prints_serial_and_part_number(
    yubihsm: Connector,
) -> None:
    result = run_cli(
        _command(yubihsm, "get-device-identity"),
        env=cli_environment(),
    )
    assert "Serial number:\t\t123456\n" in result.stdout
    assert result.stdout.endswith("Part number:\t\tYubiHSM2\n")


def test_get_device_identity_cli_fails_without_part_number(
    yubihsm: Connector,
) -> None:
    yubihsm.device.part_number = ""
    result = run_cli(
        _command(yubihsm, "get-device-identity"),
        env=cli_environment(),
        check=False,
    )
    assert result.returncode != 0
    assert "did not report a part number" in result.stderr


def test_get_loaded_key_status_cli_prints_fully_loaded_ids(
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    key = device.put_asymmetric_key(0x2000)
    device.put_asymmetric_key(0x2001)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "key")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    device.put_certificate(
        0x2000,
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()),
    )

    result = run_cli(
        _command(yubihsm, "get-loaded-key-status"),
        env=cli_environment(),
    )
    assert result.stdout.splitlines() == ["0x2000"]
