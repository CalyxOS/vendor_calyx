#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from conftest import SCRIPTS_DIR, run_cli
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, ERROR, OBJECT
from yubihsm_emulator import Connector

PASSWORD_ENV = "YUBIHSM_GENERATE_KEY_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def test_generate_asymmetric_key_cli_generates_key(yubihsm: Connector) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")

    run_cli(
        [
            "generate-asymmetric-key",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2000",
            "--label",
            "vbmeta",
            "--domain",
            "3",
            "--capabilities",
            "sign-pkcs",
            "--algorithm",
            "RSA:4096",
        ],
        env=cli_environment(),
    )

    key = yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert key is not None
    assert key.algorithm == ALGORITHM.RSA_4096
    assert key.label.rstrip(b"\0") == b"vbmeta"
    assert key.domains == 0b100
    assert key.capabilities == CAPABILITY.SIGN_PKCS


def test_generate_asymmetric_key_cli_propagates_sdk_failure(
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    yubihsm.device.fail_next(
        COMMAND.GENERATE_ASYMMETRIC_KEY,
        ERROR.INSUFFICIENT_PERMISSIONS,
    )
    result = run_cli(
        [
            "generate-asymmetric-key",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-id",
            "0x2000",
            "--label",
            "vbmeta",
            "--domain",
            "3",
            "--capabilities",
            "sign-pkcs",
            "--algorithm",
            "RSA:4096",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode != 0
    assert "INSUFFICIENT_PERMISSIONS" in result.stderr


def test_generate_asymmetric_key_cli_rejects_raw_password() -> None:
    result = run_cli(
        [
            "generate-asymmetric-key",
            "--password",
            "command-line-secret",
            "--key-id",
            "0x2000",
            "--label",
            "vbmeta",
            "--domain",
            "3",
            "--capabilities",
            "sign-pkcs",
            "--algorithm",
            "RSA:4096",
        ],
        env=cli_environment(),
        check=False,
    )
    assert result.returncode == 2
    assert "raw passwords are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr
