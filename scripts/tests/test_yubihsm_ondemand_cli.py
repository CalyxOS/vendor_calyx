#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run_cli
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import Connector, EmulatedYubiHsm

PASSWORD_ENV = "YUBIHSM_ONDEMAND_CLI_TEST_PASSWORD"


def cli_environment(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": str(SCRIPTS_DIR), PASSWORD_ENV: "secret", **extra}


def _backed_up_device(
    yubihsm: Connector,
    key_dir: Path,
    free_records: int,
) -> EmulatedYubiHsm:
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    device.put_wrap_key(0x0010)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
            base64.b64encode(
                device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, 0x0010),
            ),
        )
    device.total_records = len(device.objects) + free_records
    return device


@pytest.mark.parametrize(
    ("free_records", "expected_deleted"),
    [(100, []), (4, [0x2000])],
)
def test_limit_ondemand_objects_cli_evicts_only_when_space_is_low(
    yubihsm: Connector,
    tmp_path: Path,
    free_records: int,
    expected_deleted: list[int],
) -> None:
    device = _backed_up_device(yubihsm, tmp_path, free_records)

    run_cli(
        [
            "limit-ondemand-objects",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-dir",
            str(tmp_path),
            "--ondemand-domain",
            "3",
        ],
        env=cli_environment(),
    )

    assert [
        key_id
        for key_id in (0x2000, 0x2001)
        if device.get(key_id, OBJECT.ASYMMETRIC_KEY) is None
    ] == expected_deleted


def test_limit_ondemand_objects_cli_extracts_the_audit_log_per_delete(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _backed_up_device(yubihsm, tmp_path, 3)
    device.audit(COMMAND.DELETE_OBJECT)
    audit_log = tmp_path / "audit.log"

    run_cli(
        [
            "limit-ondemand-objects",
            "--connector",
            yubihsm.url,
            "--password-env",
            PASSWORD_ENV,
            "--key-dir",
            str(tmp_path),
            "--ondemand-domain",
            "3",
            "--audit-log",
            str(audit_log),
        ],
        env=cli_environment(),
    )

    sections: list[tuple[str, list[str]]] = []
    for line in audit_log.read_text().splitlines():
        if line.startswith("#"):
            sections.append((line, []))
        else:
            sections[-1][1].append(line)
    assert len(sections) == 2
    for (comment, entries), key_id in zip(sections, ("0x2000", "0x2001")):
        assert comment.endswith(
            f" Command: delete-object --object-id {key_id} "
            "--object-type asymmetric-key Result: 0",
        )
        assert " cmd: 0x58 " in entries[-1]
        assert f" tKey: {key_id} " in entries[-1]
