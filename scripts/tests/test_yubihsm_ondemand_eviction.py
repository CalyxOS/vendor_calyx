#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
from pathlib import Path

from conftest import yubihsm_config
from signing.vendor_yubihsm import (
    extract_and_save_audit_log,
    limit_ondemand_objects,
)
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import Connector


def test_limit_ondemand_objects_audits_each_delete(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    device.put_wrap_key(0x0010)
    for key_id in (0x2000, 0x2001):
        device.put_asymmetric_key(key_id, domains=0b100)
        (tmp_path / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
            base64.b64encode(
                device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, 0x0010),
            ),
        )
    device.total_records = len(device.objects) + 3
    device.audit(COMMAND.DELETE_OBJECT)
    config = yubihsm_config(yubihsm, password="secret")
    log_file = tmp_path / "audit.log"

    def after_delete(comment: str) -> None:
        extract_and_save_audit_log(config, log_file, comment)

    limit_ondemand_objects(config, tmp_path, "3", after_delete)

    assert device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is None
    assert device.get(0x2001, OBJECT.ASYMMETRIC_KEY) is None
    sections: list[tuple[str, list[str]]] = []
    for line in log_file.read_text().splitlines():
        if line.startswith("#"):
            sections.append((line, []))
        else:
            sections[-1][1].append(line)
    assert len(sections) == 2
    for (comment, entries), key_hex in zip(sections, ("0x2000", "0x2001")):
        assert comment.endswith(
            f" Command: delete-object --object-id {key_hex} "
            "--object-type asymmetric-key Result: 0",
        )
        assert " cmd: 0x58 " in entries[-1]
        assert f" tKey: {key_hex} " in entries[-1]
