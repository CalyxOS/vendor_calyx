#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, YUBIHSM_SDK, run, run_cli
from yubihsm.defs import OBJECT
from yubihsm_emulator import Connector

PROVISION_SH = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.provision.sh"

FAKE_SHELL = """#!/bin/sh
printf "%s\\n" "$*" >> "{root}/shell-calls"
while [ $# -gt 0 ]; do
  case "$1" in
    -a) action=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$action" in
  get-device-info)
    printf "Serial number:\\t\\t123456\\nPart number:\\t\\tYSHSM2\\n" ;;
  list-objects)
    echo "Found 2 object(s)"
    for id in 0x0101 0x0102; do
      echo "id: $id, type: asymmetric-key, algo: rsa4096, sequence: 0, label: a"
    done ;;
  get-wrapped)
    printf "wrapped-%s" "$out" > "$out" ;;
esac
"""


def _provisioning_tree(root: Path, yubihsm: Connector) -> dict[str, str]:
    provisioning = root / "hsmp"
    provisioning.mkdir()
    (root / "devices").write_text("readonly devices=(bramble)\n")
    keymap = run_cli(
        [
            "generate-keymap",
            "--devices",
            "bramble",
        ],
    ).stdout
    (root / "keymap.tsv").write_text(keymap)
    shell = root / "yubihsm-shell"
    shell.write_text(FAKE_SHELL.format(root=root))
    shell.chmod(0o755)
    device = yubihsm.device
    device.put_authentication_key(0x0001, "signing-password")
    device.put_wrap_key(0x0010)
    for object_id in (0x0101, 0x0102):
        device.put_asymmetric_key(object_id)
    return {
        "PYTHONPATH": os.pathsep.join([str(SCRIPTS_DIR), YUBIHSM_SDK]),
        "PATH": os.environ["PATH"],
        "HOME": str(root),
        "PROVISIONING_PATH": str(provisioning),
        "DEVICES_FILE": str(root / "devices"),
        "KEEP_PATH": str(root / "keep"),
        "KEYMAP_FILE": str(root / "keymap.tsv"),
        "YUBIHSM_SHELL_BIN": str(shell),
        "YUBIHSM_CONNECTOR": yubihsm.url,
    }


@pytest.mark.parametrize("python_tools", ["", "y"])
def test_backup_exports_every_asymmetric_key_under_wrap(
    tmp_path: Path,
    python_tools: str,
    yubihsm: Connector,
) -> None:
    environment = _provisioning_tree(tmp_path, yubihsm)
    environment["YUBIHSM_PYTHON_TOOLS"] = python_tools

    result = run(
        ["bash", PROVISION_SH, "backup"],
        env=environment,
        input_text="n\nsigning-password\ny\n",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    keys = tmp_path / "keep" / "keys"
    assert sorted(path.name for path in keys.iterdir()) == [
        "0x0101-asymmetric-key.yhw",
        "0x0102-asymmetric-key.yhw",
    ]
    audit = next((tmp_path / "keep" / "logs").rglob("*-provision.log"))
    wrapped = [
        line
        for line in audit.read_text().splitlines()
        if "get-wrapped" in line or "export-wrapped-key" in line
    ]
    assert len(wrapped) == 2
    assert all("--wrap-id 0x0010" in line for line in wrapped)
    assert "Provisioning completed successfully!" in result.stdout
    if python_tools:
        for path in keys.iterdir():
            key_id = int(path.name.split("-")[0], 16)
            assert yubihsm.device.unwrap(
                base64.b64decode(path.read_bytes()),
                0x0010,
            ) == (key_id, OBJECT.ASYMMETRIC_KEY)
