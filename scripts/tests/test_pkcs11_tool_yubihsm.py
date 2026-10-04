#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from signing.avb_signing import (
    SHA256_DIGEST_INFO_PREFIX,
    pkcs11_signer_from_environment,
)
from signing.models import KeyReference, SignRequest
from signing.pkcs11 import Pkcs11Backend, Pkcs11Config
from yubihsm_emulator import Connector

WRAPPER = SCRIPTS_DIR / "pkcs11" / "pkcs11_tool.yubihsm.sh"
YUBIHSM_MODULES = (
    Path("/usr/lib/pkcs11/yubihsm_pkcs11.so"),
    Path("/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"),
)


@pytest.fixture
def recording_tool(tmp_path: Path) -> Path:
    tool = tmp_path / "pkcs11-tool"
    tool.write_text(
        '#!/bin/sh\nprintf "LD_PRELOAD=%s\\n" "${LD_PRELOAD:-}"\n'
        'printf "%s\\n" "$@"\nexit 3\n',
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    return tool


def test_preloads_pkcs11_module(recording_tool: Path) -> None:
    result = run(
        [WRAPPER, "--module", "/lib/module.so", "-L"],
        env={
            "YUBIHSM_UNDERLYING_PKCS11_TOOL_BIN": str(recording_tool),
            "PKCS11_MODULE": "/lib/module.so",
            "LD_PRELOAD": "",
        },
        check=False,
    )

    assert result.returncode == 3
    assert result.stdout.splitlines() == [
        "LD_PRELOAD=/lib/module.so",
        "--module",
        "/lib/module.so",
        "-L",
    ]


def test_keeps_an_existing_preload_after_the_module(
    recording_tool: Path,
) -> None:
    result = run(
        [WRAPPER, "--module", "/lib/module.so", "-L"],
        env={
            "YUBIHSM_UNDERLYING_PKCS11_TOOL_BIN": str(recording_tool),
            "PKCS11_MODULE": "/lib/module.so",
            "LD_PRELOAD": "/lib/other.so",
        },
        check=False,
    )

    assert result.stdout.splitlines()[0] == (
        "LD_PRELOAD=/lib/module.so:/lib/other.so"
    )


def test_runs_pkcs11_tool_unchanged_without_a_module(
    recording_tool: Path,
) -> None:
    result = run(
        [WRAPPER, "-L"],
        env={
            "YUBIHSM_UNDERLYING_PKCS11_TOOL_BIN": str(recording_tool),
            "PKCS11_MODULE": "",
            "LD_PRELOAD": "",
        },
        check=False,
    )

    assert result.stdout.splitlines() == ["LD_PRELOAD=", "-L"]


def test_installed_yubihsm_module_initializes_through_the_wrapper(
    tmp_path: Path,
) -> None:
    module = next((path for path in YUBIHSM_MODULES if path.is_file()), None)
    if module is None or shutil.which("pkcs11-tool") is None:
        pytest.skip("yubihsm_pkcs11.so or pkcs11-tool is not installed")
    configuration = tmp_path / "yubihsm_pkcs11.conf"
    configuration.write_text("connector = http://127.0.0.1:12345\n")

    listed = run(
        [WRAPPER, "--module", module, "-L"],
        env={
            "PKCS11_MODULE": str(module),
            "YUBIHSM_PKCS11_CONF": str(configuration),
        },
        check=False,
    )

    assert listed.returncode == 0, listed.stderr
    assert "YubiHSM Connector" in listed.stdout


@pytest.mark.parametrize(
    ("preload", "expected"),
    ((True, "/lib/module.so:/lib/other.so"), (False, "/lib/other.so")),
)
def test_preloads_the_module_into_pkcs11_tool(
    recording_tool: Path,
    monkeypatch: pytest.MonkeyPatch,
    preload: bool,
    expected: str,
) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/lib/other.so")
    backend = Pkcs11Backend(
        Pkcs11Config(
            module=Path("/lib/module.so"),
            tool=str(recording_tool),
            preload_module=preload,
        ),
    )

    with pytest.raises(subprocess.CalledProcessError) as raised:
        backend.run("-L", include_pin=False)

    assert raised.value.stdout.decode().splitlines()[0] == (
        f"LD_PRELOAD={expected}"
    )


def test_yubihsm_vendor_preloads_the_module_for_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    yubihsm: Connector,
) -> None:
    module = next((path for path in YUBIHSM_MODULES if path.is_file()), None)
    if module is None or shutil.which("pkcs11-tool") is None:
        pytest.skip("yubihsm_pkcs11.so or pkcs11-tool is not installed")
    key = yubihsm.device.put_asymmetric_key(5, "key")
    configuration = tmp_path / "yubihsm_pkcs11.conf"
    configuration.write_text(f"connector = {yubihsm.url}\n")
    for name, value in {
        "YUBIHSM_PKCS11_CONF": str(configuration),
        "PKCS11_MODULE": str(module),
        "PKCS11_PIN": "0001password",
        "PKCS11_VENDOR": "yubihsm",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    monkeypatch.delenv("PKCS11_TOOL_BIN", raising=False)
    digest = bytes(range(32))
    request = SignRequest(
        KeyReference("0x0005", "0x0005"),
        SHA256_DIGEST_INFO_PREFIX + digest,
        "rsa-pkcs",
    )
    signature = pkcs11_signer_from_environment().sign(request)

    key.public_key().verify(
        signature,
        digest,
        padding.PKCS1v15(),
        Prehashed(hashes.SHA256()),
    )
