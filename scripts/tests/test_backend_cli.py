#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import run_cli


@pytest.mark.parametrize("option", ("--pin", "--discovery-pin"))
def test_cli_does_not_accept_raw_pin_arguments(
    tmp_path: Path,
    option: str,
) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "provider.so",
            option,
            "command-line-secret",
            "--key-id",
            "0x2000",
            "--label",
            "releasekey",
        ],
        check=False,
    )

    assert result.returncode == 2
    assert "raw PINs are forbidden" in result.stderr
    assert "command-line-secret" not in result.stderr


def test_cli_reports_an_invalid_key_id_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        ["key-exists", "--module", tmp_path / "provider.so"],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: invalid PKCS#11 key ID" in result.stderr


def test_cli_reports_an_unset_pin_variable_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "provider.so",
            "--pin-env",
            "SIGNING_TEST_UNSET_PIN",
            "--key-id",
            "0x2000",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "error: PIN environment variable is not set" in result.stderr


@pytest.mark.skipif(
    shutil.which("pkcs11-tool") is None,
    reason="needs pkcs11-tool",
)
def test_cli_reports_a_failing_tool_without_a_traceback(
    tmp_path: Path,
) -> None:
    result = run_cli(
        [
            "key-exists",
            "--module",
            tmp_path / "missing.so",
            "--key-id",
            "0x2000",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert result.stderr


OFFICER_ONLY_TOKEN = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state = Path(sys.argv[0]).with_suffix(".objects")
objects = json.loads(state.read_text()) if state.exists() else []
arguments = sys.argv[1:]


def option(name):
    if name not in arguments:
        return None
    value = arguments[arguments.index(name) + 1]
    if value.startswith("env:"):
        return os.environ.get(value.removeprefix("env:"))
    return value


if option("--login-type") == "so":
    session = "officer" if option("--so-pin") == "officer-secret" else None
else:
    session = "user" if option("--pin") == "user-secret" else None
if session is None:
    print("CKR_PIN_INCORRECT", file=sys.stderr)
    sys.exit(1)

if "--list-objects" in arguments:
    if session == "user":
        for item in objects:
            if (item["type"], item["id"]) == (option("--type"), option("--id")):
                print(f"Object\\n  ID:         {item['id']}")
    sys.exit(0)
if "--keypairgen" in arguments:
    if session != "officer":
        print("CKR_USER_NOT_LOGGED_IN", file=sys.stderr)
        sys.exit(1)
    for kind in ("privkey", "pubkey"):
        objects.append({"type": kind, "id": option("--id")})
    state.write_text(json.dumps(objects))
    sys.exit(0)
sys.exit(2)
"""


def test_pkcs11_cli_use_so_pin_generates_a_key_once(tmp_path: Path) -> None:
    token = tmp_path / "officer-only-token"
    token.write_text(OFFICER_ONLY_TOKEN)
    token.chmod(0o755)
    environment = {
        "PKCS11_SO_PIN_TEST": "officer-secret",
        "PKCS11_DISCOVERY_PIN_TEST": "user-secret",
    }
    command: list[str | Path] = [
        "generate-key",
        "--module",
        tmp_path / "provider.so",
        "--pkcs11-tool",
        token,
        "--use-so-pin",
        "--pin-env",
        "PKCS11_SO_PIN_TEST",
        "--discovery-pin-env",
        "PKCS11_DISCOVERY_PIN_TEST",
        "--key-id",
        "0x2000",
        "--label",
        "releasekey",
        "--algorithm",
        "RSA",
        "--key-size",
        "2048",
    ]

    generated = run_cli(command, env=environment, check=False)
    repeated = run_cli(command, env=environment, check=False)

    assert generated.returncode == 0, generated.stderr
    assert repeated.returncode != 0
    assert "PKCS#11 key already exists: 0x2000" in repeated.stderr
    assert json.loads(token.with_suffix(".objects").read_text()) == [
        {"type": "privkey", "id": "2000"},
        {"type": "pubkey", "id": "2000"},
    ]
    for result in (generated, repeated):
        assert "officer-secret" not in result.stderr
        assert "user-secret" not in result.stderr
