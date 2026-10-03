#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import functools
import shutil
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_cli
from signing.pkcs11 import (
    initialize_pkcs11_token,
    is_any_pkcs11_token_initialized,
)

SOFTHSM_MODULE = Path("/usr/lib/pkcs11/libsofthsm2.so")
SO_PIN = "12345678"
USER_PIN = "123456"
TOKEN_LABEL = "init-token-test"


def require_softhsm() -> None:
    if shutil.which("pkcs11-tool") is None or not SOFTHSM_MODULE.is_file():
        pytest.skip("SoftHSM test dependencies are missing")


@pytest.fixture
def uninitialized_softhsm_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, str]:
    """
    A SoftHSM module over an empty token directory, so that no slot
    behind it is initialized, with SOFTHSM2_CONF set in the returned
    environment and in this process's environment.
    """
    require_softhsm()
    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    config = tmp_path / "softhsm2.conf"
    config.write_text(
        f"""directories.tokendir = {token_dir}
objectstore.backend = file
log.level = WARNING
slots.removable = true
slots.mechanisms = ALL
library.reset_on_fork = false
""",
    )
    monkeypatch.setenv("SOFTHSM2_CONF", str(config))
    return {"SOFTHSM2_CONF": str(config)}


def test_is_any_token_initialized_false_before_init(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    assert not is_any_pkcs11_token_initialized(
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
    )


def test_initialize_pkcs11_token_creates_a_usable_token(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    initialize_pkcs11_token(
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
        label=TOKEN_LABEL,
        so_pin=SO_PIN,
        user_pin=USER_PIN,
    )

    assert is_any_pkcs11_token_initialized(
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
    )

    slots = run(
        ["pkcs11-tool", "--module", str(SOFTHSM_MODULE), "--list-slots"],
        env=uninitialized_softhsm_env,
    )
    assert TOKEN_LABEL in slots.stdout

    login = run(
        [
            "pkcs11-tool",
            "--module",
            str(SOFTHSM_MODULE),
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            USER_PIN,
            "--list-objects",
        ],
        env=uninitialized_softhsm_env,
    )
    assert login.returncode == 0, login.stderr


def test_initialize_pkcs11_token_keeps_an_initialized_token(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    initialize = functools.partial(
        initialize_pkcs11_token,
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
        so_pin=SO_PIN,
        user_pin=USER_PIN,
    )
    initialize(label=TOKEN_LABEL)
    login = [
        "pkcs11-tool",
        "--module",
        str(SOFTHSM_MODULE),
        "--token-label",
        TOKEN_LABEL,
        "--pin",
        USER_PIN,
    ]
    run(
        [
            *login,
            "--keypairgen",
            "--key-type",
            "rsa:1024",
            "--id",
            "2000",
            "--label",
            "kept",
        ],
        env=uninitialized_softhsm_env,
    )

    initialize(label="other-label")

    objects = run(
        [*login, "--list-objects", "--type", "privkey"],
        env=uninitialized_softhsm_env,
    )
    assert "label:      kept" in objects.stdout


def test_init_pkcs11_token_cli_creates_a_usable_token(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    environment = {
        **uninitialized_softhsm_env,
        "PYTHONPATH": str(SCRIPTS_DIR),
        "TOKEN_INIT_SO_PIN": SO_PIN,
        "TOKEN_INIT_PIN": USER_PIN,
    }

    result = run_cli(
        [
            "init-pkcs11-token",
            "--module",
            str(SOFTHSM_MODULE),
            "--label",
            TOKEN_LABEL,
            "--so-pin-env",
            "TOKEN_INIT_SO_PIN",
            "--pin-env",
            "TOKEN_INIT_PIN",
        ],
        env=environment,
    )
    assert result.returncode == 0, result.stderr

    slots = run(
        ["pkcs11-tool", "--module", str(SOFTHSM_MODULE), "--list-slots"],
        env=uninitialized_softhsm_env,
    )
    assert TOKEN_LABEL in slots.stdout


def test_init_pkcs11_token_cli_rejects_raw_pins() -> None:
    result = run_cli(
        [
            "init-pkcs11-token",
            "--module",
            str(SOFTHSM_MODULE),
            "--label",
            TOKEN_LABEL,
            "--so-pin",
            "command-line-so-secret",
            "--pin-env",
            "TOKEN_INIT_PIN",
        ],
        check=False,
    )
    assert result.returncode == 2
    assert "raw PINs are forbidden" in result.stderr
    assert "command-line-so-secret" not in result.stderr


def test_maybe_initialize_token_pkcs11_uses_python_when_flagged(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    """
    keygen.include.sh uses $BASH_SOURCE (not $0) for its own path
    resolution, so it can be sourced directly like
    vendor.yubihsm.include.sh, unlike vendor.yubihsm.keygen.sh.
    """
    program = r"""
source "$1" || exit $?
maybe_initialize_token_pkcs11
"""
    environment = {
        **uninitialized_softhsm_env,
        "PYTHONPATH": str(SCRIPTS_DIR),
        "PKCS11_PYTHON_TOOLS": "y",
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_SO_PIN": SO_PIN,
        "PKCS11_PIN": USER_PIN,
    }

    result = run(
        [
            "bash",
            "-c",
            program,
            "token-init-wiring-test",
            str(SCRIPTS_DIR / "pkcs11" / "keygen.include.sh"),
        ],
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    slots = run(
        ["pkcs11-tool", "--module", str(SOFTHSM_MODULE), "--list-slots"],
        env=uninitialized_softhsm_env,
    )
    assert TOKEN_LABEL in slots.stdout


def test_maybe_initialize_token_pkcs11_uses_bash_when_not_flagged(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    program = r"""
source "$1" || exit $?
maybe_initialize_token_pkcs11
"""
    environment = {
        **uninitialized_softhsm_env,
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_SO_PIN": SO_PIN,
        "PKCS11_PIN": USER_PIN,
    }

    result = run(
        [
            "bash",
            "-c",
            program,
            "token-init-wiring-test",
            str(SCRIPTS_DIR / "pkcs11" / "keygen.include.sh"),
        ],
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    slots = run(
        ["pkcs11-tool", "--module", str(SOFTHSM_MODULE), "--list-slots"],
        env=uninitialized_softhsm_env,
    )
    assert TOKEN_LABEL in slots.stdout


def test_python_tools_refuse_a_shell_function_as_pkcs11_tool(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    program = r"""
source "$1" || exit $?
pkcs11-tool_for_yubihsm() { :; }
PKCS11_TOOL_BIN=pkcs11-tool_for_yubihsm
maybe_initialize_token_pkcs11
"""
    result = run(
        [
            "bash",
            "-c",
            program,
            "token-init-wiring-test",
            str(SCRIPTS_DIR / "pkcs11" / "keygen.include.sh"),
        ],
        env={
            **uninitialized_softhsm_env,
            "PYTHONPATH": str(SCRIPTS_DIR),
            "PKCS11_PYTHON_TOOLS": "y",
            "PKCS11_MODULE": str(SOFTHSM_MODULE),
            "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
            "PKCS11_SO_PIN": SO_PIN,
            "PKCS11_PIN": USER_PIN,
        },
        check=False,
    )

    assert result.returncode != 0
    assert (
        "PKCS11_PYTHON_TOOLS cannot run the shell function "
        "'pkcs11-tool_for_yubihsm'."
    ) in result.stderr
