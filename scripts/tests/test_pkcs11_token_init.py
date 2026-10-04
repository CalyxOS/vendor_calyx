#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import functools
from pathlib import Path

import pytest
from conftest import (
    SOFTHSM_MODULE,
    SOFTHSM_SO_PIN,
    SOFTHSM_USER_PIN,
    require_softhsm,
    run,
    softhsm_environment,
)
from signing.pkcs11 import (
    initialize_pkcs11_token,
    is_any_pkcs11_token_initialized,
)

TOKEN_LABEL = "init-token-test"


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
    environment = softhsm_environment(tmp_path, TOKEN_LABEL, initialize=False)
    monkeypatch.setenv("SOFTHSM2_CONF", environment["SOFTHSM2_CONF"])
    return environment


def test_initialize_pkcs11_token_creates_a_usable_token(
    uninitialized_softhsm_env: dict[str, str],
) -> None:
    assert not is_any_pkcs11_token_initialized(
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
    )

    initialize_pkcs11_token(
        tool="pkcs11-tool",
        module=SOFTHSM_MODULE,
        label=TOKEN_LABEL,
        so_pin=SOFTHSM_SO_PIN,
        user_pin=SOFTHSM_USER_PIN,
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
            SOFTHSM_USER_PIN,
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
        so_pin=SOFTHSM_SO_PIN,
        user_pin=SOFTHSM_USER_PIN,
    )
    initialize(label=TOKEN_LABEL)
    login = [
        "pkcs11-tool",
        "--module",
        str(SOFTHSM_MODULE),
        "--token-label",
        TOKEN_LABEL,
        "--pin",
        SOFTHSM_USER_PIN,
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
