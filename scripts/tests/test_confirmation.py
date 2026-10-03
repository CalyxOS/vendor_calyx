#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import io
import sys

import pytest
from signing.confirmation import ask_variable, confirm


@pytest.mark.parametrize(
    ("answers", "expected", "reprompts"),
    (
        (["y"], True, 0),
        (["n"], False, 0),
        (["Y"], True, 0),
        ([" y\t"], True, 0),
        ([EOFError], False, 0),
        (["maybe", "sure", "y"], True, 2),
        (["yes", "no", "n"], False, 2),
    ),
)
def test_confirm_takes_only_y_or_n(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answers: list[str | type[EOFError]],
    expected: bool,
    reprompts: int,
) -> None:
    responses = iter(answers)

    def answer(prompt: str = "") -> str:
        response = next(responses)
        if not isinstance(response, str):
            raise response
        return response

    monkeypatch.setattr("builtins.input", answer)
    assert confirm("Continue?") is expected
    assert capsys.readouterr().err.count("Please enter Y or N.") == reprompts


def test_confirm_assume_yes_skips_prompting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_if_called(prompt: str = "") -> str:
        raise AssertionError("input() must not be called under assume_yes")

    monkeypatch.setattr("builtins.input", fail_if_called)
    assert confirm("Continue?", assume_yes=True) is True
    assert "auto-answered by SIGN_ASSUME_YES=y" in capsys.readouterr().out


def test_ask_variable_uses_existing_environment_value() -> None:
    environment = {"PKCS11_MODULE": "/usr/lib/softhsm2.so"}
    assert ask_variable("PKCS11_MODULE", environment) == "/usr/lib/softhsm2.so"


def test_ask_variable_applies_default_on_blank_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    environment: dict[str, str] = {}
    value = ask_variable("YUBIHSM_AUTHKEY", environment, default="0x0001")
    assert value == "0x0001"
    assert environment["YUBIHSM_AUTHKEY"] == "0x0001"


def test_ask_variable_reprompts_until_nonempty_when_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(["", "", "some-value"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(responses))
    environment: dict[str, str] = {}
    assert ask_variable("VAR", environment) == "some-value"


def test_ask_variable_accepts_blank_when_not_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    environment: dict[str, str] = {}
    assert ask_variable("VAR", environment, needs_value=False) == ""
    assert environment["VAR"] == ""


def test_ask_variable_literal_empty_quotes_mean_explicitly_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": '""')
    environment: dict[str, str] = {}
    value = ask_variable(
        "VAR",
        environment,
        default="fallback",
        needs_value=False,
    )
    assert value == ""
    assert environment["VAR"] == ""


def test_ask_variable_private_uses_getpass_and_does_not_log_value(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "signing.confirmation.getpass.getpass",
        lambda prompt="": "secret",
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    environment: dict[str, str] = {}
    value = ask_variable("YUBIHSM_PASSWORD", environment, private=True)
    assert value == "secret"
    assert "secret" not in capsys.readouterr().out


def test_ask_variable_private_reads_a_pipe_without_a_prompt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("secret\n"))
    environment: dict[str, str] = {}

    value = ask_variable("YUBIHSM_PASSWORD", environment, private=True)

    captured = capsys.readouterr()
    assert value == "secret"
    assert captured.out == "\n"
    assert captured.err == ""


def test_ask_variable_private_already_set_does_not_log_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = {"YUBIHSM_PASSWORD": "secret"}
    value = ask_variable("YUBIHSM_PASSWORD", environment, private=True)
    assert value == "secret"
    out = capsys.readouterr().out
    assert "secret" not in out
    assert "Using YUBIHSM_PASSWORD from environment." in out


def _raise_eof(prompt: str = "") -> str:
    raise EOFError


@pytest.mark.parametrize(
    ("default", "needs_value", "expected"),
    [("0x0001", True, "0x0001"), ("dflt", False, "dflt"), ("", False, "")],
)
def test_ask_variable_takes_the_default_on_closed_stdin(
    monkeypatch: pytest.MonkeyPatch,
    default: str,
    needs_value: bool,
    expected: str,
) -> None:
    monkeypatch.setattr("builtins.input", _raise_eof)
    environment: dict[str, str] = {}
    value = ask_variable(
        "SOME_VAR",
        environment,
        default=default,
        needs_value=needs_value,
    )
    assert value == expected
    assert environment["SOME_VAR"] == expected


def test_ask_variable_fails_on_closed_stdin_without_a_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", _raise_eof)
    with pytest.raises(RuntimeError, match="SOME_VAR"):
        ask_variable("SOME_VAR", {})


def test_ask_variable_prompts_only_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": " 0x0001 ")
    environment: dict[str, str] = {}

    assert ask_variable("YUBIHSM_AUTHKEY", environment) == "0x0001"
    assert environment["YUBIHSM_AUTHKEY"] == "0x0001"
    captured = capsys.readouterr()
    assert "Enter YUBIHSM_AUTHKEY" not in captured.out + captured.err
