#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import TEST_METADATA
from signing import keygen, sign_environment
from signing.keygen import KeygenError, Pkcs11KeygenDriver, keygen_main


@pytest.mark.parametrize("testing", ("", "n"))
def test_pkcs11_keygen_refuses_to_default_the_pins_outside_testing(
    tmp_path: Path,
    testing: str,
) -> None:
    environment = {"PKCS11_TESTING": testing}

    with pytest.raises(KeygenError):
        Pkcs11KeygenDriver(environment, tmp_path).initialize_post_metadata()

    assert "PKCS11_SO_PIN" not in environment
    assert "PKCS11_PIN" not in environment


def test_pkcs11_keygen_defaults_the_so_pin_only_for_pkcs11_testing_y(
    tmp_path: Path,
) -> None:
    environment = {
        "PKCS11_TESTING": "1",
        "PKCS11_PIN": "123456",
        "PKCS11_MODULE": "/dev/null",
    }

    Pkcs11KeygenDriver(environment, tmp_path).initialize_post_metadata()

    assert "PKCS11_SO_PIN" not in environment


def test_keygen_honours_sign_assume_yes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers: list[bool] = []

    def interactive(environment: object, *, assume_yes: bool) -> None:
        answers.append(assume_yes)
        raise KeygenError("stop")

    monkeypatch.setattr(
        sign_environment,
        "maybe_initialize_vendor_interactive",
        interactive,
    )
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "KEYMAPPER": "id2b",
        "METADATA_FILE": str(TEST_METADATA),
        "DEVICES_FILE": str(devices),
        "SIGN_ASSUME_YES": "y",
        "TMPDIR": str(tmp_path),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "PKCS11_TOOL_BIN": "/bin/true",
        "OPENSSL_BIN": "/bin/true",
    }

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    assert answers == [True]


def test_pkcs11_keygen_explains_an_unsupported_extraction_mode(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    driver = Pkcs11KeygenDriver({"EXTRACTION_ARGS": "--extractable"}, tmp_path)

    with pytest.raises(KeygenError):
        driver.spec("0x2000", "label", "RSA:4096")

    assert "Unsupported EXTRACTION_ARGS='--extractable'" in (
        capsys.readouterr().err
    )


def test_pkcs11_keygen_finds_the_openssl_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = tmp_path / "libpkcs11.so"
    engine.touch()
    monkeypatch.setattr(
        keygen,
        "OPENSSL_ENGINE_PATHS",
        (str(tmp_path / "missing.so"), str(engine)),
    )
    environment = {"PKCS11_TOOL_BIN": "/bin/true"}

    Pkcs11KeygenDriver(environment, tmp_path).initialize_pre_metadata()

    assert environment["PKCS11_OPENSSL_ENGINE_LIBRARY_PATH"] == str(engine)


def test_pkcs11_keygen_needs_the_openssl_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        keygen,
        "OPENSSL_ENGINE_PATHS",
        (str(tmp_path / "missing.so"),),
    )

    with pytest.raises(KeygenError):
        Pkcs11KeygenDriver(
            {"PKCS11_TOOL_BIN": "/bin/true"},
            tmp_path,
        ).initialize_pre_metadata()


def test_openssl_engine_paths_follow_the_brace_pattern() -> None:
    expanded = subprocess.run(
        [
            "bash",
            "-c",
            "printf '%s\\n' /usr{/local,}/lib{/x86_64-linux-gnu,"
            "/aarch64-linux-gnu,64,}/engines-3/libpkcs11.so",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    assert list(keygen.OPENSSL_ENGINE_PATHS) == expanded


@pytest.mark.parametrize(
    "failure",
    (
        RuntimeError("no PKCS#11 module"),
        subprocess.CalledProcessError(1, ["openssl"]),
        FileNotFoundError(2, "No such file or directory", "/missing/tool"),
        KeyError("Could not find key type 'core' and name 'releasekey'"),
    ),
    ids=("vendor", "tool", "missing-tool", "keymap"),
)
def test_keygen_reports_a_failure_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: Exception,
) -> None:
    def fail(environment: object, *, assume_yes: bool) -> None:
        raise failure

    monkeypatch.setattr(
        sign_environment,
        "maybe_initialize_vendor_interactive",
        fail,
    )
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "KEYMAPPER": "id2b",
        "METADATA_FILE": str(TEST_METADATA),
        "DEVICES_FILE": str(devices),
        "TMPDIR": str(tmp_path),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "PKCS11_TOOL_BIN": "/bin/true",
        "OPENSSL_BIN": "/bin/true",
    }

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    message = failure.args[0] if isinstance(failure, KeyError) else failure
    assert f"error: {message}\n" in capsys.readouterr().err


def test_keygen_writes_the_stderr_of_a_failed_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(environment: object, *, assume_yes: bool) -> None:
        raise subprocess.CalledProcessError(
            1,
            ["pkcs11-tool", "--keypairgen"],
            stderr=b"C_Login failed: CKR_PIN_INCORRECT\n",
        )

    monkeypatch.setattr(
        sign_environment,
        "maybe_initialize_vendor_interactive",
        fail,
    )
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "KEYMAPPER": "id2b",
        "METADATA_FILE": str(TEST_METADATA),
        "DEVICES_FILE": str(devices),
        "TMPDIR": str(tmp_path),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "PKCS11_TOOL_BIN": "/bin/true",
        "OPENSSL_BIN": "/bin/true",
    }

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    assert "CKR_PIN_INCORRECT" in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    (["--help"], ["-x"], ["keys", "-h"]),
    ids=("help", "short-option", "help-after-directory"),
)
def test_keygen_prints_usage_for_a_help_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    assert keygen_main({}, arguments) == 0
    assert "usage: keygen" in capsys.readouterr().out
    assert not (tmp_path / "keys").exists()
