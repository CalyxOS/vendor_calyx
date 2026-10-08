#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import TEST_METADATA, install_executable
from signing import keygen, sign_environment
from signing.keygen import (
    KeygenError,
    Pkcs11KeygenDriver,
    YubiHsmKeygenDriver,
    keygen_main,
)
from yubihsm.exceptions import YubiHsmConnectionError


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


def test_yubihsm_keygen_reports_an_sdk_failure_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(self: YubiHsmKeygenDriver) -> None:
        raise YubiHsmConnectionError("connection refused")

    monkeypatch.setattr(YubiHsmKeygenDriver, "initialize_pre_metadata", fail)
    environment = {"PKCS11_VENDOR": "yubihsm", "YUBIHSM_PASSWORD": "password"}

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    assert "error: YubiHSM failure: connection refused\n" in (
        capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("operation_fails", "no_log_fail", "fails"),
    ((False, "", True), (False, "y", False), (True, "y", True)),
    ids=("log-fails", "no-log-fail", "operation-fails"),
)
def test_yubihsm_keygen_handles_a_failed_log_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation_fails: bool,
    no_log_fail: str,
    fails: bool,
) -> None:
    driver = YubiHsmKeygenDriver({"NO_LOG_FAIL": no_log_fail}, tmp_path)

    def extract_logs(comment: str) -> None:
        raise RuntimeError("the audit log is unreachable")

    def operation() -> None:
        if operation_fails:
            raise ValueError("the device refused")

    monkeypatch.setattr(driver, "_extract_logs", extract_logs)

    if fails:
        with pytest.raises((RuntimeError, ValueError)):
            driver.logged(["generate-asymmetric-key"], operation)
    else:
        driver.logged(["generate-asymmetric-key"], operation)
    assert "Failed to extract logs" in capsys.readouterr().err


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
    usage = capsys.readouterr().out
    assert usage.startswith("usage: keygen public_key_output_dir\n")
    assert "PKCS11_MODULE" not in usage
    assert not (tmp_path / "keys").exists()


def test_yubihsm_keygen_cleanup_fails_when_the_upload_fails(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    install_executable(logs / "upload.py", "#!/bin/sh\nexit 3\n")
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("entry\n")
    driver = YubiHsmKeygenDriver(
        {"YUBIHSM_LOGS_DIR": str(logs), "AUDIT_LOG_PATH": str(audit_log)},
        tmp_path / "keys",
    )

    assert driver.cleanup() is False
