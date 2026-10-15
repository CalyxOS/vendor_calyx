#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import ID2B_KEYMAP, TEST_METADATA, install_executable
from cryptography.hazmat.primitives.serialization import Encoding
from signing import keygen, sign_environment
from signing.keygen import (
    KeygenError,
    Pkcs11KeygenDriver,
    YubiHsmKeygenDriver,
    export_public_keys,
    keygen_main,
)
from yubihsm.defs import OBJECT
from yubihsm.exceptions import YubiHsmConnectionError
from yubihsm_emulator import Connector, self_signed_certificate


def _softhsm_main_environment(tmp_path: Path) -> dict[str, str]:
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    return {
        "PKCS11_VENDOR": "softhsm",
        "KEYMAPPER": "id2b",
        "METADATA_FILE": str(TEST_METADATA),
        "DEVICES_FILE": str(devices),
        "TMPDIR": str(tmp_path),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "PKCS11_TOOL_BIN": "/bin/true",
        "OPENSSL_BIN": "/bin/true",
    }


def _yubihsm_driver(
    yubihsm: Connector,
    output: Path,
    **overrides: str,
) -> YubiHsmKeygenDriver:
    return YubiHsmKeygenDriver(
        {
            "YUBIHSM_CONNECTOR": yubihsm.url,
            "YUBIHSM_AUTHKEY": "0x0001",
            "YUBIHSM_PASSWORD": "password",
            **overrides,
        },
        output,
    )


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

    def interactive(
        environment: object,
        vendor: object,
        *,
        assume_yes: bool,
    ) -> None:
        answers.append(assume_yes)
        raise KeygenError("stop")

    monkeypatch.setattr(
        sign_environment,
        "maybe_initialize_vendor_interactive",
        interactive,
    )
    environment = {
        **_softhsm_main_environment(tmp_path),
        "SIGN_ASSUME_YES": "y",
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
    def fail(
        environment: object,
        vendor: object,
        *,
        assume_yes: bool,
    ) -> None:
        raise failure

    monkeypatch.setattr(
        sign_environment,
        "maybe_initialize_vendor_interactive",
        fail,
    )
    environment = _softhsm_main_environment(tmp_path)

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    message = failure.args[0] if isinstance(failure, KeyError) else failure
    assert f"error: {message}\n" in capsys.readouterr().err


def test_keygen_writes_the_stderr_of_a_failed_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(
        environment: object,
        vendor: object,
        *,
        assume_yes: bool,
    ) -> None:
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
    environment = _softhsm_main_environment(tmp_path)

    assert keygen_main(environment, [str(tmp_path / "keys")]) == 1
    assert "CKR_PIN_INCORRECT" in capsys.readouterr().err


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


@pytest.mark.parametrize("dry_run", ("", "y"))
def test_yubihsm_keygen_evicts_by_its_own_backups(
    tmp_path: Path,
    yubihsm: Connector,
    monkeypatch: pytest.MonkeyPatch,
    dry_run: str,
) -> None:
    searched: list[Path] = []

    def limit(
        config: object,
        key_dir: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        searched.append(key_dir)

    monkeypatch.setattr(keygen, "limit_ondemand_objects", limit)
    output = tmp_path / "elsewhere"
    driver = _yubihsm_driver(
        yubihsm,
        output,
        KEY_DIR="keys/",
        YUBIHSM_ONDEMAND_DOMAIN="2",
        YUBIHSM_KEY_CAPABILITIES="exportable-under-wrap",
        YUBIHSM_LOGS_DIR=str(tmp_path / "logs"),
        KEYMAP_FILE=str(ID2B_KEYMAP),
        DRY_RUN=dry_run,
    )

    driver.initialize_post_metadata()

    assert searched == [output]


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


def test_yubihsm_keygen_needs_the_certificate_file(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    """
    A certificate an older version of the scripts stored on the HSM does
    not stand in for the .x509.pem file signing reads.
    """
    yubihsm.device.put_certificate(
        0x2000,
        yubihsm.device.attestation_certificate,
    )
    driver = _yubihsm_driver(yubihsm, tmp_path)

    assert not driver.cert_exists("0x2000")
    (tmp_path / "0x2000.x509.pem").write_text("certificate\n")
    assert driver.cert_exists("0x2000")


def test_yubihsm_keygen_writes_the_certificate_stored_on_the_hsm(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    """
    A key whose certificate an older version of the scripts stored on the
    HSM gets that certificate back as its file, not a new attestation.
    """
    stored = self_signed_certificate(
        key=yubihsm.device.put_asymmetric_key(0x2000),
    )
    yubihsm.device.put_certificate(0x2000, stored)
    driver = _yubihsm_driver(
        yubihsm,
        tmp_path / "keys",
        AUDIT_LOG_PATH=str(tmp_path / "audit.log"),
        YUBIHSM_ONDEMAND_DOMAIN="3",
    )

    driver.generate_cert("0x2000", "app", "RSA:4096")

    assert (tmp_path / "keys/0x2000.x509.pem").read_bytes() == (
        stored.public_bytes(Encoding.PEM)
    )
    assert not (tmp_path / "keys/0x2000.attestation.pem").exists()


def test_yubihsm_keygen_attests_a_key_its_stored_certificate_does_not_name(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    """
    A certificate left on the HSM under the key's ID that certifies
    another key, such as an earlier key under that ID, is not the key's
    certificate, so the key is attested.
    """
    yubihsm.device.put_asymmetric_key(0x2000)
    yubihsm.device.put_certificate(
        0x2000,
        yubihsm.device.attestation_certificate,
    )
    driver = _yubihsm_driver(
        yubihsm,
        tmp_path / "keys",
        AUDIT_LOG_PATH=str(tmp_path / "audit.log"),
        YUBIHSM_ONDEMAND_DOMAIN="3",
    )

    driver.generate_cert("0x2000", "app", "RSA:4096")

    assert (tmp_path / "keys/0x2000.attestation.pem").exists()
    assert (tmp_path / "keys/0x2000.x509.pem").read_bytes() != (
        yubihsm.device.attestation_certificate.public_bytes(Encoding.PEM)
    )


@pytest.mark.parametrize("stored", (True, False), ids=("stored", "none"))
def test_yubihsm_keygen_dry_run_previews_the_attestation_it_would_make(
    tmp_path: Path,
    yubihsm: Connector,
    capsys: pytest.CaptureFixture[str],
    stored: bool,
) -> None:
    key = yubihsm.device.put_asymmetric_key(0x2000)
    if stored:
        yubihsm.device.put_certificate(0x2000, self_signed_certificate(key=key))
    driver = _yubihsm_driver(
        yubihsm,
        tmp_path / "keys",
        YUBIHSM_ONDEMAND_DOMAIN="3",
        DRY_RUN="y",
    )

    driver.generate_cert("0x2000", "app", "RSA:4096")

    captured = capsys.readouterr()
    assert ("attest-key" in captured.out + captured.err) is not stored
    assert not (tmp_path / "keys/0x2000.x509.pem").exists()


@pytest.mark.parametrize("dry_run", ("", "y"), ids=("live", "dry-run"))
def test_yubihsm_keygen_certifies_only_a_key_on_the_hsm(
    tmp_path: Path,
    yubihsm: Connector,
    capsys: pytest.CaptureFixture[str],
    dry_run: str,
) -> None:
    """
    A key evicted to its backup, with its certificate left on the HSM, is
    not certified until it is loaded again.
    """
    key = yubihsm.device.put_asymmetric_key(0x2000)
    yubihsm.device.put_certificate(0x2000, self_signed_certificate(key=key))
    del yubihsm.device.objects[(0x2000, OBJECT.ASYMMETRIC_KEY)]
    driver = _yubihsm_driver(
        yubihsm,
        tmp_path / "keys",
        YUBIHSM_ONDEMAND_DOMAIN="3",
        DRY_RUN=dry_run,
    )

    if dry_run:
        driver.generate_cert("0x2000", "app", "RSA:4096")
        assert "attest-key" in capsys.readouterr().err
    else:
        with pytest.raises(KeygenError):
            driver.generate_cert("0x2000", "app", "RSA:4096")
        assert "Key 0x2000 is not on the HSM." in capsys.readouterr().err
    assert not (tmp_path / "keys/0x2000.x509.pem").exists()


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


def test_export_public_keys_reports_each_key_before_the_next_runs(
    tmp_path: Path,
) -> None:
    certificate = tmp_path / "0x2000.x509.pem"
    certificate.write_bytes(
        self_signed_certificate().public_bytes(Encoding.PEM),
    )
    written: list[Path] = []

    with pytest.raises(subprocess.CalledProcessError):
        export_public_keys(
            {"OPENSSL_BIN": "openssl", "AVBTOOL_BIN": "/bin/false"},
            certificate,
            "avb",
            written.append,
        )

    assert written == [tmp_path / "0x2000.pem"]
    assert written[0].is_file()


def test_openssl_engine_paths_keep_their_search_order() -> None:
    assert keygen.OPENSSL_ENGINE_PATHS == (
        "/usr/local/lib/x86_64-linux-gnu/engines-3/libpkcs11.so",
        "/usr/local/lib/aarch64-linux-gnu/engines-3/libpkcs11.so",
        "/usr/local/lib64/engines-3/libpkcs11.so",
        "/usr/local/lib/engines-3/libpkcs11.so",
        "/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so",
        "/usr/lib/aarch64-linux-gnu/engines-3/libpkcs11.so",
        "/usr/lib64/engines-3/libpkcs11.so",
        "/usr/lib/engines-3/libpkcs11.so",
    )
