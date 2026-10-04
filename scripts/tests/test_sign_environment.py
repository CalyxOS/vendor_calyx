#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import fcntl
import sys
import threading
from pathlib import Path

import pytest
from conftest import stub
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from signing import sign_environment
from signing.keymap import StaticKeymapper
from signing.sign_environment import (
    SoftHsmVendor,
    UnsupportedVendorError,
    Vendor,
    YubiHsmVendor,
    load_vendor,
    maybe_initialize_vendor,
    maybe_initialize_vendor_interactive,
    maybe_initialize_vendor_release,
)
from signing.vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import (
    Connector,
    EmulatedYubiHsm,
    self_signed_certificate,
)


@pytest.mark.parametrize("vendor", ("yubihsm", "softhsm"))
def test_load_vendor_leaves_pkcs11_tool_alone(vendor: str) -> None:
    environment = {
        "PKCS11_VENDOR": vendor,
        "PKCS11_TOOL_BIN": "/opt/opensc/bin/pkcs11-tool",
    }

    load_vendor(environment)

    assert environment["PKCS11_TOOL_BIN"] == "/opt/opensc/bin/pkcs11-tool"


def test_load_vendor_refuses_pkcs11_vendor_file() -> None:
    with pytest.raises(UnsupportedVendorError):
        load_vendor({"PKCS11_VENDOR_FILE": "/some/custom.sh"})


def test_maybe_initialize_vendor_interactive_skips_when_not_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(prompt: str = "") -> str:
        raise AssertionError("should not prompt")

    monkeypatch.setattr("builtins.input", fail_if_called)
    environment: dict[str, str] = {}
    maybe_initialize_vendor_interactive(environment, assume_yes=False)
    assert "PKCS11_VENDOR_INITIALIZED_INTERACTIVE" not in environment


def test_maybe_initialize_vendor_interactive_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(prompt: str = "") -> str:
        raise AssertionError("should not prompt")

    monkeypatch.setattr("builtins.input", fail_if_called)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_VENDOR_INITIALIZED_INTERACTIVE": "y",
    }
    maybe_initialize_vendor_interactive(environment, assume_yes=False)


def test_initialize_yubihsm_interactive_prompts_for_authkey_and_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": "0x0002")
    monkeypatch.setattr(
        "signing.confirmation.getpass.getpass",
        lambda prompt="": "hunter2",
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
    }

    maybe_initialize_vendor_interactive(environment, assume_yes=False)

    assert environment["YUBIHSM_AUTHKEY"] == "0x0002"
    assert environment["YUBIHSM_PASSWORD"] == "hunter2"
    assert environment["PKCS11_VENDOR_INITIALIZED_INTERACTIVE"] == "y"


def _no_password_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(prompt: str = "") -> str:
        raise AssertionError(f"unexpected prompt: {prompt}")

    monkeypatch.setattr("signing.confirmation.getpass.getpass", refuse)


def test_initialize_yubihsm_interactive_reads_password_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _no_password_prompt(monkeypatch)
    password_file = tmp_path / "signing.txt"
    password_file.write_text("hunter2\n")
    password_file.chmod(0o600)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD_FILE": str(password_file),
    }

    maybe_initialize_vendor_interactive(environment, assume_yes=False)

    assert environment["YUBIHSM_PASSWORD"] == "hunter2"


def test_initialize_yubihsm_interactive_prefers_password_over_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _no_password_prompt(monkeypatch)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "from-environment",
        "YUBIHSM_PASSWORD_FILE": str(tmp_path / "missing.txt"),
    }

    maybe_initialize_vendor_interactive(environment, assume_yes=False)

    assert environment["YUBIHSM_PASSWORD"] == "from-environment"


def test_initialize_yubihsm_interactive_refuses_readable_password_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _no_password_prompt(monkeypatch)
    password_file = tmp_path / "signing.txt"
    password_file.write_text("hunter2\n")
    password_file.chmod(0o644)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD_FILE": str(password_file),
    }

    with pytest.raises(RuntimeError, match="group or other permissions"):
        maybe_initialize_vendor_interactive(environment, assume_yes=False)
    assert "YUBIHSM_PASSWORD" not in environment


def test_initialize_yubihsm_interactive_warns_and_confirms_when_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "is_running", stub(True))
    responses = iter(["y", "0x0001"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(responses))
    monkeypatch.setattr(
        "signing.confirmation.getpass.getpass",
        lambda prompt="": "hunter2",
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    environment: dict[str, str] = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor_interactive(environment, assume_yes=False)

    assert environment["YUBIHSM_AUTHKEY"] == "0x0001"


def test_initialize_yubihsm_interactive_aborts_when_declined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "is_running", stub(True))
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    environment: dict[str, str] = {"PKCS11_VENDOR": "yubihsm"}

    with pytest.raises(RuntimeError):
        maybe_initialize_vendor_interactive(environment, assume_yes=False)


def test_initialize_yubihsm_interactive_assume_yes_skips_warning_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "is_running", stub(True))
    monkeypatch.setattr("builtins.input", lambda prompt="": "0x0001")
    monkeypatch.setattr(
        "signing.confirmation.getpass.getpass",
        lambda prompt="": "hunter2",
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    environment: dict[str, str] = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor_interactive(environment, assume_yes=True)

    assert environment["PKCS11_VENDOR_INITIALIZED_INTERACTIVE"] == "y"


def test_maybe_initialize_vendor_sets_pkcs11_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "upload.py").write_text("#!/usr/bin/env python3\n")
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor(environment, tmpdir=tmp_path)

    assert environment["PKCS11_PIN"] == "0001secret"
    assert environment["PKCS11_VENDOR_INITIALIZED"] == "y"
    assert environment["SIGNING_COMMAND_INTERCEPTOR"].endswith(
        "vendor.yubihsm.interceptor.py",
    )


def test_maybe_initialize_vendor_reads_the_password_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "upload.py").write_text("#!/usr/bin/env python3\n")
    password_file = tmp_path / "signing.txt"
    password_file.write_text("hunter2\n")
    password_file.chmod(0o600)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD_FILE": str(password_file),
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor(environment, tmpdir=tmp_path)

    assert environment["YUBIHSM_PASSWORD"] == "hunter2"
    assert environment["PKCS11_PIN"] == "0001hunter2"


def test_maybe_initialize_vendor_rejects_empty_upload_script(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """
    An empty upload.py does not mark an audit-log repository.
    """
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "upload.py").touch()
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    with pytest.raises(RuntimeError, match="not the expected git repository"):
        maybe_initialize_vendor(environment, tmpdir=tmp_path)


def test_maybe_initialize_vendor_pin_does_not_truncate_long_authkey(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "upload.py").write_text("#!/usr/bin/env python3\n")
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x12345",
        "YUBIHSM_PASSWORD": "",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor(environment, tmpdir=tmp_path)

    assert environment["PKCS11_PIN"] == "12345"


def test_maybe_initialize_vendor_dry_run_skips_full_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def refuse_to_start(self: YubiHsmConnector) -> None:
        raise AssertionError("DRY_RUN must not start yubihsm-connector")

    monkeypatch.setattr(YubiHsmConnector, "start", refuse_to_start)
    monkeypatch.chdir(tmp_path)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "DRY_RUN": "y",
    }

    maybe_initialize_vendor(environment, tmpdir=tmpdir)

    assert sorted(path.name for path in tmp_path.iterdir()) == ["tmp"]
    assert list(tmpdir.iterdir()) == []


def test_maybe_initialize_vendor_generates_pkcs11_conf(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "upload.py").write_text("#!/usr/bin/env python3\n")
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_CONNECTOR": "http://127.0.0.1:9999",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    maybe_initialize_vendor(environment, tmpdir=tmp_path)

    conf_text = Path(environment["YUBIHSM_PKCS11_CONF"]).read_text()
    assert "connector = http://127.0.0.1:9999" in conf_text


def test_maybe_initialize_vendor_requires_logs_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(YubiHsmConnector, "start", stub(None))
    monkeypatch.chdir(tmp_path)
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_CONNECTOR_BIN": "fake-yubihsm-connector",
    }

    with pytest.raises(RuntimeError):
        maybe_initialize_vendor(environment, tmpdir=tmp_path)


def test_maybe_initialize_vendor_is_idempotent(tmp_path: Path) -> None:
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_VENDOR_INITIALIZED": "y",
    }
    maybe_initialize_vendor(environment, tmpdir=tmp_path)
    assert "PKCS11_PIN" not in environment


def test_maybe_initialize_vendor_softhsm_is_a_noop(tmp_path: Path) -> None:
    environment = {"PKCS11_VENDOR": "softhsm"}
    maybe_initialize_vendor(environment, tmpdir=tmp_path)
    assert environment["PKCS11_VENDOR_INITIALIZED"] == "y"
    assert "PKCS11_PIN" not in environment


def test_load_vendor_applies_the_yubihsm_include_exports() -> None:
    environment = {"PKCS11_VENDOR": "yubihsm", "PKCS11_MODULE": "/m.so"}

    assert isinstance(load_vendor(environment), YubiHsmVendor)
    assert environment["KEYMAPPER"] == "static"
    assert environment["YUBIHSM_EXPORTABLE_DOMAIN"] == "3"
    assert environment["YUBIHSM_WRAP_KEY_ID"] == "0x0010"
    assert environment["KEYMAP_FILE"].endswith("pkcs11/keymap.tsv")
    assert environment["KEY_DIR"] == "keys/"


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        (
            SoftHsmVendor,
            (
                "/usr/local/lib/x86_64-linux-gnu/pkcs11/libsofthsm2.so",
                "/usr/local/lib/x86_64-linux-gnu/libsofthsm2.so",
                "/usr/local/lib64/pkcs11/libsofthsm2.so",
                "/usr/local/lib64/libsofthsm2.so",
                "/usr/local/lib/pkcs11/libsofthsm2.so",
                "/usr/local/lib/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/pkcs11/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/libsofthsm2.so",
                "/usr/lib64/pkcs11/libsofthsm2.so",
                "/usr/lib64/libsofthsm2.so",
                "/usr/lib/pkcs11/libsofthsm2.so",
                "/usr/lib/libsofthsm2.so",
            ),
        ),
        (
            YubiHsmVendor,
            (
                "/usr/local/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
                "/usr/local/lib/x86_64-linux-gnu/yubihsm_pkcs11.so",
                "/usr/local/lib/aarch64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
                "/usr/local/lib/aarch64-linux-gnu/yubihsm_pkcs11.so",
                "/usr/local/lib64/pkcs11/yubihsm_pkcs11.so",
                "/usr/local/lib64/yubihsm_pkcs11.so",
                "/usr/local/lib/pkcs11/yubihsm_pkcs11.so",
                "/usr/local/lib/yubihsm_pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/yubihsm_pkcs11.so",
                "/usr/lib/aarch64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
                "/usr/lib/aarch64-linux-gnu/yubihsm_pkcs11.so",
                "/usr/lib64/pkcs11/yubihsm_pkcs11.so",
                "/usr/lib64/yubihsm_pkcs11.so",
                "/usr/lib/pkcs11/yubihsm_pkcs11.so",
                "/usr/lib/yubihsm_pkcs11.so",
            ),
        ),
    ),
    ids=("softhsm", "yubihsm"),
)
def test_pkcs11_module_paths_keep_their_search_order(
    kind: type[Vendor],
    expected: tuple[str, ...],
) -> None:
    assert kind.pkcs11_module_paths == expected


@pytest.fixture
def release_environment(tmp_path: Path, yubihsm: Connector) -> dict[str, str]:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    yubihsm.device.put_wrap_key(0x0010)
    keymap_file = tmp_path / "keymap.tsv"
    keymap_file.write_text(
        "ID\tDevice\tKey Type\tKey\n0x2000\tbramble\tavb\tvbmeta\n",
    )
    (tmp_path / "keys").mkdir()
    return {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_EXPORTABLE_DOMAIN": "1",
        "YUBIHSM_ONDEMAND_DOMAIN": "3",
        "YUBIHSM_KEY_CAPABILITIES": "sign-pkcs",
        "YUBIHSM_OPAQUE_CAPABILITIES": "get-opaque",
        "YUBIHSM_LOGS_DIR": str(tmp_path / "logs"),
        "KEYMAP_FILE": str(keymap_file),
        "KEY_DIR": str(tmp_path / "keys"),
    }


def _back_up_vbmeta_key(
    device: EmulatedYubiHsm,
    key_dir: Path,
    *,
    loaded: bool,
) -> x509.Certificate:
    device.put_asymmetric_key(0x2000)
    wrapped = device.wrapped(0x2000, OBJECT.ASYMMETRIC_KEY, 0x0010)
    (key_dir / "0x2000-asymmetric-key.yhw").write_bytes(
        base64.b64encode(wrapped),
    )
    certificate = self_signed_certificate()
    (key_dir / "0x2000.x509.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    if loaded:
        device.put_certificate(0x2000, certificate)
    else:
        del device.objects[(0x2000, OBJECT.ASYMMETRIC_KEY)]
    return certificate


def _object_changes(device: EmulatedYubiHsm) -> list[COMMAND]:
    changes = (
        COMMAND.IMPORT_WRAPPED,
        COMMAND.PUT_OPAQUE,
        COMMAND.DELETE_OBJECT,
    )
    return [
        COMMAND(command)
        for _, command, _ in device.history
        if command in changes
    ]


def test_initialize_yubihsm_release_reports_a_wrong_password(
    release_environment: dict[str, str],
) -> None:
    release_environment["YUBIHSM_PASSWORD"] = "wrong"

    with pytest.raises(RuntimeError, match="YubiHSM failure"):
        maybe_initialize_vendor_release(
            release_environment,
            device="bramble",
            build_number="2026081500",
        )


def test_initialize_yubihsm_release_reports_a_device_missing_from_the_keymap(
    release_environment: dict[str, str],
) -> None:
    with pytest.raises(RuntimeError, match="Could not find key type 'avb'"):
        maybe_initialize_vendor_release(
            release_environment,
            device="redfin",
            build_number="2026081500",
        )


def test_initialize_yubihsm_release_loads_missing_vbmeta_key(
    tmp_path: Path,
    yubihsm: Connector,
    release_environment: dict[str, str],
) -> None:
    certificate = _back_up_vbmeta_key(
        yubihsm.device,
        tmp_path / "keys",
        loaded=False,
    )

    maybe_initialize_vendor_release(
        release_environment,
        device="bramble",
        build_number="2026081500",
    )

    assert yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY) is not None
    stored = yubihsm.device.get(0x2000, OBJECT.OPAQUE)
    assert stored is not None
    assert stored.data == certificate.public_bytes(serialization.Encoding.DER)
    assert release_environment["PKCS11_VENDOR_INITIALIZED_RELEASE"] == "y"
    assert Path(release_environment["AUDIT_LOG_PATH"]).is_file()


def test_initialize_yubihsm_release_is_a_noop_when_already_loaded(
    tmp_path: Path,
    yubihsm: Connector,
    release_environment: dict[str, str],
) -> None:
    _back_up_vbmeta_key(yubihsm.device, tmp_path / "keys", loaded=True)

    maybe_initialize_vendor_release(
        release_environment,
        device="bramble",
        build_number="2026081500",
    )

    assert _object_changes(yubihsm.device) == []


def test_initialize_yubihsm_release_skips_ensure_key_when_disabled(
    tmp_path: Path,
    yubihsm: Connector,
    release_environment: dict[str, str],
) -> None:
    _back_up_vbmeta_key(yubihsm.device, tmp_path / "keys", loaded=False)
    release_environment["ENSURE_KEY_IS_AVAILABLE"] = "n"

    maybe_initialize_vendor_release(
        release_environment,
        device="bramble",
        build_number="2026081500",
    )

    assert _object_changes(yubihsm.device) == []
    assert Path(release_environment["AUDIT_LOG_PATH"]).is_file()


def test_initialize_yubihsm_release_dry_run_is_a_noop(tmp_path: Path) -> None:
    environment = {"PKCS11_VENDOR": "yubihsm", "DRY_RUN": "y"}

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert environment["PKCS11_VENDOR_INITIALIZED_RELEASE"] == "y"
    assert "AUDIT_LOG_PATH" not in environment


def test_initialize_yubihsm_release_names_the_logs_after_the_command(
    release_environment: dict[str, str],
) -> None:
    environment = {**release_environment, "ENSURE_KEY_IS_AVAILABLE": "n"}

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500_2026080100",
        command="generate_delta",
    )

    suffix = "-2026081500_2026080100-bramble-generate_delta.log"
    assert environment["AUDIT_LOG_PATH"].endswith(suffix)
    assert environment["EXEC_LOG_PATH"].endswith(suffix)
    assert (
        "generate_delta.sh" in Path(environment["AUDIT_LOG_PATH"]).read_text()
    )


def test_maybe_initialize_vendor_release_is_idempotent(tmp_path: Path) -> None:
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_VENDOR_INITIALIZED_RELEASE": "y",
    }

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert "AUDIT_LOG_PATH" not in environment


def test_initialize_softhsm_release_sets_log_paths(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "SOFTHSM_LOGS_DIR": str(logs_dir),
    }

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert logs_dir.is_dir()
    assert "AUDIT_LOG_PATH" not in environment
    assert environment["EXEC_LOG_PATH"].startswith(
        f"{logs_dir}/2026081500-bramble-",
    )
    assert environment["EXEC_LOG_PATH"].endswith("-exec.log")


def test_initialize_softhsm_release_dry_run_only_renders_mkdir(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    logs_dir = tmp_path / "logs"
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "SOFTHSM_LOGS_DIR": str(logs_dir),
        "DRY_RUN": "y",
    }

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert not logs_dir.exists()
    assert f"mkdir {logs_dir}" in capsys.readouterr().err


def test_initialize_softhsm_release_names_empty_log_paths_itself(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "SOFTHSM_LOGS_DIR": str(logs_dir),
        "EXEC_LOG_PATH": "",
    }

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert environment["EXEC_LOG_PATH"].endswith("-release-exec.log")


def test_initialize_softhsm_release_respects_preset_exec_log_path(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    environment = {
        "PKCS11_VENDOR": "softhsm",
        "SOFTHSM_LOGS_DIR": str(logs_dir),
        "EXEC_LOG_PATH": "custom.log",
    }

    maybe_initialize_vendor_release(
        environment,
        device="bramble",
        build_number="2026081500",
    )

    assert environment["EXEC_LOG_PATH"] == f"{logs_dir}/custom.log"


def test_load_vendor_softhsm_applies_source_exports() -> None:
    environment = {"PKCS11_VENDOR": "softhsm", "KEYMAPPER": "legacy"}

    load_vendor(environment)

    assert environment["KEYMAPPER"] == "id2b"
    assert environment["USE_APKSIGNER"] == "y"


def test_load_vendor_yubihsm_applies_source_exports() -> None:
    environment = {"PKCS11_VENDOR": "yubihsm"}

    load_vendor(environment)

    assert environment["KEYMAPPER"] == "static"
    assert environment["YUBIHSM_EXPORTABLE_DOMAIN"] == "3"
    assert environment["KEYMAP_FILE"].endswith("pkcs11/keymap.tsv")


@pytest.mark.parametrize(
    ("vendor", "name", "default"),
    (
        ("yubihsm", "YUBIHSM_CONNECTOR", "http://127.0.0.1:12345"),
        ("yubihsm", "YUBIHSM_ONDEMAND_DOMAIN", "2"),
    ),
)
def test_load_vendor_defaults_empty_variables(
    vendor: str,
    name: str,
    default: str,
) -> None:
    environment = {"PKCS11_VENDOR": vendor, "PKCS11_MODULE": "/m.so", name: ""}

    load_vendor(environment)

    assert environment[name] == default


@pytest.mark.parametrize("vendor", ["yubihsm", "softhsm"])
def test_load_vendor_finds_pkcs11_module(
    vendor: str,
    fake_pkcs11_modules: dict[str, Path],
) -> None:
    environment = {"PKCS11_VENDOR": vendor}

    load_vendor(environment)

    assert environment["PKCS11_MODULE"] == str(fake_pkcs11_modules[vendor])


def test_load_vendor_keeps_configured_pkcs11_module() -> None:
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_MODULE": "/opt/custom.so",
    }

    load_vendor(environment)

    assert environment["PKCS11_MODULE"] == "/opt/custom.so"


def test_load_vendor_requires_pkcs11_module(
    fake_pkcs11_modules: dict[str, Path],
) -> None:
    fake_pkcs11_modules["yubihsm"].unlink()

    with pytest.raises(RuntimeError, match="YubiHSM PKCS#11 module"):
        load_vendor({"PKCS11_VENDOR": "yubihsm"})


def test_load_vendor_returns_none_without_a_vendor() -> None:
    environment: dict[str, str] = {}

    assert load_vendor(environment) is None
    assert environment["KEY_DIR"] == "keys/"


def test_load_vendor_treats_an_empty_keymapper_as_legacy() -> None:
    environment = {"KEYMAPPER": "", "KEY_DIR": "custom/"}

    load_vendor(environment)

    assert environment["KEY_DIR"] == "keys/"


def test_softhsm_vendor_counts_every_device_as_loaded() -> None:
    vendor = SoftHsmVendor()

    assert vendor.split_devices_by_loaded_keys(
        {},
        StaticKeymapper([]),
        ("bramble", "redfin"),
    ) == (("bramble", "redfin"), ())


def test_yubihsm_vendor_cleanup_stops_only_a_connector_it_started(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stopped: list[Path] = []

    class Connector:
        def __init__(self, config: YubiHsmConnectorConfig) -> None:
            self.pid_file = config.pid_file

        def stop(self) -> None:
            stopped.append(self.pid_file)

    monkeypatch.setattr(sign_environment, "YubiHsmConnector", Connector)
    inherited_pid_file = str(tmp_path / "inherited.pid")
    started_pid_file = str(tmp_path / "started.pid")
    vendor = YubiHsmVendor()

    vendor.cleanup(
        {"YUBIHSM_CONNECTOR_PIDFILE": inherited_pid_file},
        inherited={"YUBIHSM_CONNECTOR_PIDFILE": inherited_pid_file},
    )
    vendor.cleanup(
        {"YUBIHSM_CONNECTOR_PIDFILE": started_pid_file},
        inherited={"YUBIHSM_CONNECTOR_PIDFILE": inherited_pid_file},
    )

    assert stopped == [Path(started_pid_file)]


def test_load_vendor_leaves_key_dir_to_a_keymapper_file() -> None:
    environment = {
        "KEYMAPPER_FILE": "keymapper.plugin.py",
        "KEY_DIR": "custom/",
    }

    load_vendor(environment)

    assert environment["KEY_DIR"] == "custom/"


def test_yubihsm_finalize_release_extracts_under_the_lock(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    yubihsm.device.put_authentication_key(0x0001, "secret")
    lock = tmp_path / "yubihsm.lock"
    audit_log = tmp_path / "audit.log"
    environment = {
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
        "YUBIHSM_LOCKFILE": str(lock),
        "AUDIT_LOG_PATH": str(audit_log),
    }
    finalize = threading.Thread(
        target=sign_environment.YubiHsmVendor().finalize_release,
        args=(environment,),
        kwargs={
            "device": "bramble",
            "build_number": "1",
            "record_finish": True,
            "command": "release",
        },
    )

    with lock.open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        finalize.start()
        finalize.join(0.5)
        assert finalize.is_alive()
        assert not audit_log.exists()
        fcntl.flock(held, fcntl.LOCK_UN)
    finalize.join(30)

    assert "Finished BUILD_NUMBER=1 DEVICE=bramble release.sh" in (
        audit_log.read_text()
    )


@pytest.mark.parametrize(
    ("contents", "mode", "message"),
    (
        (None, 0o600, "is not a file."),
        ("secret\n", 0o640, "must not have group or other permissions."),
        ("one\ntwo\n", 0o600, "must contain exactly one non-empty line."),
        ("secret\n\n", 0o600, "must contain exactly one non-empty line."),
        (b"caf\xe9\n", 0o600, "is not valid UTF-8."),
    ),
    ids=("missing", "shared", "two-lines", "blank-line", "latin-1"),
)
def test_read_yubihsm_password_file_reports_as_bash_does(
    tmp_path: Path,
    contents: str | bytes | None,
    mode: int,
    message: str,
) -> None:
    password_file = tmp_path / "password"
    if contents is not None:
        password_file.write_bytes(
            contents if isinstance(contents, bytes) else contents.encode(),
        )
        password_file.chmod(mode)
    environment = {"YUBIHSM_PASSWORD_FILE": str(password_file)}

    with pytest.raises(RuntimeError) as raised:
        sign_environment.read_yubihsm_password_file(environment)

    assert str(raised.value) == (
        f"YUBIHSM_PASSWORD_FILE ({password_file}) {message}"
    )


@pytest.mark.parametrize(
    "contents",
    ("pass\fword\n", "secret\r\n", "secret"),
    ids=("form-feed", "crlf", "no-newline"),
)
def test_read_yubihsm_password_file_splits_lines_as_mapfile(
    tmp_path: Path,
    contents: str,
) -> None:
    password_file = tmp_path / "password"
    password_file.write_text(contents)
    password_file.chmod(0o600)
    environment = {"YUBIHSM_PASSWORD_FILE": str(password_file)}

    assert sign_environment.read_yubihsm_password_file(environment)
    assert environment["YUBIHSM_PASSWORD"] == contents.split("\n")[
        0
    ].removesuffix(
        "\r",
    )


def test_finalize_vendor_release_finalizes_then_cleans_up_the_vendor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class RecordingVendor:
        def finalize_release(
            self,
            environment: dict[str, str],
            **options: object,
        ) -> None:
            calls.append(f"finalize {options['command']}")

        def cleanup(
            self,
            environment: dict[str, str],
            *,
            inherited: dict[str, str],
        ) -> None:
            calls.append("cleanup")

    def load_vendor(environment: dict[str, str]) -> RecordingVendor:
        return RecordingVendor()

    monkeypatch.setattr(sign_environment, "load_vendor", load_vendor)

    sign_environment.finalize_vendor_release(
        {},
        device="bramble",
        build_number="1",
        record_finish=True,
        inherited={},
        command="generate_delta",
    )

    assert calls == ["finalize generate_delta", "cleanup"]
