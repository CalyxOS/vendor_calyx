#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from conftest import stub
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
)
from signing.vendor_yubihsm_connector import (
    YubiHsmConnector,
    YubiHsmConnectorConfig,
)


def test_load_vendor_yubihsm_wraps_pkcs11_tool() -> None:
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_TOOL_BIN": "/opt/opensc/bin/pkcs11-tool",
    }

    load_vendor(environment)
    load_vendor(environment)

    assert environment["PKCS11_TOOL_BIN"].endswith(
        "pkcs11/pkcs11_tool.yubihsm.sh",
    )
    assert (
        environment["YUBIHSM_UNDERLYING_PKCS11_TOOL_BIN"]
        == "/opt/opensc/bin/pkcs11-tool"
    )


def test_load_vendor_softhsm_leaves_pkcs11_tool_alone() -> None:
    environment = {"PKCS11_VENDOR": "softhsm"}

    load_vendor(environment)

    assert "PKCS11_TOOL_BIN" not in environment


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


def test_maybe_initialize_vendor_requires_python_interceptor(
    tmp_path: Path,
) -> None:
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "secret",
    }
    with pytest.raises(UnsupportedVendorError):
        maybe_initialize_vendor(environment, tmpdir=tmp_path)


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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
        "PKCS11_PYTHON_INTERCEPTOR": "y",
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
    ("kind", "pattern"),
    (
        (
            SoftHsmVendor,
            "/usr{/local,}/lib{/x86_64-linux-gnu,64,}{/pkcs11,}/libsofthsm2.so",
        ),
        (
            YubiHsmVendor,
            "/usr{/local,}/lib{/x86_64-linux-gnu,/aarch64-linux-gnu,64,}"
            "{/pkcs11,}/yubihsm_pkcs11.so",
        ),
    ),
)
def test_pkcs11_module_paths_keep_their_search_order(
    kind: type[Vendor],
    pattern: str,
) -> None:
    expanded = subprocess.run(
        ["bash", "-c", f"printf '%s\\n' {pattern}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    assert list(kind.pkcs11_module_paths) == expanded


def test_load_vendor_softhsm_applies_source_exports() -> None:
    """
    Loading the SoftHSM vendor exports these even though its
    initialize_vendor() does nothing else. The AVB signing helper reads
    OPENSSL_PKCS11_URI_USES_HEX_KEY_ID to look keys up by ID, and keygen
    reads STRIP_HEX_KEY_ID_PREFIX to strip the 0x from the IDs it writes.
    """
    environment = {"PKCS11_VENDOR": "softhsm", "KEYMAPPER": "legacy"}

    load_vendor(environment)

    assert environment["KEYMAPPER"] == "id2b"
    assert environment["OPENSSL_PKCS11_URI_USES_HEX_KEY_ID"] == "y"
    assert environment["STRIP_HEX_KEY_ID_PREFIX"] == "y"
    assert environment["FIND_KEYS_BY_ID"] == "y"
    assert environment["USE_APKSIGNER"] == "y"


def test_load_vendor_yubihsm_applies_source_exports() -> None:
    environment = {"PKCS11_VENDOR": "yubihsm"}

    load_vendor(environment)

    assert environment["KEYMAPPER"] == "static"
    assert environment["OPENSSL_PKCS11_URI_USES_HEX_KEY_ID"] == "y"
    assert environment["STRIP_HEX_KEY_ID_PREFIX"] == "y"
    assert environment["YUBIHSM_EXPORTABLE_DOMAIN"] == "3"
    assert environment["KEYMAP_FILE"].endswith("pkcs11/keymap.tsv")


@pytest.mark.parametrize(
    ("vendor", "name", "default"),
    (
        ("yubihsm", "YUBIHSM_CONNECTOR", "http://127.0.0.1:12345"),
        ("yubihsm", "YUBIHSM_ONDEMAND_DOMAIN", "2"),
        ("softhsm", "DATE_FORMAT", "%Y%m%d-%H%M%S"),
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
