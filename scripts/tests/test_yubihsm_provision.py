#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, YUBIHSM_SDK, parameter_id, run, run_cli
from signing import yubihsm_provision
from signing.keymap import Id2bKeymapper
from signing.metadata import load_metadata
from yubihsm.defs import OBJECT
from yubihsm_emulator import Connector

PROVISION_SH = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.provision.sh"
WRAP_KEY_ID = 0x0010


def _provisioning_tree(root: Path, yubihsm: Connector) -> dict[str, str]:
    provisioning = root / "hsmp"
    provisioning.mkdir()
    (root / "devices").write_text("readonly devices=(bramble)\n")
    keymap = run_cli(
        [
            "generate-keymap",
            "--devices",
            "bramble",
        ],
    ).stdout
    (root / "keymap.tsv").write_text(keymap)
    return {
        "PYTHONPATH": os.pathsep.join([str(SCRIPTS_DIR), YUBIHSM_SDK]),
        "PATH": os.environ["PATH"],
        "HOME": str(root),
        "PROVISIONING_PATH": str(provisioning),
        "DEVICES_FILE": str(root / "devices"),
        "KEEP_PATH": str(root / "keep"),
        "KEYMAP_FILE": str(root / "keymap.tsv"),
        "YUBIHSM_CONNECTOR": yubihsm.url,
    }


PROVISION_FIXTURES = Path(__file__).parent / "fixtures" / "provision"


def _wizard(
    mode: str,
    environment: dict[str, str],
    input_text: str,
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        [PROVISION_SH, mode],
        env=environment,
        input_text=input_text,
        cwd=cwd,
        check=False,
    )


def _audit_comments(keep: Path, yubihsm: Connector) -> list[str]:
    comments: list[str] = []
    for log in sorted((keep / "logs").rglob("*.log")):
        for line in log.read_text().splitlines():
            if line.startswith("#"):
                comment = re.sub(r"^# \S+ \S+ ", "# ", line)
                comments.append(
                    comment.replace(str(keep), "<keep>").replace(
                        yubihsm.url,
                        "<connector>",
                    ),
                )
    return comments


def _tree(directory: Path, yubihsm: Connector) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix == ".log":
            continue
        if path.name.endswith("-asymmetric-key.yhw"):
            object_id, object_type = yubihsm.device.unwrap(
                base64.b64decode(path.read_bytes()),
                WRAP_KEY_ID,
            )
            content = f"<wrapped {object_id:#06x} {object_type.name}>"
        elif path.name.endswith((".x509.pem", ".avbpubkey", ".pem")):
            content = "<generated>"
        else:
            content = path.read_text()
        files[str(path.relative_to(directory))] = content
    return files


KEYGEN_METADATA = """KEYS_AVB = ("vbmeta",)
KEYS_OTHER = ("ota",)
KEYS_CORE = ("build/make/target/product/security/testkey",)
KEYS_APEX = ()
KEYS_APEX_APK = ()
KEYS_APP = ()
KEYS_REPO = ()
KEY_TYPES = ("avb", "other", "core")
MAPPED_KEY_TYPES = ("core",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "other": "keys_other",
    "core": "keys_core",
}
"""


def _source_directory(root: Path) -> Path:
    source = root / "src"
    (source / "logs").mkdir(parents=True)
    upload = source / "logs" / "upload.py"
    upload.write_text("#!/bin/sh\n")
    upload.chmod(0o755)
    return source


def _keygen_environment(root: Path, avbtool: Path) -> dict[str, str]:
    metadata = root / "metadata.py"
    metadata.write_text(KEYGEN_METADATA)
    keymap = Id2bKeymapper(load_metadata(metadata)).to_tsv(("bramble",))
    (root / "keymap.tsv").write_text(keymap)
    (root / "tmp").mkdir()
    return {
        "METADATA_FILE": str(metadata),
        "AVBTOOL_BIN": str(avbtool),
        "TMPDIR": str(root / "tmp"),
        "PKCS11_MODULE": "/dev/null",
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "UNIQUE_KEY_OUT_DIR": str(root / "keep" / "keys" / "unique"),
    }


def _outcome(
    tmp_path: Path,
    mode: str,
    input_text: str,
    yubihsm: Connector,
    avbtool: Path | None = None,
) -> dict[str, object]:
    root = tmp_path
    device = yubihsm.device
    device.put_authentication_key(0x0001, "signing-password")
    device.put_wrap_key(WRAP_KEY_ID)
    for object_id in (0x0101, 0x0102):
        device.put_asymmetric_key(object_id)
    (root / "keys").mkdir()
    (root / "keys" / "0x0101-asymmetric-key.yhw").write_bytes(
        base64.b64encode(
            device.wrapped(0x0101, OBJECT.ASYMMETRIC_KEY, WRAP_KEY_ID),
        )
        + b"\n",
    )
    if mode == "load-keys":
        for object_id in (0x0101, 0x0102):
            del device.objects[(object_id, OBJECT.ASYMMETRIC_KEY)]
    environment = _provisioning_tree(root, yubihsm)
    environment["SOURCE_DIRECTORY"] = str(_source_directory(root))
    if avbtool is not None:
        environment.update(_keygen_environment(root, avbtool))
    result = _wizard(mode, environment, input_text, cwd=root)
    keep = root / "keep"
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.replace(str(root), "<root>"),
        "stderr": result.stderr.replace(str(root), "<root>"),
        "files": {
            name: content.replace(str(root), "<root>")
            for name, content in (
                _tree(keep, yubihsm) if keep.exists() else {}
            ).items()
        },
        "audit": _audit_comments(keep, yubihsm) if keep.exists() else [],
        "keys": [
            f"{object_id:#06x}"
            for object_id, object_type in sorted(device.objects)
            if object_type == OBJECT.ASYMMETRIC_KEY
        ],
    }


@pytest.mark.parametrize(
    ("mode", "input_text"),
    [
        ("backup", "n\nsigning-password\ny\n"),
        ("restore", "n\n"),
        ("backup", "n\nsigning-password\nn\nn\n"),
        ("bogus", ""),
        ("load-keys", "signing-password\nn\ny\n"),
        ("keygen", "n\nsigning-password\ny\n"),
    ],
    ids=(
        "backup",
        "restore",
        "backup-without-hsm",
        "unknown-mode",
        "load-keys",
        "keygen",
    ),
)
def test_wizard_runs_its_stages(
    tmp_path: Path,
    mode: str,
    input_text: str,
    request: pytest.FixtureRequest,
    yubihsm: Connector,
) -> None:
    expected = json.loads(
        (PROVISION_FIXTURES / f"{parameter_id(request)}.json").read_text(),
    )

    avbtool = None
    if mode == "keygen":
        aosp_top = request.getfixturevalue("aosp_top")
        avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"
    assert _outcome(tmp_path, mode, input_text, yubihsm, avbtool) == expected


def test_wizard_gives_up_after_one_failure_under_sign_assume_yes(
    tmp_path: Path,
) -> None:
    from signing.yubihsm_provision import ProvisionWizard, StepFailed

    wizard = ProvisionWizard({"SIGN_ASSUME_YES": "y"}, cwd=tmp_path)
    calls: list[int] = []

    def always_fails() -> None:
        calls.append(1)
        raise StepFailed(3)

    assert wizard.try_("connect_hsm", always_fails) == 3
    assert calls == [1]


@pytest.mark.parametrize(
    ("export_fails", "no_log_fail", "fails"),
    (
        (False, "", True),
        (False, "y", False),
        (True, "y", True),
        (True, "", True),
    ),
    ids=("log-fails", "no-log-fail", "export-fails", "both-fail"),
)
def test_wizard_backup_handles_a_failed_log_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    export_fails: bool,
    no_log_fail: str,
    fails: bool,
) -> None:
    def export_wrapped_key(config: object, key_id: str) -> bytes:
        if export_fails:
            raise RuntimeError("the device refused")
        return b"wrapped"

    def extract_logs(comment: str) -> None:
        raise RuntimeError("the audit log is unreachable")

    monkeypatch.setattr(
        yubihsm_provision,
        "export_wrapped_key",
        export_wrapped_key,
    )
    wizard = yubihsm_provision.ProvisionWizard(
        {
            "NO_LOG_FAIL": no_log_fail,
            "KEY_DIR": str(tmp_path),
            "YUBIHSM_CONNECTOR": "http://127.0.0.1:1",
            "YUBIHSM_PASSWORD": "password",
            "YUBIHSM_WRAP_KEY_ID": "0x0010",
        },
        cwd=tmp_path,
    )
    monkeypatch.setattr(wizard, "_extract_logs", extract_logs)

    if fails:
        with pytest.raises(yubihsm_provision.StepFailed):
            wizard.export_wrapped_key("0x2000")
    else:
        wizard.export_wrapped_key("0x2000")
        assert (tmp_path / "0x2000-asymmetric-key.yhw").is_file()
    err = capsys.readouterr().err
    assert "Failed to extract logs" in err
    assert ("error: the device refused" in err) is export_fails


def test_wizard_backup_dry_run_exports_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def export_wrapped_key(config: object, key_id: str) -> bytes:
        raise AssertionError("exported under DRY_RUN")

    def extract_logs(comment: str) -> None:
        raise AssertionError("extracted under DRY_RUN")

    monkeypatch.setattr(
        yubihsm_provision,
        "export_wrapped_key",
        export_wrapped_key,
    )
    wizard = yubihsm_provision.ProvisionWizard(
        {
            "DRY_RUN": "y",
            "KEY_DIR": str(tmp_path),
            "YUBIHSM_CONNECTOR": "http://127.0.0.1:1",
            "YUBIHSM_AUTHKEY": "0x0001",
            "YUBIHSM_PASSWORD": "password",
            "YUBIHSM_WRAP_KEY_ID": "0x0010",
        },
        cwd=tmp_path,
    )
    monkeypatch.setattr(wizard, "_extract_logs", extract_logs)

    wizard.export_wrapped_key("0x2000")

    assert "export-wrapped-key" in capsys.readouterr().err
    assert not (tmp_path / "0x2000-asymmetric-key.yhw").exists()


def test_wizard_load_keys_dry_run_restores_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def restore(*arguments: object, **options: object) -> None:
        raise AssertionError("restored under DRY_RUN")

    monkeypatch.setattr(
        yubihsm_provision,
        "restore_all_keys_and_certs",
        restore,
    )
    wizard = yubihsm_provision.ProvisionWizard(
        {"DRY_RUN": "y", "KEY_DIR": str(tmp_path)},
        cwd=tmp_path,
    )
    wizard.keymapper = Id2bKeymapper(load_metadata(SCRIPTS_DIR / "metadata.py"))
    wizard.audit_log_path = tmp_path / "audit.log"

    getattr(wizard, "_load_keys")()

    assert "restore_all_keys_and_certs" in capsys.readouterr().err
