#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import importlib.util
import itertools
import os
import shutil
import subprocess
import tarfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest
from conftest import (
    HSM_PROVISIONING_DIR,
    SCRIPTS_DIR,
    install_executable,
    prepare_ceremony_package,
    run,
    sha256,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from yubihsm.core import AuthSession, YubiHsm
from yubihsm.defs import ALGORITHM, AUDIT, CAPABILITY, COMMAND, OBJECT, OPTION
from yubihsm.exceptions import YubiHsmAuthenticationError, YubiHsmDeviceError
from yubihsm.objects import AsymmetricKey, WrapKey
from yubihsm.utils import password_to_key
from yubihsm_emulator import (
    Connector,
    EmulatedYubiHsm,
    serve_connector,
    stored_certificate,
)

SHAMIR_DIR = Path(
    os.environ.get(
        "CALYX_SHAMIR_DIR",
        Path.home() / ".cache/calyx-shamir/v0.0.1",
    ),
)
SHAMIR_COMBINE_SHA256 = (
    "e130d50ea83bdcfc24fa242a3d318077572cac842d8123a8353d01d70ec1909a"
)
WRAP_KEY_ID = 0x0010
SIGNING_AUTHKEY_ID = 0x0001
AUDIT_AUTHKEY_ID = 0x0002
ADMIN_AUTHKEY_ID = 0x00AD
PROMPT_TIMEOUT = 120
FAKE_CURL = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -L) shift ;;
    *) link=$1; shift ;;
  esac
done
cp "$DOWNLOADS/${link##*/}" "$out"
"""
FAKE_SUDO = """#!/bin/sh
printf '%s\\n' "$*" >> "$SUDO_LOG"
"""
INSTANT_SLEEP = """import time

time.sleep = lambda _seconds: None
"""


def _manifest_rows() -> list[list[str]]:
    lines = (HSM_PROVISIONING_DIR / "manifest.tsv").read_text().splitlines()
    return [line.split("\t") for line in lines[1:] if line]


def _pinned_sha256(name: str) -> str:
    for row in _manifest_rows():
        if row[0].endswith(f"/{name}"):
            return row[1]
    raise AssertionError(f"{name} is not in manifest.tsv")


def _require_tools() -> None:
    missing = [
        tool
        for tool in ("age", "ssh-keygen", "7z", "zip", "bash")
        if shutil.which(tool) is None
    ]
    split = SHAMIR_DIR / "calyx-shamir-split"
    combine = SHAMIR_DIR / "calyx-shamir-combine"
    if not split.is_file() or sha256(split) != _pinned_sha256(
        "calyx-shamir-split",
    ):
        missing.append(f"{split} matching manifest.tsv")
    if not combine.is_file() or sha256(combine) != SHAMIR_COMBINE_SHA256:
        missing.append(f"{combine} with sha256 {SHAMIR_COMBINE_SHA256}")
    if missing:
        pytest.skip(f"ceremony test tools are missing: {', '.join(missing)}")


class Interaction:
    """Answer a process's prompts as they appear on its output."""

    def __init__(
        self,
        args: list[str | Path],
        *,
        cwd: Path,
        env: dict[str, str],
    ) -> None:
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
            env=env,
        )
        self.output = ""
        self._seen = 0
        self._changed = threading.Condition()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        while chunk := self.process.stdout.read(1):
            with self._changed:
                self.output += chunk
                self._changed.notify_all()
        with self._changed:
            self._changed.notify_all()

    def answer(
        self,
        prompt: str,
        reply: str = "\n",
        *,
        then: Callable[[], None] | None = None,
    ) -> None:
        with self._changed:
            found = self._changed.wait_for(
                lambda: (
                    prompt in self.output[self._seen :]
                    or self.process.poll() is not None
                ),
                timeout=PROMPT_TIMEOUT,
            )
            index = self.output.find(prompt, self._seen)
            assert found and index >= 0, (
                f"no prompt {prompt!r} in:\n{self.output}"
            )
            self._seen = index + len(prompt)
        if then is not None:
            then()
        assert self.process.stdin is not None
        self.process.stdin.write(reply)
        self.process.stdin.flush()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()

    def finish(self) -> int:
        assert self.process.stdin is not None
        self.process.stdin.close()
        code = self.process.wait(timeout=PROMPT_TIMEOUT)
        self._reader.join(timeout=PROMPT_TIMEOUT)
        return code


@dataclass
class Recipients:
    directory: Path

    def private_key(self, number: int) -> Path:
        return self.directory / f"{number}"

    def decrypt(self, number: int, path: Path) -> bytes:
        return run(
            ["age", "-d", "-i", self.private_key(number), path],
            text=False,
        ).stdout


def _recipients(directory: Path) -> Recipients:
    directory.mkdir()
    for number in range(1, 6):
        run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"holder-{number}",
                "-f",
                directory / f"{number}",
            ],
        )
    return Recipients(directory)


def _downloads(directory: Path, manifest: Path) -> None:
    directory.mkdir()
    shutil.copy(
        SHAMIR_DIR / "calyx-shamir-split",
        directory / "calyx-shamir-split",
    )
    sdk = directory / "sdk"
    (sdk / "yubihsm2-sdk").mkdir(parents=True)
    for name in (
        "libyubihsm2_2.6.0_amd64.deb",
        "libyubihsm-dev_2.6.0_amd64.deb",
        "yubihsm-shell_2.6.0_amd64.deb",
    ):
        (sdk / "yubihsm2-sdk" / name).write_text(f"{name}\n")
    rows: list[str] = []
    for row in _manifest_rows():
        name, _, _, link = (row + ["", "", "", ""])[:4]
        if not link:
            rows.append("\t".join(row))
            continue
        download = directory / link.rsplit("/", 1)[1]
        if not download.exists():
            if name.startswith("sdk/"):
                with tarfile.open(download, "w:gz") as archive:
                    archive.add(sdk / "yubihsm2-sdk", "yubihsm2-sdk")
            else:
                download.write_text(f"{name}\n")
        rows.append(
            "\t".join(
                (name, sha256(download), str(download.stat().st_size), link),
            ),
        )
    manifest.write_text(
        "filename\tsha256sum\tfilesize\tlink\n" + "\n".join(rows) + "\n",
    )


@dataclass
class Ceremony:
    keep: Path
    recipients: Recipients
    package: Path
    primary: EmulatedYubiHsm
    secondary: EmulatedYubiHsm
    connector: Connector
    sudo_log: Path
    output: str
    start: Path
    path: str
    pythonpath: str
    unread_after_ceremony: dict[str, list[tuple[int, bytes, bytes]]]

    def signing_password(self) -> str:
        return self.recipients.decrypt(
            5,
            self.keep / "auth-keys" / "signing.key",
        ).decode()

    def auth_private_key(
        self,
        name: str,
        number: int,
    ) -> ec.EllipticCurvePrivateKey:
        pem = self.recipients.decrypt(
            number,
            self.keep / "auth-keys" / f"{name}.key",
        )
        key = serialization.load_pem_private_key(
            pem[pem.index(b"-----BEGIN PRIVATE KEY-----") :],
            None,
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return key

    def session(
        self,
        device: EmulatedYubiHsm,
        authkey: int,
        secret: str | ec.EllipticCurvePrivateKey,
    ) -> AuthSession:
        self.connector.plug(device)
        hsm = YubiHsm.connect(self.connector.url)
        if isinstance(secret, str):
            return hsm.create_session_derived(authkey, secret)
        return hsm.create_session_asymmetric(authkey, secret)

    def environment(self, keep: Path) -> dict[str, str]:
        return {
            "KEEP_PATH": str(keep),
            "YUBIHSM_CONNECTOR": self.connector.url,
            "PYTHONPATH": self.pythonpath,
        }


@pytest.fixture(scope="module")
def ceremony(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Ceremony]:
    _require_tools()
    root = tmp_path_factory.mktemp("ceremony")
    recipients = _recipients(root / "recipients")
    downloads = root / "downloads"
    manifest = root / "manifest.tsv"
    _downloads(downloads, manifest)
    fake_bin = root / "bin"
    fake_bin.mkdir()
    install_executable(fake_bin / "sudo", FAKE_SUDO)
    path = f"{fake_bin}:{os.environ['PATH']}"

    packaged = prepare_ceremony_package(
        root,
        FAKE_CURL,
        {"DOWNLOADS": str(downloads), "MANIFEST_FILE": str(manifest)},
    )
    assert packaged.returncode == 0, packaged.stdout + packaged.stderr
    usb = root / "usb"
    usb.mkdir()
    run(["7z", "x", root / "out" / "ceremony.zip"], cwd=usb)
    package = usb / "ceremony" / "scripts"
    for number in range(1, 6):
        shutil.copy(
            recipients.private_key(number).with_suffix(".pub"),
            package / "keys" / f"{number}.pub",
        )
    for name in ("restore_wrap_key.py", "restore_signing_keys.py"):
        shutil.copy2(HSM_PROVISIONING_DIR / name, package / name)

    primary = EmulatedYubiHsm(10000001)
    secondary = EmulatedYubiHsm(10000002)
    keep = root / "CalyxHSM"
    sudo_log = root / "sudo.log"
    instant_sleep = root / "instant-sleep"
    instant_sleep.mkdir()
    (instant_sleep / "sitecustomize.py").write_text(INSTANT_SLEEP)
    pythonpath = os.pathsep.join(
        filter(None, [str(instant_sleep), os.environ.get("PYTHONPATH")]),
    )
    with (
        serve_connector() as connector,
        Interaction(
            [usb / "ceremony" / "start.sh"],
            cwd=usb / "ceremony",
            env={
                **os.environ,
                "PATH": path,
                "PYTHONPATH": pythonpath,
                "SUDO_LOG": str(sudo_log),
                "KEEP_PATH": str(keep),
                "YUBIHSM_CONNECTOR": connector.url,
            },
        ) as interaction,
    ):
        interaction.answer("Press any key to install HSM packages.")
        interaction.answer("Press any key to start the YubiHSM connector.")
        interaction.answer(
            "Press any key when primary HSM is connected.",
            then=lambda: connector.plug(primary),
        )
        interaction.answer(
            "Press any key when secondary HSM is connected.",
            then=lambda: connector.plug(secondary),
        )
        code = interaction.finish()
        assert code == 0, interaction.output
        assert "Error in sitecustomize" not in interaction.output
        yield Ceremony(
            keep,
            recipients,
            package,
            primary,
            secondary,
            connector,
            sudo_log,
            interaction.output,
            usb / "ceremony" / "start.sh",
            path,
            pythonpath,
            {
                "primary": primary.unread_log(),
                "secondary": secondary.unread_log(),
            },
        )


def test_ceremony_installs_the_packaged_sdk_and_starts_the_connector(
    ceremony: Ceremony,
) -> None:
    dpkg, systemctl = ceremony.sudo_log.read_text().splitlines()

    installed = sorted(Path(word).name for word in dpkg.split()[2:])
    assert dpkg.startswith("dpkg -i ")
    assert "libyubihsm2_2.6.0_amd64.deb" in installed
    assert "yubihsm-shell_2.6.0_amd64.deb" in installed
    assert "libyubihsm-dev_2.6.0_amd64.deb" not in installed
    assert "python3-yubihsm_3.1.1-1_all.deb" in installed
    assert systemctl == "systemctl start yubihsm-connector"
    assert "Congratulations! Both HSMs provisioned." in ceremony.output


@pytest.mark.parametrize("device", ("primary", "secondary"))
def test_ceremony_resets_and_provisions_each_hsm(
    ceremony: Ceremony,
    device: str,
) -> None:
    hsm = getattr(ceremony, device)

    assert hsm.resets == 1
    assert hsm.force_audit == AUDIT.FIXED
    for command in (
        COMMAND.SET_OPTION,
        COMMAND.PUT_WRAP_KEY,
        COMMAND.PUT_AUTHENTICATION_KEY,
        COMMAND.DELETE_OBJECT,
        COMMAND.GENERATE_ASYMMETRIC_KEY,
        COMMAND.EXPORT_WRAPPED,
        COMMAND.IMPORT_WRAPPED,
        COMMAND.SIGN_PKCS1,
    ):
        assert hsm.command_audit[command] == AUDIT.FIXED, command
    assert sorted(
        key
        for key in hsm.objects
        if key[1] in (OBJECT.AUTHENTICATION_KEY, OBJECT.WRAP_KEY)
    ) == [
        (SIGNING_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY),
        (AUDIT_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY),
        (WRAP_KEY_ID, OBJECT.WRAP_KEY),
        (ADMIN_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY),
    ]
    wrap_key = hsm.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    assert wrap_key.algorithm == ALGORITHM.AES256_CCM_WRAP
    assert wrap_key.capabilities == (
        CAPABILITY.IMPORT_WRAPPED | CAPABILITY.EXPORT_WRAPPED
    )
    signing = hsm.get(SIGNING_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY)
    assert signing.label.rstrip(b"\0") == b"Signing auth key"

    with pytest.raises(YubiHsmAuthenticationError):
        ceremony.session(hsm, SIGNING_AUTHKEY_ID, "password")
    for authkey, secret in (
        (SIGNING_AUTHKEY_ID, ceremony.signing_password()),
        (ADMIN_AUTHKEY_ID, ceremony.auth_private_key("admin", 4)),
        (AUDIT_AUTHKEY_ID, ceremony.auth_private_key("audit", 3)),
    ):
        ceremony.session(hsm, authkey, secret).close()


def test_ceremony_puts_one_wrap_key_on_both_hsms(ceremony: Ceremony) -> None:
    primary = ceremony.primary.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    secondary = ceremony.secondary.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    assert primary is not None
    assert secondary is not None

    assert len(primary.data) == 32
    assert primary.data == secondary.data


def test_any_three_shards_restore_the_wrap_key(ceremony: Ceremony) -> None:
    stored_wrap_key = ceremony.primary.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    assert stored_wrap_key is not None
    wrap_key = stored_wrap_key.data
    shards = {
        number: ceremony.recipients.decrypt(
            number,
            ceremony.keep / "shards" / f"{number}.shard",
        ).decode()
        for number in range(1, 6)
    }

    for chosen in itertools.combinations(sorted(shards), 3):
        combined = run(
            [SHAMIR_DIR / "calyx-shamir-combine"],
            input="\n".join(shards[number] for number in chosen),
        ).stdout
        assert combined == wrap_key.hex(), chosen
    two = run(
        [SHAMIR_DIR / "calyx-shamir-combine"],
        input="\n".join((shards[1], shards[2])),
        check=False,
    )
    assert two.stdout != wrap_key.hex()


def test_each_secret_is_readable_only_by_its_holder(
    ceremony: Ceremony,
) -> None:
    holders = {
        ceremony.keep / "auth-keys" / "signing.key": 5,
        ceremony.keep / "auth-keys" / "admin.key": 4,
        ceremony.keep / "auth-keys" / "audit.key": 3,
        **{
            ceremony.keep / "shards" / f"{number}.shard": number
            for number in range(1, 6)
        },
    }

    for path, holder in holders.items():
        assert path.read_bytes().startswith(b"age-encryption.org/v1\n")
        for number in range(1, 6):
            decrypted = subprocess.run(
                ["age", "-d", "-i", ceremony.recipients.private_key(number)],
                input=path.read_bytes(),
                capture_output=True,
            )
            assert (decrypted.returncode == 0) == (number == holder), (
                path,
                number,
            )


@pytest.mark.parametrize("device", ("primary", "secondary"))
def test_ceremony_saves_each_hsms_identity_and_audit_log(
    ceremony: Ceremony,
    device: str,
) -> None:
    hsm = getattr(ceremony, device)
    name = f"YubiHSM2-{hsm.serial}"

    attestation = x509.load_pem_x509_certificate(
        (ceremony.keep / name / "attestation.pem").read_bytes(),
    )
    assert attestation == hsm.attestation_certificate
    public_key = serialization.load_pem_public_key(
        (ceremony.keep / name / "public_key.pem").read_bytes(),
    )
    assert public_key == hsm.device_key.public_key()
    (log,) = (ceremony.keep / "logs" / name).glob("*-provision.log")
    lines = log.read_text().splitlines()
    assert lines[0].endswith(
        " provisioning: 4f is for audit log options, the rest is key setup",
    )
    commands = [line.split()[2] for line in lines[1:]]
    assert commands.count("0x4f") > 40
    assert {"0x4c", "0x44", "0x58"} <= set(commands)
    assert ceremony.unread_after_ceremony[device] == []


def _generate_and_back_up(
    ceremony: Ceremony,
    key_dir: Path,
) -> dict[int, bytes]:
    session = ceremony.session(
        ceremony.primary,
        SIGNING_AUTHKEY_ID,
        ceremony.signing_password(),
    )
    wrap_key = WrapKey(session, WRAP_KEY_ID)
    key_dir.mkdir()
    keys: dict[int, bytes] = {}
    for key_id, label in ((0x1100, "core"), (0x3500, "apex_container")):
        key = AsymmetricKey.generate(
            session,
            key_id,
            label,
            1,
            CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            ALGORITHM.RSA_2048,
        )
        (key_dir / f"{key_id:#06x}-asymmetric-key.yhw").write_bytes(
            base64.b64encode(wrap_key.export_wrapped(key)),
        )
        (key_dir / f"{key_id:#06x}.attestation.pem").write_bytes(
            ceremony.primary.attest(key_id).public_bytes(
                serialization.Encoding.PEM,
            ),
        )
        stored = ceremony.primary.get(key_id, OBJECT.ASYMMETRIC_KEY)
        assert stored is not None
        keys[key_id] = stored.data
    session.close()
    return keys


def test_backup_hsm_restores_the_wrap_key_and_the_signing_keys(
    ceremony: Ceremony,
    tmp_path: Path,
) -> None:
    backup = EmulatedYubiHsm(10000003)
    work = tmp_path / "otatools-keys"
    work.mkdir()
    keys = _generate_and_back_up(ceremony, work / "keys")
    combined = run(
        [SHAMIR_DIR / "calyx-shamir-combine"],
        input="\n".join(
            ceremony.recipients.decrypt(
                number,
                ceremony.keep / "shards" / f"{number}.shard",
            ).decode()
            for number in (2, 4, 5)
        ),
    ).stdout
    keep = tmp_path / "CalyxBackupHSM"
    ceremony.connector.plug(backup)

    restored = run(
        [ceremony.package / "restore_wrap_key.py"],
        env=ceremony.environment(keep),
        input=combined + "\n",
        check=False,
    )
    assert restored.returncode == 0, restored.stdout + restored.stderr
    backup_wrap_key = backup.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    primary_wrap_key = ceremony.primary.get(WRAP_KEY_ID, OBJECT.WRAP_KEY)
    assert backup_wrap_key is not None
    assert primary_wrap_key is not None
    assert backup_wrap_key.data == primary_wrap_key.data

    admin_key = tmp_path / "admin.pem"
    admin_key.write_bytes(
        ceremony.recipients.decrypt(4, keep / "auth-keys" / "admin.key"),
    )
    outputs: list[str] = []
    for _ in range(2):
        ceremony.connector.plug(backup)
        imported = run(
            [ceremony.package / "restore_signing_keys.py", "-k", admin_key],
            cwd=work,
            env=ceremony.environment(keep),
            check=False,
        )
        assert imported.returncode == 0, imported.stdout + imported.stderr
        outputs.append(imported.stdout)
    assert "Key was already imported, skipping..." in outputs[-1]

    for key_id, private_key in keys.items():
        restored_key = backup.get(key_id, OBJECT.ASYMMETRIC_KEY)
        assert restored_key is not None
        assert restored_key.data == private_key
        certificate = backup.get(key_id, OBJECT.OPAQUE)
        assert certificate is not None
        expected = ceremony.primary.attest(key_id)
        assert stored_certificate(certificate).public_key() == (
            expected.public_key()
        )
        primary_key = ceremony.primary.get(key_id, OBJECT.ASYMMETRIC_KEY)
        assert primary_key is not None
        label = primary_key.label
        assert certificate.label == label


def test_restored_signing_key_signs_on_the_backup_hsm(
    ceremony: Ceremony,
) -> None:
    primary_session = ceremony.session(
        ceremony.primary,
        SIGNING_AUTHKEY_ID,
        ceremony.signing_password(),
    )
    key = AsymmetricKey.generate(
        primary_session,
        0x2300,
        "avb",
        1,
        CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        ALGORITHM.RSA_2048,
    )
    wrapped = WrapKey(primary_session, WRAP_KEY_ID).export_wrapped(key)
    primary_session.close()
    stored = ceremony.primary.get(0x2300, OBJECT.ASYMMETRIC_KEY)
    assert stored is not None
    public_key = serialization.load_der_private_key(
        stored.data,
        None,
    ).public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)

    session = ceremony.session(
        ceremony.secondary,
        SIGNING_AUTHKEY_ID,
        ceremony.signing_password(),
    )
    restored = WrapKey(session, WRAP_KEY_ID).import_wrapped(wrapped)
    assert isinstance(restored, AsymmetricKey)
    signature = restored.sign_pkcs1v1_5(b"release")
    session.close()

    public_key.verify(
        signature,
        b"release",
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_signing_auth_key_cannot_delete_auth_keys_or_reset_the_hsm(
    ceremony: Ceremony,
) -> None:
    session = ceremony.session(
        ceremony.secondary,
        SIGNING_AUTHKEY_ID,
        ceremony.signing_password(),
    )
    try:
        with pytest.raises(YubiHsmDeviceError):
            session.get_object(
                AUDIT_AUTHKEY_ID,
                OBJECT.AUTHENTICATION_KEY,
            ).delete()
        with pytest.raises(YubiHsmDeviceError):
            session.reset_device()
    finally:
        if session.sid is not None:
            session.close()


def test_audit_script_appends_new_entries_and_clears_them(
    ceremony: Ceremony,
    tmp_path: Path,
) -> None:
    hsm = EmulatedYubiHsm(10000004)
    ceremony.connector.plug(hsm)
    session = YubiHsm.connect(ceremony.connector.url).create_session_derived(
        1,
        "password",
    )
    session.put_option(
        OPTION.COMMAND_AUDIT,
        bytes([COMMAND.GENERATE_ASYMMETRIC_KEY, AUDIT.ON]),
    )
    AsymmetricKey.generate(
        session,
        0x1100,
        "core",
        1,
        CAPABILITY.SIGN_PKCS,
        ALGORITHM.RSA_2048,
    )
    session.close()
    log_file = tmp_path / "logs" / "audit.log"
    environment = {"YUBIHSM_CONNECTOR": ceremony.connector.url}

    first = run(
        [
            ceremony.package / "audit.py",
            "--log-file",
            log_file,
            "--comment",
            "keygen\nrun",
        ],
        env=environment,
    )
    second = run(
        [ceremony.package / "audit.py", "--log-file", log_file],
        env=environment,
    )

    lines = log_file.read_text().splitlines()
    assert lines[0].endswith(" keygenrun")
    assert [line.split()[2] for line in lines[1:]] == ["0x00", "0x46"]
    assert hsm.unread_log() == []
    assert first.stdout == ""
    assert second.stdout == "No logs to extract and no comment to write.\n"


def test_audit_script_syncs_the_log_before_acknowledging_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "audit_under_test",
        SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.audit.logs.py",
    )
    assert spec is not None and spec.loader is not None
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    events: list[str] = []
    fsync = os.fsync

    def record_fsync(fd: int) -> None:
        events.append("fsync")
        fsync(fd)

    monkeypatch.setattr(audit.os, "fsync", record_fsync)
    entry = SimpleNamespace(
        number=7,
        command=COMMAND.SIGN_PKCS1,
        length=2,
        session_key=1,
        target_key=0x1100,
        second_key=0,
        result=0x80 | COMMAND.SIGN_PKCS1,
        tick=5,
        digest=bytes(16),
    )

    def acknowledge(number: int) -> None:
        events.append(f"acknowledge {number}")

    session = SimpleNamespace(
        get_log_entries=lambda: SimpleNamespace(entries=[entry]),
        set_log_index=acknowledge,
    )
    log_file = tmp_path / "logs" / "audit.log"

    audit.extract_and_save_logs(session, str(log_file), "restore")

    assert events == ["fsync", "acknowledge 7"]
    assert log_file.read_text().splitlines()[1].split()[0] == "7"


def test_ceremony_fails_on_an_hsm_that_is_not_factory_reset(
    ceremony: Ceremony,
    tmp_path: Path,
) -> None:
    hsm = EmulatedYubiHsm(10000005)
    enc, mac = password_to_key("in use")
    signing_authkey = hsm.get(SIGNING_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY)
    assert signing_authkey is not None
    signing_authkey.data = enc + mac
    before = dict(hsm.objects)

    with Interaction(
        [ceremony.start],
        cwd=ceremony.start.parent,
        env={
            **os.environ,
            **ceremony.environment(tmp_path / "keep"),
            "PATH": ceremony.path,
            "SUDO_LOG": str(tmp_path / "sudo.log"),
        },
    ) as interaction:
        interaction.answer("Press any key to install HSM packages.")
        interaction.answer("Press any key to start the YubiHSM connector.")
        interaction.answer(
            "Press any key when primary HSM is connected.",
            then=lambda: ceremony.connector.plug(hsm),
        )
        code = interaction.finish()

    assert code == 1
    assert "ERROR: The HSM does not seem to be factory reset." in (
        interaction.output
    )
    assert hsm.objects == before
    assert hsm.resets == 0
