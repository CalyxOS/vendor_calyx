#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

import pytest
from conftest import (
    KEYGEN_METADATA,
    SCRIPTS_DIR,
    YUBIHSM_SDK,
    install_executable,
    run,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from signing.keymap import Id2bKeymapper
from signing.metadata import load_metadata
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import Connector, stored_certificate

KEYGEN_SH = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.keygen.sh"
KEYGEN_FIXTURE = Path(__file__).parent / "fixtures" / "yubihsm-keygen.json"


def _keygen_tree(
    root: Path,
    yubihsm: Connector,
    avbtool: Path,
) -> dict[str, str]:
    root.mkdir(parents=True)
    (root / "devices").write_text("devices=(bramble)\n")
    keymap = Id2bKeymapper(load_metadata(KEYGEN_METADATA)).to_tsv(
        ("bramble",),
    )
    (root / "keymap.tsv").write_text(keymap)
    logs = root / "logs"
    logs.mkdir()
    install_executable(
        logs / "upload.py",
        f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{root}/uploads"\n',
    )
    (root / "tmp").mkdir()
    yubihsm.device.put_wrap_key(0x0010)
    return {
        "PYTHONPATH": os.pathsep.join([str(SCRIPTS_DIR), YUBIHSM_SDK]),
        "PATH": os.environ["PATH"],
        "HOME": str(root),
        "TMPDIR": str(root / "tmp"),
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "PKCS11_MODULE": "/dev/null",
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
        "METADATA_FILE": str(KEYGEN_METADATA),
        "DEVICES_FILE": str(root / "devices"),
        "KEYMAP_FILE": str(root / "keymap.tsv"),
        "AVBTOOL_BIN": str(avbtool),
        "UNIQUE_KEY_OUT_DIR": str(root / "keys" / "unique"),
    }


def _objects(yubihsm: Connector, object_type: OBJECT) -> list[str]:
    return [
        f"{obj.object_id:#06x} {obj.algorithm.name}"
        for (_, kind), obj in sorted(yubihsm.device.objects.items())
        if kind == object_type
    ]


def _normalize(text: str, root: Path, yubihsm: Connector) -> str:
    text = re.sub(r"\d{4}-\d\d-\d\d_[\d-]+", "<date>", text)
    return text.replace(str(root), "<root>").replace(yubihsm.url, "<connector>")


def _tree(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _assert_files_match_the_device(root: Path, yubihsm: Connector) -> None:
    device = yubihsm.device
    keymap = (root / "keymap.tsv").read_text()
    for path in sorted((root / "keys").rglob("*")):
        name = path.name
        if name == "hsm_info.txt":
            info = path.read_text()
            assert info.startswith("Version number:\t\t2.4.0\n")
            assert f"Serial number:\t\t{device.serial}\n" in info
            assert info.endswith(f"Part number:\t\t{device.part_number}\n")
        elif name == "keymap.tsv":
            assert path.read_text() == keymap
        elif name.endswith("-asymmetric-key.yhw"):
            key_id = int(name.split("-")[0], 16)
            assert device.unwrap(
                base64.b64decode(path.read_bytes()),
                0x0010,
            ) == (key_id, OBJECT.ASYMMETRIC_KEY)
        elif name.endswith(".x509.pem"):
            key_id = int(name.split(".")[0], 16)
            stored = device.get(key_id, OBJECT.OPAQUE)
            assert stored is not None
            assert x509.load_pem_x509_certificate(
                path.read_bytes(),
            ) == stored_certificate(stored)
        elif (
            name.startswith("0x")
            and name.count(".") == 1
            and (name.endswith(".pem"))
        ):
            key = device.get(int(name.split(".")[0], 16), OBJECT.ASYMMETRIC_KEY)
            assert key is not None
            private = serialization.load_der_private_key(
                key.data,
                None,
                unsafe_skip_rsa_key_validation=True,
            )
            public = serialization.load_pem_public_key(path.read_bytes())
            expected = private.public_key()
            assert isinstance(
                public,
                (rsa.RSAPublicKey, ec.EllipticCurvePublicKey),
            )
            assert isinstance(
                expected,
                (rsa.RSAPublicKey, ec.EllipticCurvePublicKey),
            )
            assert public.public_numbers() == expected.public_numbers()


def _audit_comments(root: Path, yubihsm: Connector) -> list[str]:
    (log,) = (root / "logs").rglob("*-keygen.log")
    return [
        _normalize(re.sub(r"^# \S+ \S+ ", "# ", line), root, yubihsm)
        for line in log.read_text().splitlines()
        if line.startswith("#")
    ]


@pytest.mark.aosp
def test_yubihsm_keygen_generates_every_key(
    tmp_path: Path,
    aosp_top: Path,
    yubihsm: Connector,
) -> None:
    avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"
    root = tmp_path / "tree"
    environment = _keygen_tree(root, yubihsm, avbtool)

    result = run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Key generation finished successfully." in result.stdout
    outcome = {
        "keys": sorted(_tree(root / "keys")),
        "generated": _objects(yubihsm, OBJECT.ASYMMETRIC_KEY),
        "imported": _objects(yubihsm, OBJECT.OPAQUE),
        "audit": _audit_comments(root, yubihsm),
        "uploads": _normalize((root / "uploads").read_text(), root, yubihsm),
    }
    assert outcome == json.loads(KEYGEN_FIXTURE.read_text())
    _assert_files_match_the_device(root, yubihsm)


@pytest.mark.aosp
def test_yubihsm_keygen_skips_backed_up_keys(
    tmp_path: Path,
    aosp_top: Path,
    yubihsm: Connector,
) -> None:
    avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"
    root = tmp_path / "tree"
    environment = _keygen_tree(root, yubihsm, avbtool)
    first = run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)
    backup = next(root.rglob("*-asymmetric-key.yhw"))
    evicted = int(backup.name.split("-")[0], 16)
    del yubihsm.device.objects[(evicted, OBJECT.ASYMMETRIC_KEY)]
    generated = _objects(yubihsm, OBJECT.ASYMMETRIC_KEY)
    commands = len(yubihsm.device.history)

    rerun = run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)

    assert first.returncode == 0
    assert "No keys generated during the process." in rerun.stdout
    assert "No certs generated during the process." in rerun.stdout
    assert _objects(yubihsm, OBJECT.ASYMMETRIC_KEY) == generated
    assert COMMAND.GENERATE_ASYMMETRIC_KEY not in [
        command for _, command, _ in yubihsm.device.history[commands:]
    ]


def test_python_yubihsm_keygen_refuses_generate_using_pkcs11_first(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    root = tmp_path / "tree"
    environment = {
        **_keygen_tree(root, yubihsm, Path("/bin/true")),
        "GENERATE_USING_PKCS11": "y",
    }

    result = run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env=environment,
        check=False,
    )

    assert result.returncode != 0
    assert "GENERATE_USING_PKCS11=y is not supported." in result.stderr
    assert _objects(yubihsm, OBJECT.ASYMMETRIC_KEY) == []


@pytest.mark.aosp
def test_yubihsm_keygen_sizes_only_avb_and_apex_payload_keys(
    tmp_path: Path,
    aosp_top: Path,
    yubihsm: Connector,
) -> None:
    avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"
    root = tmp_path / "tree"
    environment = {
        **_keygen_tree(root, yubihsm, avbtool),
        "RSA_KEY_SIZE": "2048",
    }

    result = run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert _objects(yubihsm, OBJECT.ASYMMETRIC_KEY) == [
        "0x1100 RSA_4096",
        "0x1200 RSA_4096",
        "0x1300 RSA_2048",
        "0x2000 RSA_2048",
    ]


def test_yubihsm_keygen_previews_its_device_writes_under_dry_run(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    root = tmp_path / "tree"
    environment = {
        **_keygen_tree(root, yubihsm, Path("/bin/true")),
        "DRY_RUN": "y",
    }
    objects = dict(yubihsm.device.objects)

    result = run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert yubihsm.device.objects == objects
    assert not {
        COMMAND.GENERATE_ASYMMETRIC_KEY,
        COMMAND.EXPORT_WRAPPED,
        COMMAND.SIGN_ATTESTATION_CERTIFICATE,
        COMMAND.PUT_OPAQUE,
        COMMAND.DELETE_OBJECT,
    } & {command for _, command, _ in yubihsm.device.history}
    assert _tree(root / "keys") == {}
    generated = [
        line.split("--key-id ")[1].split()[0]
        for line in result.stderr.splitlines()
        if "generate-asymmetric-key" in line
    ]
    assert generated == ["0x2000", "0x1300", "0x1100", "0x1200"]


FAKE_AVBTOOL = """#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
printf 'avb public key' > "$output"
"""


def test_yubihsm_keygen_refuses_a_certificate_without_its_key(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    root = tmp_path / "tree"
    avbtool = install_executable(tmp_path / "avbtool", FAKE_AVBTOOL)
    environment = _keygen_tree(root, yubihsm, avbtool)
    run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)
    backup = next((root / "keys").glob("*-asymmetric-key.yhw"))
    key_id = backup.name.removesuffix("-asymmetric-key.yhw")
    backup.unlink()
    del yubihsm.device.objects[(int(key_id, 16), OBJECT.ASYMMETRIC_KEY)]
    generated = _objects(yubihsm, OBJECT.ASYMMETRIC_KEY)

    rerun = run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env=environment,
        check=False,
    )

    assert rerun.returncode == 1
    assert f"{key_id}" in rerun.stderr
    assert "certificate exists without its key" in rerun.stderr
    assert _objects(yubihsm, OBJECT.ASYMMETRIC_KEY) == generated


def test_yubihsm_keygen_derives_the_public_keys_a_failed_run_left_out(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    root = tmp_path / "tree"
    avbtool = install_executable(tmp_path / "avbtool", FAKE_AVBTOOL)
    environment = {
        **_keygen_tree(root, yubihsm, avbtool),
        "HSM_KEY_OUT_DIR": str(root / "hsm"),
    }
    run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)
    public_key = next((root / "keys").glob("*.avbpubkey"))
    hsm_copy = root / "hsm" / public_key.name
    public_key.unlink()
    hsm_copy.unlink()

    rerun = run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)

    assert public_key.read_text() == "avb public key"
    assert hsm_copy.read_text() == "avb public key"
    assert "already exists" not in rerun.stderr


def test_yubihsm_keygen_derives_no_public_key_in_a_dry_run(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    root = tmp_path / "tree"
    avbtool = install_executable(tmp_path / "avbtool", FAKE_AVBTOOL)
    environment = _keygen_tree(root, yubihsm, avbtool)
    run([KEYGEN_SH, root / "keys"], cwd=root, env=environment)
    public_key = next((root / "keys").glob("*.avbpubkey"))
    public_key.unlink()

    run(
        [KEYGEN_SH, root / "keys"],
        cwd=root,
        env={**environment, "DRY_RUN": "y"},
    )

    assert not public_key.exists()
