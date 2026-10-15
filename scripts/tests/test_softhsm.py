#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import (
    APKSIGNER_SIGNING_HELPER,
    FIXTURES_DIR,
    KEYGEN_METADATA,
    PAYLOAD_SIGNER,
    PKCS11_DIR,
    PKCS11_ENGINE,
    SIGNING_HELPER,
    SOFTHSM_MODULE,
    SOFTHSM_SO_PIN,
    YUBIHSM_INTERCEPTOR,
    aosp_jar_command,
    require_softhsm,
    run,
    softhsm_environment,
)
from software_rsa import avb_input

TOKEN_LABEL = "androsign-test"
SOFTHSM_KEYGEN_FIXTURE = FIXTURES_DIR / "softhsm-keygen.json"


def softhsm_token(
    directory: Path,
    *,
    initialize: bool = True,
) -> dict[str, str]:
    return {
        **softhsm_environment(directory, TOKEN_LABEL, initialize=initialize),
        "SOFTHSM_TOKEN_DIR": str(directory / "tokens"),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": str(PKCS11_ENGINE),
        "PKCS11_SO_PIN": SOFTHSM_SO_PIN,
        "PKCS11_TESTING": "y",
    }


def keygen_environment(
    token: dict[str, str],
    directory: Path,
    avbtool: Path,
) -> dict[str, str]:
    devices = directory / "devices"
    devices.write_text("devices=(bramble)\n")
    return {
        **token,
        "METADATA_FILE": str(KEYGEN_METADATA),
        "DEVICES_FILE": str(devices),
        "AVBTOOL_BIN": str(avbtool),
        "RSA_KEY_SIZE": "2048",
        "CERT_EXPIRY_DAYS": "1",
        "YUBIHSM_PASSWORD": "unused-by-softhsm",
    }


def run_keygen(
    output: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return run(
        [PKCS11_DIR / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )


def token_inventory(environment: dict[str, str]) -> list[list[str]]:
    listing = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--list-objects",
        ],
        env=environment,
    )
    inventory: list[list[str]] = []
    kind = ""
    for line in listing.stdout.splitlines():
        if not line.startswith(" "):
            kind = line.split(";")[0].strip()
        elif line.strip().startswith("ID:"):
            key_id = line.split(":", 1)[1].strip()
            if "(0x" in key_id:
                key_id = key_id.split("(0x", 1)[1].rstrip(")").replace(":", "")
            inventory.append([kind, key_id])
    return sorted(inventory)


@pytest.fixture
def softhsm_env(tmp_path: Path) -> dict[str, str]:
    require_softhsm(engine=True)
    return softhsm_token(tmp_path)


@pytest.fixture
def generated_softhsm_keys(
    tmp_path: Path,
    softhsm_env: dict[str, str],
    avbtool: Path,
) -> tuple[Path, dict[str, str]]:
    output = tmp_path / "keys"
    environment = keygen_environment(softhsm_env, tmp_path, avbtool)
    generated = run_keygen(output, environment)
    assert generated.returncode == 0, generated.stderr
    return output, environment


def signing_environment(
    base_environment: dict[str, str],
    key_dir: str | Path = "keys/",
) -> dict[str, str]:
    return {
        **base_environment,
        "KEY_DIR": f"{str(key_dir).removesuffix('/')}/",
    }


def public_key_named(output: Path, directory: Path, key_id: str) -> Path:
    """Copy key 0x2000's public key to a file that names key_id."""
    named = directory / f"0x{key_id}.pem"
    shutil.copyfile(output / "0x2000.pem", named)
    return named


@pytest.mark.aosp
def test_payload_signer_rejects_mismatched_public_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, tmp_path)
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"
    signature.write_bytes(b"existing-signature")

    signed = run(
        [
            PAYLOAD_SIGNER,
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            public_key_named(output, tmp_path, "1300"),
        ],
        env=environment,
        check=False,
    )

    assert signed.returncode != 0
    assert "does not match the selected PKCS#11 key" in signed.stderr
    assert signature.read_bytes() == b"existing-signature"


@pytest.mark.aosp
def test_softhsm_signing_rejects_missing_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, tmp_path)
    signed = run(
        [
            SIGNING_HELPER,
            "SHA256_RSA2048",
            public_key_named(output, tmp_path, "ffff"),
        ],
        env=environment,
        input=avb_input(bytes(range(32))),
        check=False,
        text=False,
    )

    assert signed.returncode != 0
    assert b"not found" in signed.stderr.lower()
    assert b"Traceback" not in signed.stderr


@pytest.mark.aosp
def test_keygen_repairs_missing_certificate(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, environment = generated_softhsm_keys
    deleted = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--delete-object",
            "--type",
            "cert",
            "--id",
            "1100",
        ],
        env=environment,
        check=False,
    )
    assert deleted.returncode == 0, deleted.stderr
    (output / "0x1100.x509.pem").unlink()

    rerun = run_keygen(output, environment)
    assert rerun.returncode == 0, rerun.stderr
    assert "generating missing cert" in rerun.stdout
    assert "No keys generated during the process." in rerun.stdout
    assert (output / "0x1100.x509.pem").is_file()


@pytest.mark.aosp
def test_avbtool_signs_with_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    avbtool: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, output)
    image = tmp_path / "test.img"
    image.write_bytes(bytes(range(256)) * 16)

    signed = run(
        [
            avbtool,
            "add_hash_footer",
            "--image",
            image,
            "--partition_name",
            "test",
            "--partition_size",
            "131072",
            "--key",
            output / "0x2000.pem",
            "--algorithm",
            "SHA256_RSA2048",
            "--signing_helper",
            SIGNING_HELPER,
        ],
        env=environment,
        check=False,
    )
    assert signed.returncode == 0, signed.stderr
    verified = run(
        [
            avbtool,
            "verify_image",
            "--image",
            image,
            "--key",
            output / "0x2000.pem",
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr


@pytest.mark.aosp
def test_avb_helper_rejects_mismatched_public_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    avbtool: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, tmp_path)
    image = tmp_path / "mismatched.img"
    image.write_bytes(bytes(range(256)) * 16)

    signed = run(
        [
            avbtool,
            "add_hash_footer",
            "--image",
            image,
            "--partition_name",
            "test",
            "--partition_size",
            "131072",
            "--key",
            public_key_named(output, tmp_path, "1300"),
            "--algorithm",
            "SHA256_RSA2048",
            "--signing_helper",
            SIGNING_HELPER,
        ],
        env=environment,
        check=False,
    )

    assert signed.returncode != 0
    assert "does not match the selected PKCS#11 key" in signed.stderr


@pytest.mark.aosp
def test_keygen_initializes_empty_softhsm_store(
    tmp_path: Path,
    avbtool: Path,
) -> None:
    require_softhsm(engine=True)
    output = tmp_path / "initialized-keys"
    environment = {
        name: value
        for name, value in keygen_environment(
            softhsm_token(tmp_path / "empty", initialize=False),
            tmp_path,
            avbtool,
        ).items()
        if name not in ("PKCS11_PIN", "PKCS11_SO_PIN")
    }

    generated = run_keygen(output, environment)
    assert generated.returncode == 0, generated.stderr
    assert "PKCS11_PIN not specified. Using 123456." in generated.stderr
    assert "PKCS11_SO_PIN not specified. Using 12345678." in generated.stderr
    slots = run(["softhsm2-util", "--show-slots"], env=environment, check=False)
    assert slots.returncode == 0, slots.stderr
    assert f"Label:            {TOKEN_LABEL}" in slots.stdout
    assert (output / "0x2000.x509.pem").is_file()


def _certificate_sha256(certificate: Path) -> str:
    fingerprint = run(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-fingerprint",
            "-sha256",
        ],
    )
    return fingerprint.stdout.split("=", 1)[1].strip().replace(":", "").lower()


SIGN_APK = """
import sys
import common

common.OPTIONS.search_path = sys.argv[1]
common.OPTIONS.java_path = sys.argv[2]
common.OPTIONS.pkcs11_config = sys.argv[3]
common.OPTIONS.apksigner_kms_type = "calyx"
common.SignFile(sys.argv[4], sys.argv[5], "keys/0x1100", None, min_api_level=30)
"""


@pytest.mark.aosp
def test_releasetools_signs_apks_through_the_calyx_kms_provider(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    apksigner = aosp_jar_command(aosp_top, "apksigner.jar")
    app = aosp_top / "build/make/tools/releasetools/testdata/TestApp.apk"
    releasetools = aosp_top / "build/make/tools/releasetools"

    signed = run(
        [
            "python3",
            "-c",
            SIGN_APK,
            aosp_top / "out" / "host" / "linux-x86",
            apksigner[0],
            "/dev/null",
            app,
            "signed.apk",
        ],
        cwd=tmp_path,
        env={
            **base_environment,
            "KEY_DIR": "keys/",
            "CALYX_APKSIGNER_SIGNING_HELPER": str(
                APKSIGNER_SIGNING_HELPER,
            ),
            "PYTHONPATH": str(releasetools),
        },
        check=False,
    )

    assert signed.returncode == 0, signed.stderr
    verified = run(
        [*apksigner, "verify", "--print-certs", tmp_path / "signed.apk"],
    )
    assert (
        f"certificate SHA-256 digest: "
        f"{_certificate_sha256(output / '0x1100.x509.pem')}"
    ) in verified.stdout


SIGN_APK_TWICE = """
import os
import sys
import common

common.OPTIONS.search_path = sys.argv[1]
common.OPTIONS.java_path = sys.argv[2]
common.OPTIONS.pkcs11_config = sys.argv[3]
common.OPTIONS.apksigner_kms_type = "calyx"
common.OPTIONS.signing_command_interceptor = sys.argv[4]
key = "keys/0x1100"
common.SignFile(sys.argv[5], "signed.apk", key, None, min_api_level=30)
os.environ["CALYX_APKSIGNER_SIGNING_HELPER"] = "false"
common.SignFile(sys.argv[5], "cached.apk", key, None, min_api_level=30)
"""


@pytest.mark.aosp
def test_releasetools_reuses_a_cached_kms_signature(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    apksigner = aosp_jar_command(aosp_top, "apksigner.jar")
    app = aosp_top / "build/make/tools/releasetools/testdata/TestApp.apk"
    releasetools = aosp_top / "build/make/tools/releasetools"
    cache = tmp_path / "cache"
    cache.mkdir()

    signed = run(
        [
            "python3",
            "-c",
            SIGN_APK_TWICE,
            aosp_top / "out" / "host" / "linux-x86",
            "java",
            "/dev/null",
            YUBIHSM_INTERCEPTOR,
            app,
        ],
        cwd=tmp_path,
        env={
            **base_environment,
            "KEY_DIR": "keys/",
            "CALYX_APKSIGNER_SIGNING_HELPER": str(
                APKSIGNER_SIGNING_HELPER,
            ),
            "PYTHONPATH": str(releasetools),
            "PATH": os.pathsep.join(
                (str(Path(apksigner[0]).parent), os.environ["PATH"]),
            ),
            "YUBIHSM_SIGNING_CACHE": str(cache),
            "YUBIHSM_LOCKFILE": "",
            "DRY_RUN": "y",
        },
        check=False,
    )

    assert signed.returncode == 0, signed.stderr
    assert len(list(cache.iterdir())) == 1
    cached = tmp_path / "cached.apk"
    assert cached.read_bytes() == (tmp_path / "signed.apk").read_bytes()
    verified = run([*apksigner, "verify", "--print-certs", cached])
    assert (
        f"certificate SHA-256 digest: "
        f"{_certificate_sha256(output / '0x1100.x509.pem')}"
    ) in verified.stdout


SIGN_WHOLE_FILE = """
import sys
import common

common.OPTIONS.search_path = sys.argv[1]
common.OPTIONS.java_path = sys.argv[2]
common.OPTIONS.pkcs11_config = sys.argv[3]
common.OPTIONS.signapk_external_signer = sys.argv[4]
common.SignFile(sys.argv[5], sys.argv[6], "keys/0x2000", None, whole_file=True)
"""


@pytest.mark.aosp
def test_releasetools_signs_packages_through_the_external_signer(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
) -> None:
    _, base_environment = generated_softhsm_keys
    java, *_ = aosp_jar_command(aosp_top, "signapk.jar")
    package = aosp_top / "build/make/tools/releasetools/testdata/TestApp.apk"
    releasetools = aosp_top / "build/make/tools/releasetools"

    signed = run(
        [
            "python3",
            "-c",
            SIGN_WHOLE_FILE,
            aosp_top / "out" / "host" / "linux-x86",
            java,
            "/dev/null",
            PAYLOAD_SIGNER,
            package,
            "signed.zip",
        ],
        cwd=tmp_path,
        env={
            **signing_environment(base_environment),
            "PYTHONPATH": str(releasetools),
        },
        check=False,
    )

    assert signed.returncode == 0, signed.stderr
    verified = run(
        [
            "python3",
            "-c",
            "import sys; import check_ota_package_signature as check; "
            "check.VerifyPackage(sys.argv[1], sys.argv[2])",
            tmp_path / "keys" / "0x2000.x509.pem",
            tmp_path / "signed.zip",
        ],
        env={"PYTHONPATH": str(releasetools)},
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert "Whole package signature VERIFIED" in verified.stdout


@pytest.mark.aosp
def test_softhsm_keygen_fills_the_token(
    tmp_path: Path,
    softhsm_env: dict[str, str],
    avbtool: Path,
) -> None:
    environment = keygen_environment(softhsm_env, tmp_path, avbtool)
    output = tmp_path / "keys"

    generated = run_keygen(output, environment)

    assert generated.returncode == 0, generated.stderr
    outcome = {
        "token": token_inventory(environment),
        "files": sorted(path.name for path in output.iterdir()),
        "summary": [
            line
            for line in generated.stdout.splitlines()
            if line.startswith(("#", "Key generation", "No "))
        ],
    }
    expected = json.loads(SOFTHSM_KEYGEN_FIXTURE.read_text())
    assert outcome == expected
    signature_algorithm = run(
        [
            "openssl",
            "x509",
            "-noout",
            "-text",
            "-in",
            str(output / "0x2000.x509.pem"),
        ],
    )
    assert "sha256WithRSAEncryption" in signature_algorithm.stdout

    rerun = run_keygen(output, environment)
    assert rerun.returncode == 0, rerun.stderr
    assert "No keys generated during the process." in rerun.stdout
    assert "No certs generated during the process." in rerun.stdout
    assert token_inventory(environment) == expected["token"]
