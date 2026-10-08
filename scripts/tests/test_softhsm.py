#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import (
    PKCS11_ENGINE,
    SCRIPTS_DIR,
    SOFTHSM_MODULE,
    SOFTHSM_SO_PIN,
    aosp_jar_command,
    require_softhsm,
    run,
    softhsm_environment,
)

TOKEN_LABEL = "androsign-test"
SOFTHSM_KEYGEN_FIXTURE = (
    Path(__file__).parent / "fixtures" / "softhsm-keygen.json"
)


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


def token_inventory(environment: dict[str, str]) -> list[tuple[str, str]]:
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
    inventory: list[tuple[str, str]] = []
    kind = ""
    for line in listing.stdout.splitlines():
        if not line.startswith(" "):
            kind = line.split(";")[0].strip()
        elif line.strip().startswith("ID:"):
            key_id = line.split(":", 1)[1].strip()
            if "(0x" in key_id:
                key_id = key_id.split("(0x", 1)[1].rstrip(")").replace(":", "")
            inventory.append((kind, key_id))
    return sorted(inventory)


@pytest.fixture
def softhsm_env(tmp_path: Path) -> dict[str, str]:
    require_softhsm(engine=True)
    return softhsm_token(tmp_path)


@pytest.fixture
def minimal_keygen_metadata(tmp_path: Path) -> tuple[Path, Path]:
    metadata = tmp_path / "metadata.py"
    metadata.write_text(
        """KEYS_AVB = ("vbmeta",)
KEYS_OTHER = ("ota",)
KEYS_CORE = ("build/make/target/product/security/testkey",)
KEYS_APEX = ("com.android.test",)
KEYS_APEX_APK = ()
KEYS_APP = ()
KEYS_REPO = ()
KEY_TYPES = ("avb", "apex_payload", "other", "core", "apex_container")
MAPPED_KEY_TYPES = ("core",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "apex_payload": "keys_apex",
    "other": "keys_other",
    "core": "keys_core",
    "apex_container": "keys_apex",
}
""",
    )
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    return metadata, devices


@pytest.fixture
def generated_softhsm_keys(
    tmp_path: Path,
    softhsm_env: dict[str, str],
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> tuple[Path, dict[str, str]]:
    metadata, devices = minimal_keygen_metadata
    output = tmp_path / "keys"
    environment = {
        **softhsm_env,
        "METADATA_FILE": str(metadata),
        "DEVICES_FILE": str(devices),
        "AVBTOOL_BIN": str(
            aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
        ),
        "RSA_KEY_SIZE": "2048",
        "CERT_EXPIRY_DAYS": "1",
        "YUBIHSM_PASSWORD": "unused-by-softhsm",
    }
    generated = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    return output, environment


@pytest.mark.aosp
def test_softhsm_keygen_creates_expected_objects_and_exports(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, environment = generated_softhsm_keys
    objects = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            f"env:{'PKCS11_PIN'}",
            "--list-objects",
        ],
        env=environment,
    )
    for key_id in ("2000", "1300", "1100", "1200"):
        rendered_id = f"(0x{key_id[:2]}:{key_id[2:]})"
        assert objects.stdout.count(rendered_id) == 3

    for key_name in ("0x2000", "0x1300", "0x1100", "0x1200"):
        assert (output / f"{key_name}.x509.pem").is_file()
    for key_name in ("0x2000", "0x1300"):
        assert (output / f"{key_name}.pem").is_file()
        assert (output / f"{key_name}.avbpubkey").is_file()


@pytest.mark.aosp
def test_softhsm_keygen_uses_the_testing_pins(
    tmp_path: Path,
    softhsm_env: dict[str, str],
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> None:
    metadata, devices = minimal_keygen_metadata
    environment = {
        name: value
        for name, value in softhsm_env.items()
        if name not in ("PKCS11_PIN", "PKCS11_SO_PIN")
    }
    generated = run(
        [
            SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh",
            tmp_path / "keys",
        ],
        env={
            **environment,
            "METADATA_FILE": str(metadata),
            "DEVICES_FILE": str(devices),
            "AVBTOOL_BIN": str(
                aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
            ),
            "RSA_KEY_SIZE": "2048",
            "CERT_EXPIRY_DAYS": "1",
        },
        check=False,
    )

    assert generated.returncode == 0, generated.stderr
    assert (tmp_path / "keys" / "0x2000.x509.pem").is_file()


@pytest.mark.aosp
def test_softhsm_keygen_generates_usable_keys(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, environment = generated_softhsm_keys

    objects = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            f"env:{'PKCS11_PIN'}",
            "--list-objects",
        ],
        env=environment,
    )
    for key_id in ("2000", "1300", "1100", "1200"):
        rendered_id = f"(0x{key_id[:2]}:{key_id[2:]})"
        assert objects.stdout.count(rendered_id) == 3

    for key_name in ("0x2000", "0x1300", "0x1100", "0x1200"):
        assert (output / f"{key_name}.x509.pem").is_file()
    for key_name in ("0x2000", "0x1300"):
        assert (output / f"{key_name}.pem").is_file()
        assert (output / f"{key_name}.avbpubkey").is_file()

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


@pytest.mark.aosp
def test_softhsm_keygen_rerun_generates_nothing(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, environment = generated_softhsm_keys
    rerun = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert "No keys generated during the process." in rerun.stdout
    assert "No certs generated during the process." in rerun.stdout

    objects = run(
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
    for key_id in ("2000", "1300", "1100", "1200"):
        rendered_id = f"(0x{key_id[:2]}:{key_id[2:]})"
        assert objects.stdout.count(rendered_id) == 3


@pytest.mark.aosp
def test_softhsm_keygen_is_idempotent(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, environment = generated_softhsm_keys
    rerun = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert "No keys generated during the process." in rerun.stdout
    assert "No certs generated during the process." in rerun.stdout

    objects = run(
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
    for key_id in ("2000", "1300", "1100", "1200"):
        rendered_id = f"(0x{key_id[:2]}:{key_id[2:]})"
        assert objects.stdout.count(rendered_id) == 3


def signing_environment(
    base_environment: dict[str, str],
    key_id: str,
) -> dict[str, str]:
    return {
        **base_environment,
        "KEY_DIR": "keys/",
        "KEY_ID": f"0x{key_id}",
        "FIND_KEYS_BY_ID": "y",
        "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
        "DEBUG_PAYLOAD_SIGNER": "n",
    }


def verify_sha256_signature(
    public_key: Path,
    digest: Path,
    signature: Path,
) -> None:
    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            public_key,
            "-in",
            digest,
            "-sigfile",
            signature,
            "-pkeyopt",
            "rsa_padding_mode:pkcs1",
            "-pkeyopt",
            "digest:sha256",
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr


@pytest.mark.aosp
def test_payload_signer_uses_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    environment["DEBUG_PAYLOAD_SIGNER"] = ""
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"

    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / "payload_signer.py",
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            "keys/0x2000",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
    )
    assert signed.returncode == 0, signed.stderr
    assert signature.stat().st_size == 256
    verify_sha256_signature(output / "0x2000.pem", digest, signature)


@pytest.mark.aosp
def test_payload_signer_rejects_mismatched_public_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "1300")
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"
    signature.write_bytes(b"existing-signature")

    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / "payload_signer.py",
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            output / "0x2000.pem",
        ],
        env=environment,
        check=False,
    )

    assert signed.returncode != 0
    assert "does not match the selected PKCS#11 key" in signed.stderr
    assert signature.read_bytes() == b"existing-signature"


@pytest.mark.aosp
def test_softhsm_signing_rejects_wrong_pin(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    environment["PKCS11_PIN"] = "wrong-pin"
    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            output / "0x2000.pem",
        ],
        env=environment,
        input=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + bytes.fromhex("3031300d060960864801650304020105000420")
            + bytes(range(32))
        ),
        check=False,
        text=False,
    )

    assert signed.returncode != 0
    assert b"PIN" in signed.stderr
    assert b"Traceback" not in signed.stderr


@pytest.mark.aosp
def test_softhsm_signing_rejects_missing_key(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "ffff")
    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            output / "0x2000.pem",
        ],
        env=environment,
        input=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + bytes.fromhex("3031300d060960864801650304020105000420")
            + bytes(range(32))
        ),
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

    rerun = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert "generating missing cert" in rerun.stdout
    assert "No keys generated during the process." in rerun.stdout
    assert (output / "0x1100.x509.pem").is_file()


@pytest.mark.aosp
def test_avbtool_signs_with_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    image = tmp_path / "test.img"
    image.write_bytes(bytes(range(256)) * 16)
    avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"

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
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
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
    aosp_top: Path,
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "1300")
    image = tmp_path / "mismatched.img"
    image.write_bytes(bytes(range(256)) * 16)
    avbtool = aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool"

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
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
        ],
        env=environment,
        check=False,
    )

    assert signed.returncode != 0
    assert "does not match the selected PKCS#11 key" in signed.stderr


@pytest.mark.aosp
def test_keygen_initializes_empty_softhsm_store(
    tmp_path: Path,
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> None:
    require_softhsm(engine=True)
    metadata, devices = minimal_keygen_metadata
    output = tmp_path / "initialized-keys"
    environment = {
        **softhsm_token(tmp_path / "empty", initialize=False),
        "METADATA_FILE": str(metadata),
        "DEVICES_FILE": str(devices),
        "AVBTOOL_BIN": str(
            aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
        ),
        "RSA_KEY_SIZE": "2048",
        "CERT_EXPIRY_DAYS": "1",
        "YUBIHSM_PASSWORD": "unused-by-softhsm",
    }

    generated = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
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
common.OPTIONS.apksigner_kms_type = "external"
common.SignFile(sys.argv[4], sys.argv[5], "keys/0x1100", None, min_api_level=30)
"""


@pytest.mark.aosp
def test_releasetools_signs_apks_through_the_external_kms_provider(
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
            "APKSIGNER_EXTERNAL_SIGNER": str(
                SCRIPTS_DIR / "pkcs11" / "apksigner_signing_helper.py",
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
common.OPTIONS.apksigner_kms_type = "external"
common.OPTIONS.signing_command_interceptor = sys.argv[4]
key = "keys/0x1100"
common.SignFile(sys.argv[5], "signed.apk", key, None, min_api_level=30)
os.environ["APKSIGNER_EXTERNAL_SIGNER"] = "false"
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
            SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.interceptor.py",
            app,
        ],
        cwd=tmp_path,
        env={
            **base_environment,
            "KEY_DIR": "keys/",
            "APKSIGNER_EXTERNAL_SIGNER": str(
                SCRIPTS_DIR / "pkcs11" / "apksigner_signing_helper.py",
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
@pytest.mark.parametrize(
    "payload_signer",
    ("payload_signer.py", "payload_signer.server.py"),
)
def test_releasetools_signs_packages_through_the_external_signer(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
    payload_signer: str,
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
            SCRIPTS_DIR / "pkcs11" / payload_signer,
            package,
            "signed.zip",
        ],
        cwd=tmp_path,
        env={
            **signing_environment(base_environment, "2000"),
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
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> None:
    require_softhsm(engine=True)
    metadata, devices = minimal_keygen_metadata
    environment = {
        **softhsm_token(tmp_path / "token"),
        "METADATA_FILE": str(metadata),
        "DEVICES_FILE": str(devices),
        "AVBTOOL_BIN": str(
            aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
        ),
        "RSA_KEY_SIZE": "2048",
        "CERT_EXPIRY_DAYS": "1",
        "YUBIHSM_PASSWORD": "unused-by-softhsm",
    }
    output = tmp_path / "keys"

    generated = run(
        [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
        env=environment,
        check=False,
    )

    assert generated.returncode == 0, generated.stderr
    outcome = {
        "token": [list(entry) for entry in token_inventory(environment)],
        "files": sorted(path.name for path in output.iterdir()),
        "summary": [
            line
            for line in generated.stdout.splitlines()
            if line.startswith(("#", "Key generation", "No "))
        ],
    }
    assert outcome == json.loads(SOFTHSM_KEYGEN_FIXTURE.read_text())
