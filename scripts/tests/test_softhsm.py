#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, aosp_jar_command, run, run_bytes

SOFTHSM_MODULE = Path("/usr/lib/pkcs11/libsofthsm2.so")
PKCS11_ENGINE = Path("/usr/lib/engines-3/pkcs11.so")
SO_PIN = "12345678"
USER_PIN = "123456"
TOKEN_LABEL = "androsign-test"


def require_softhsm() -> None:
    missing = [
        name
        for name in ("softhsm2-util", "pkcs11-tool")
        if shutil.which(name) is None
    ]
    missing.extend(
        str(path)
        for path in (SOFTHSM_MODULE, PKCS11_ENGINE)
        if not path.is_file()
    )
    if missing:
        pytest.skip(
            f"SoftHSM test dependencies are missing: {', '.join(missing)}",
        )


def initialized_softhsm_token(directory: Path) -> dict[str, str]:
    token_dir = directory / "tokens"
    token_dir.mkdir(parents=True)
    config = directory / "softhsm2.conf"
    config.write_text(
        f"""directories.tokendir = {token_dir}
objectstore.backend = file
log.level = WARNING
slots.removable = true
slots.mechanisms = ALL
library.reset_on_fork = false
""",
    )
    environment = {
        "SOFTHSM2_CONF": str(config),
        "SOFTHSM_TOKEN_DIR": str(token_dir),
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": str(PKCS11_ENGINE),
        "PKCS11_TOOL_BIN": str(Path(shutil.which("pkcs11-tool") or "")),
        "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_SO_PIN": SO_PIN,
        "PKCS11_PIN": USER_PIN,
        "PKCS11_TESTING": "y",
    }
    initialized = run(
        [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            TOKEN_LABEL,
            "--so-pin",
            SO_PIN,
            "--pin",
            USER_PIN,
        ],
        env=environment,
        check=False,
    )
    assert initialized.returncode == 0, initialized.stderr
    return environment


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
            inventory.append((kind, line.split(":", 1)[1].strip()))
    return sorted(inventory)


@pytest.fixture
def softhsm_env(tmp_path: Path) -> dict[str, str]:
    require_softhsm()
    return initialized_softhsm_token(tmp_path)


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
KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "apex_payload": "keys_apex",
    "other": "keys_other",
    "core": "keys_core",
    "apex_container": "keys_apex",
}
MAPPED_KEY_TYPES = ("core",)
ALL_DEVICES = ("bramble",)
""",
    )
    devices = tmp_path / "devices"
    devices.write_text("devices=(bramble)\n")
    return metadata, devices


@pytest.fixture(params=("bash", "python"))
def generated_softhsm_keys(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    softhsm_env: dict[str, str],
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> tuple[Path, dict[str, str]]:
    metadata, devices = minimal_keygen_metadata
    output = tmp_path / "keys"
    environment = {
        **softhsm_env,
        "USE_PYTHON_KEYGEN": "y" if request.param == "python" else "",
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


@pytest.fixture
def generated_softhsm_keys_via_python(
    tmp_path: Path,
    softhsm_env: dict[str, str],
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> tuple[Path, dict[str, str]]:
    metadata, devices = minimal_keygen_metadata
    output = tmp_path / "keys"
    environment = {
        **softhsm_env,
        "PYTHONPATH": str(SCRIPTS_DIR),
        "PKCS11_PYTHON_TOOLS": "y",
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
            "PKCS11_PYTHON_TOOLS": "y",
            "METADATA_FILE": str(metadata),
            "DEVICES_FILE": str(devices),
            "AVBTOOL_BIN": str(
                aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
            ),
            "RSA_KEY_SIZE": "2048",
            "CERT_EXPIRY_DAYS": "1",
            "YUBIHSM_PASSWORD": "unused-by-softhsm",
        },
        check=False,
    )

    assert generated.returncode == 0, generated.stderr
    assert (tmp_path / "keys" / "0x2000.x509.pem").is_file()


@pytest.mark.aosp
def test_softhsm_keygen_generates_keys_via_python_when_flagged(
    generated_softhsm_keys_via_python: tuple[Path, dict[str, str]],
) -> None:
    """
    Keys and certificates generated under PKCS11_PYTHON_TOOLS=y go through
    the Bash avbpubkey export.
    """
    output, environment = generated_softhsm_keys_via_python

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
def test_softhsm_keygen_existence_checks_via_python_are_idempotent(
    generated_softhsm_keys_via_python: tuple[Path, dict[str, str]],
) -> None:
    """
    A rerun under PKCS11_PYTHON_TOOLS=y finds the keys and certificates of
    the first run and generates nothing.
    """
    output, environment = generated_softhsm_keys_via_python
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
def test_signing_helper_uses_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = {
        **base_environment,
        "KEY_ID": "0x2000",
        "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
        "STRIP_HEX_KEY_ID_PREFIX": "y",
    }
    digest = bytes(range(32))
    signed = run_bytes(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.openssl.sh",
            "SHA256_RSA2048",
            "unused.pem",
        ],
        env=environment,
        input_data=b"\x00" * 205 + digest,
        check=False,
    )
    assert signed.returncode == 0, signed.stderr.decode(errors="replace")
    signature = tmp_path / "signature.bin"
    signature.write_bytes(signed.stdout)
    digest_file = tmp_path / "digest.bin"
    digest_file.write_bytes(digest)

    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            output / "0x2000.pem",
            "-in",
            digest_file,
            "-sigfile",
            signature,
            "-pkeyopt",
            "rsa_padding_mode:pkcs1",
        ],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr


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
        "STRIP_HEX_KEY_ID_PREFIX": "y",
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
def test_pkcs11_tool_payload_signer_cross_checks_without_dumping_secrets(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    del environment["DEBUG_PAYLOAD_SIGNER"]
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"
    debug_root = Path("/dev/shm/payload_signer_debug")
    before: set[Path] = (
        set(debug_root.iterdir()) if debug_root.is_dir() else set()
    )

    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / "payload_signer.pkcs11-tool.sh",
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            Path("keys/0x2000.pem"),
        ],
        env=environment,
        check=False,
    )

    assert signed.returncode == 0, signed.stderr
    verify_sha256_signature(output / "0x2000.pem", digest, signature)
    (debug_dir,) = set(debug_root.iterdir()) - before
    names = sorted(path.name for path in debug_dir.iterdir())
    assert names == [
        "arguments.txt",
        "input.bin",
        "output-openssl.bin",
        "output-pkcs11-tool.bin",
    ]


@pytest.mark.aosp
@pytest.mark.parametrize(
    "helper_name",
    (
        "payload_signer.openssl.sh",
        "payload_signer.pkcs11-tool.sh",
        "payload_signer.py",
    ),
)
def test_payload_signers_use_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    helper_name: str,
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    if helper_name == "payload_signer.py":
        environment["DEBUG_PAYLOAD_SIGNER"] = ""
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"

    signed = run(
        [
            SCRIPTS_DIR / "pkcs11" / helper_name,
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
    _, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    environment["PKCS11_PIN"] = "wrong-pin"
    signed = run_bytes(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.openssl.sh",
            "SHA256_RSA2048",
            "keys/0x2000.pem",
        ],
        env=environment,
        input_data=b"\x00" * 205 + bytes(range(32)),
        check=False,
    )
    assert signed.returncode != 0


@pytest.mark.aosp
def test_python_softhsm_signing_rejects_wrong_pin(
    generated_softhsm_keys: tuple[Path, dict[str, str]],
) -> None:
    output, base_environment = generated_softhsm_keys
    environment = signing_environment(base_environment, "2000")
    environment["PKCS11_PIN"] = "wrong-pin"
    signed = run_bytes(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            output / "0x2000.pem",
        ],
        env=environment,
        input_data=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + bytes.fromhex("3031300d060960864801650304020105000420")
            + bytes(range(32))
        ),
        check=False,
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
    signed = run_bytes(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            output / "0x2000.pem",
        ],
        env=environment,
        input_data=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + bytes.fromhex("3031300d060960864801650304020105000420")
            + bytes(range(32))
        ),
        check=False,
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
@pytest.mark.parametrize(
    "signing_helper",
    (
        SCRIPTS_DIR / "pkcs11" / "signing_helper.openssl.sh",
        SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
    ),
)
def test_avbtool_signs_with_softhsm_key(
    tmp_path: Path,
    generated_softhsm_keys: tuple[Path, dict[str, str]],
    aosp_top: Path,
    signing_helper: Path,
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
            signing_helper,
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
@pytest.mark.parametrize("python", (False, True), ids=("bash", "python"))
def test_keygen_initializes_empty_softhsm_store(
    tmp_path: Path,
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
    python: bool,
) -> None:
    require_softhsm()
    token_dir = tmp_path / "empty-tokens"
    token_dir.mkdir()
    config = tmp_path / "empty-softhsm2.conf"
    config.write_text(
        f"""directories.tokendir = {token_dir}
objectstore.backend = file
log.level = WARNING
slots.removable = true
slots.mechanisms = ALL
library.reset_on_fork = false
""",
    )
    metadata, devices = minimal_keygen_metadata
    output = tmp_path / "initialized-keys"
    environment = {
        "SOFTHSM2_CONF": str(config),
        "SOFTHSM_TOKEN_DIR": str(token_dir),
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": str(PKCS11_ENGINE),
        "PKCS11_TOOL_BIN": str(Path(shutil.which("pkcs11-tool") or "")),
        "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_SO_PIN": SO_PIN,
        "PKCS11_PIN": USER_PIN,
        "PKCS11_TESTING": "y",
        "METADATA_FILE": str(metadata),
        "DEVICES_FILE": str(devices),
        "AVBTOOL_BIN": str(
            aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
        ),
        "RSA_KEY_SIZE": "2048",
        "CERT_EXPIRY_DAYS": "1",
        "YUBIHSM_PASSWORD": "unused-by-softhsm",
        "USE_PYTHON_KEYGEN": "y" if python else "",
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


def test_sign_plan_signs_softhsm_devices_without_loading_keys() -> None:
    result = run(
        [
            "bash",
            "-c",
            r"""
source <(sed '/^err=0$/,$d' "$1")
source "$2"
source "$3"
all_devices=(bramble redfin oriole)
declare -A device_to_next_build=([bramble]=2 [redfin]=3)
declare -A device_to_prev_build=([bramble]=1)
declare -A device_to_preexisting_build=()
no_sign=n
no_incremental=n
sign_builds() { printf 'sign %s\n' "$*"; }
generate_incrementals() { printf 'delta %s\n' "$*"; }
ensure_all_keys_available_for_devices() { printf 'load %s\n' "$*"; }
upload_logs() { :; }
sort_and_separate_devices_by_key_availability
do_or_show
""",
            "softhsm-sign-plan-test",
            SCRIPTS_DIR / "sign.sh",
            SCRIPTS_DIR / "common.include.sh",
            SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.include.sh",
        ],
        env={"PKCS11_MODULE": "/dev/null"},
    )

    assert [
        line
        for line in result.stdout.splitlines()
        if not line.startswith("Running:")
    ] == ["sign bramble,2,2 redfin,3,3", "delta bramble,1,2"]


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
    (
        "payload_signer.openssl.sh",
        "payload_signer.pkcs11-tool.sh",
        "payload_signer.py",
        "payload_signer.server.py",
    ),
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
def test_python_softhsm_keygen_matches_bash(
    tmp_path: Path,
    minimal_keygen_metadata: tuple[Path, Path],
    aosp_top: Path,
) -> None:
    require_softhsm()
    metadata, devices = minimal_keygen_metadata
    results = {}
    for label, flag in (("bash", ""), ("python", "y")):
        environment = {
            **initialized_softhsm_token(tmp_path / label),
            "USE_PYTHON_KEYGEN": flag,
            "METADATA_FILE": str(metadata),
            "DEVICES_FILE": str(devices),
            "AVBTOOL_BIN": str(
                aosp_top / "out" / "host" / "linux-x86" / "bin" / "avbtool",
            ),
            "RSA_KEY_SIZE": "2048",
            "CERT_EXPIRY_DAYS": "1",
            "YUBIHSM_PASSWORD": "unused-by-softhsm",
        }
        output = tmp_path / label / "keys"
        generated = run(
            [SCRIPTS_DIR / "pkcs11" / "vendor.softhsm.keygen.sh", output],
            env=environment,
            check=False,
        )
        assert generated.returncode == 0, generated.stderr
        results[label] = (
            token_inventory(environment),
            sorted(path.name for path in output.iterdir()),
            [
                line
                for line in generated.stdout.splitlines()
                if line.startswith(("#", "Key generation", "No "))
            ],
        )

    assert results["python"] == results["bash"]
