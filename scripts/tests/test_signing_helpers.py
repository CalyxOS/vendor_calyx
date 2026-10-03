#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import importlib.util
import io
import stat
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run, run_bytes, stub
from openssl_shim import generate_rsa_key, helper_env, write_openssl_pkcs11_shim

SIGNING_HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.openssl.sh"
PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.openssl.sh"
PYTHON_SIGNING_HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.py"
PYTHON_PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.py"


@pytest.fixture
def openssl_pkcs11_shim(tmp_path: Path) -> Path:
    return write_openssl_pkcs11_shim(tmp_path)


@pytest.fixture
def failing_pkcs11_tool(tmp_path: Path) -> Path:
    """Create a provider tool that emits a YubiHSM recovery marker."""
    tool = tmp_path / "failing-pkcs11-tool"
    tool.write_text(
        "#!/bin/sh\necho 'Connector operation failed: simulated' >&2\nexit 1\n",
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    return tool


def python_helper_env(tool: Path) -> dict[str, str]:
    """Configure Python helpers to invoke one test PKCS#11 tool."""
    return {
        "PKCS11_MODULE": "/dev/null",
        "PKCS11_TOOL_BIN": str(tool),
        "KEY_ID": "0x2000",
        "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
        "DEBUG_PAYLOAD_SIGNER": "n",
    }


def test_avb_helper_preserves_provider_stderr(
    failing_pkcs11_tool: Path,
) -> None:
    result = run_bytes(
        [PYTHON_SIGNING_HELPER, "SHA256_RSA2048", "keys/0x2000.pem"],
        env=python_helper_env(failing_pkcs11_tool),
        input_data=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + bytes.fromhex("3031300d060960864801650304020105000420")
            + bytes(range(32))
        ),
        check=False,
    )

    assert result.returncode != 0
    assert b"Connector operation failed: simulated" in result.stderr
    assert b"Traceback" not in result.stderr


def test_payload_helper_preserves_provider_stderr(
    tmp_path: Path,
    failing_pkcs11_tool: Path,
) -> None:
    digest = tmp_path / "digest.bin"
    output = tmp_path / "signature.bin"
    digest.write_bytes(bytes(range(32)))
    result = run_bytes(
        [
            PYTHON_PAYLOAD_SIGNER,
            "-in",
            digest,
            "-out",
            output,
            "-inkey",
            "keys/0x2000.pem",
        ],
        env=python_helper_env(failing_pkcs11_tool),
        check=False,
    )

    assert result.returncode != 0
    assert b"Connector operation failed: simulated" in result.stderr
    assert b"Traceback" not in result.stderr
    assert not output.exists()


def test_payload_helper_rejects_invalid_verification_mode(
    tmp_path: Path,
) -> None:
    digest = tmp_path / "digest.bin"
    output = tmp_path / "signature.bin"
    digest.write_bytes(bytes(range(32)))
    result = run(
        [
            PYTHON_PAYLOAD_SIGNER,
            "-in",
            digest,
            "-out",
            output,
            "-inkey",
            "keys/0x2000.pem",
        ],
        env={"DEBUG_PAYLOAD_SIGNER": "yes"},
        check=False,
    )

    assert result.returncode != 0
    assert "DEBUG_PAYLOAD_SIGNER must be 'y' or 'n'" in result.stderr
    assert "PKCS11_MODULE" not in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("algorithm", "bits", "padding_size", "digest"),
    (
        ("SHA256_RSA2048", 2048, 205, bytes(range(32))),
        ("SHA512_RSA4096", 4096, 429, bytes(range(64))),
    ),
)
def test_signing_helper_strips_avb_padding_and_signs_digest(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
    algorithm: str,
    bits: int,
    padding_size: int,
    digest: bytes,
) -> None:
    private_key = generate_rsa_key(tmp_path, bits)
    result = run_bytes(
        [SIGNING_HELPER, algorithm, "keys/test-key.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        input_data=b"\x00" * padding_size + digest,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    signature = tmp_path / "signature.bin"
    signature.write_bytes(result.stdout)
    digest_file = tmp_path / "digest.bin"
    digest_file.write_bytes(digest)

    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-inkey",
            private_key,
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
    assert signature.stat().st_size == bits // 8


def test_signing_helper_rejects_unsupported_algorithm(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    result = run(
        [SIGNING_HELPER, "SHA1_RSA2048", "keys/test-key.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert "Unsupported/untested algorithm: SHA1_RSA2048" in result.stderr


def test_signing_helper_rejects_extra_arguments(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    result = run(
        [SIGNING_HELPER, "SHA256_RSA2048", "keys/test-key.pem", "unexpected"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert "Unexpected arguments: unexpected" in result.stderr


def test_payload_signer_signs_sha256_digest(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    digest = tmp_path / "payload.digest"
    digest.write_bytes(bytes(range(32)))
    signature = tmp_path / "payload.signature"

    result = run(
        [
            PAYLOAD_SIGNER,
            "-in",
            digest,
            "-out",
            signature,
            "-inkey",
            "keys/ota.pem",
        ],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-inkey",
            private_key,
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


def test_payload_signer_rejects_missing_required_arguments(
    tmp_path: Path,
    openssl_pkcs11_shim: Path,
) -> None:
    private_key = generate_rsa_key(tmp_path, 2048)
    signature = tmp_path / "payload.signature"
    result = run(
        [PAYLOAD_SIGNER, "-out", signature, "-inkey", "keys/ota.pem"],
        env=helper_env(openssl_pkcs11_shim, private_key),
        check=False,
    )
    assert result.returncode != 0
    assert not signature.exists()


def test_python_avb_helper_refuses_a_signature_that_does_not_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "signing_helper_under_test",
        PYTHON_SIGNING_HELPER,
    )
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    private_key = generate_rsa_key(tmp_path, 2048)
    public_key = tmp_path / "rsa-2048.pub.pem"
    run(["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key])
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420")
        + hashlib.sha256(b"vbmeta").digest()
    )
    data = b"\x00\x01" + b"\xff" * 202 + b"\x00" + digest_info
    monkeypatch.setattr(helper, "pkcs11_signer_from_environment", object)
    monkeypatch.setattr(helper, "key_reference_from_path", stub(None))
    monkeypatch.setattr(helper, "require_matching_public_key", stub(None))
    monkeypatch.setattr(helper, "sign_avb_input", stub(bytes(256)))
    monkeypatch.setattr(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))

    with pytest.raises(ValueError, match="does not verify"):
        helper.main(["SHA256_RSA2048", str(public_key)])
