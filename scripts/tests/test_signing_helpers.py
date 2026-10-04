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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PYTHON_SIGNING_HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.py"
PYTHON_PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.py"


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
    public_key = tmp_path / "rsa-2048.pub.pem"
    public_key.write_bytes(
        rsa.generate_private_key(65537, 2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
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
