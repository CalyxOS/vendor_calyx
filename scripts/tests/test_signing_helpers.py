#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from conftest import SCRIPTS_DIR, install_executable, run, stub
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from software_rsa import avb_input

PYTHON_SIGNING_HELPER = SCRIPTS_DIR / "pkcs11" / "signing_helper.py"
PYTHON_PAYLOAD_SIGNER = SCRIPTS_DIR / "pkcs11" / "payload_signer.py"


def load_helper(path: Path) -> ModuleType:
    """Import a helper script without running its entry point."""
    spec = importlib.util.spec_from_file_location(
        f"{path.stem}_under_test",
        path,
    )
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


@pytest.fixture
def failing_pkcs11_tool(tmp_path: Path) -> Path:
    """Create a provider tool that emits a YubiHSM recovery marker."""
    return install_executable(
        tmp_path / "failing-pkcs11-tool",
        "#!/bin/sh\necho 'Connector operation failed: simulated' >&2\nexit 1\n",
    )


def python_helper_env(tool: Path) -> dict[str, str]:
    """Configure Python helpers to invoke one test PKCS#11 tool."""
    return {
        "PKCS11_MODULE": "/dev/null",
        "PKCS11_TOOL_BIN": str(tool),
        "KEY_DIR": "keys/",
        "DEBUG_PAYLOAD_SIGNER": "n",
    }


def test_avb_helper_preserves_provider_stderr(
    failing_pkcs11_tool: Path,
) -> None:
    result = run(
        [PYTHON_SIGNING_HELPER, "SHA256_RSA2048", "keys/0x2000.pem"],
        env=python_helper_env(failing_pkcs11_tool),
        input=avb_input(bytes(range(32))),
        check=False,
        text=False,
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
        env=python_helper_env(failing_pkcs11_tool),
        check=False,
        text=False,
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
    helper = load_helper(PYTHON_SIGNING_HELPER)
    public_key = tmp_path / "rsa-2048.pub.pem"
    public_key.write_bytes(
        rsa.generate_private_key(65537, 2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    data = avb_input(hashlib.sha256(b"vbmeta").digest())
    monkeypatch.setattr(
        helper,
        "pkcs11_signer_from_environment",
        stub(SimpleNamespace(sign=stub(bytes(256)))),
    )
    monkeypatch.setattr(helper, "require_matching_public_key", stub(None))
    monkeypatch.setattr(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))

    with pytest.raises(ValueError, match="does not verify"):
        helper.main(["SHA256_RSA2048", str(public_key)])


@pytest.mark.parametrize("size", (0, 31, 33))
def test_payload_helper_rejects_invalid_digest_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size: int,
) -> None:
    helper = load_helper(PYTHON_PAYLOAD_SIGNER)
    digest = tmp_path / "digest.bin"
    output = tmp_path / "signature.bin"
    digest.write_bytes(b"x" * size)
    monkeypatch.setattr(helper, "pkcs11_signer_from_environment", object)
    monkeypatch.setattr(helper, "require_matching_public_key", stub(None))

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        helper.main(
            [
                "-in",
                str(digest),
                "-out",
                str(output),
                "-inkey",
                "keys/ota.pem",
            ],
        )
    assert not output.exists()


def test_python_payload_signer_refuses_a_signature_that_does_not_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(PYTHON_PAYLOAD_SIGNER)
    public_key = tmp_path / "ota.pem"
    public_key.write_bytes(
        rsa.generate_private_key(65537, 2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    digest = tmp_path / "digest.bin"
    digest.write_bytes(hashlib.sha256(b"payload").digest())
    output = tmp_path / "signature.bin"
    monkeypatch.delenv("SIGNING_SERVER_SOCKET", raising=False)
    monkeypatch.delenv("DEBUG_PAYLOAD_SIGNER", raising=False)
    monkeypatch.setattr(
        helper,
        "pkcs11_signer_from_environment",
        stub(SimpleNamespace(sign=stub(bytes(256)))),
    )
    monkeypatch.setattr(helper, "require_matching_public_key", stub(None))

    with pytest.raises(ValueError, match="does not verify"):
        helper.main(
            [
                "-in",
                str(digest),
                "-out",
                str(output),
                "-inkey",
                str(public_key),
            ],
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "contents",
    (b"not a key\n", b"\x30\x82\x01\x22"),
    ids=("text", "der"),
)
def test_python_avb_helper_names_a_key_file_it_cannot_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contents: bytes,
) -> None:
    helper = load_helper(PYTHON_SIGNING_HELPER)
    public_key = tmp_path / "rsa-2048.pub.pem"
    public_key.write_bytes(contents)
    data = avb_input(hashlib.sha256(b"vbmeta").digest())
    monkeypatch.setattr(
        helper,
        "pkcs11_signer_from_environment",
        stub(SimpleNamespace(sign=stub(bytes(256)))),
    )
    monkeypatch.setattr(helper, "require_matching_public_key", stub(None))
    monkeypatch.setattr(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))

    with pytest.raises(ValueError, match="holds no usable PEM public key"):
        helper.main(["SHA256_RSA2048", str(public_key)])
