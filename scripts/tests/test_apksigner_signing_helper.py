#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import contextlib
import datetime
import hashlib
from collections.abc import Generator
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, SOFTHSM_KEY_ID, run, yubihsm_config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from signing.signing_server import Message, SigningServer
from signing.yubihsm_session_service import YubiHsmSessionService
from software_rsa import rsa_key, verifies
from yubihsm_emulator import Connector

HELPER = SCRIPTS_DIR / "pkcs11" / "apksigner_signing_helper.py"


@contextlib.contextmanager
def _signing_server(
    socket_path: Path,
    yubihsm: Connector,
) -> Generator[SigningServer, None, None]:
    service = YubiHsmSessionService(
        yubihsm_config(yubihsm),
    )
    server = SigningServer(socket_path, {"yubihsm_sign_pkcs1": service})
    with server:
        yield server


KEY_ID = SOFTHSM_KEY_ID


def _certificate(
    directory: Path,
    key_id: str,
    public_key: rsa.RSAPublicKey,
) -> Path:
    issuer = rsa_key("issuer")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, key_id)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(issuer, hashes.SHA256())
    )
    directory.mkdir(exist_ok=True)
    (directory / f"{key_id}.x509.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    return directory


def _der_public_key(path: Path) -> rsa.RSAPublicKey:
    key = serialization.load_der_public_key(path.read_bytes())
    assert isinstance(key, rsa.RSAPublicKey)
    return key


def _softhsm_key_dir(directory: Path, public_key: Path) -> str:
    return f"{_certificate(directory, KEY_ID, _der_public_key(public_key))}/"


@pytest.mark.parametrize(
    ("mechanism", "algorithm"),
    (
        ("sha256-rsa-pkcs", hashes.SHA256()),
        ("sha384-rsa-pkcs", hashes.SHA384()),
        ("sha512-rsa-pkcs", hashes.SHA512()),
    ),
)
def test_apksigner_signing_helper_signs_raw_data(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
    mechanism: str,
    algorithm: hashes.HashAlgorithm,
) -> None:
    environment, public_key = softhsm_rsa_key
    data = b"apksigner signable content, unhashed" * 100

    result = run(
        [HELPER, mechanism, KEY_ID],
        env={
            **environment,
            "KEY_DIR": _softhsm_key_dir(tmp_path / "keys", public_key),
        },
        input=data,
        check=False,
        text=False,
    )
    assert result.returncode == 0, result.stderr
    assert verifies(
        _der_public_key(public_key),
        result.stdout,
        hashlib.new(algorithm.name, data).digest(),
        algorithm,
    )
    assert len(result.stdout) == 256


def test_apksigner_signing_helper_rejects_unsupported_mechanism(
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key

    result = run(
        [HELPER, "rsa-pkcs", KEY_ID],
        env=environment,
        input=b"data",
        check=False,
        text=False,
    )
    assert result.returncode != 0
    assert b"Unsupported mechanism: rsa-pkcs" in result.stderr


def test_apksigner_signing_helper_rejects_extra_arguments() -> None:
    result = run(
        [HELPER, "sha256-rsa-pkcs", KEY_ID, "unexpected"],
        env={"PKCS11_MODULE": "/dev/null"},
        check=False,
    )
    assert result.returncode != 0
    assert "Unexpected arguments: unexpected" in result.stderr


class _SignHandler:
    def __init__(self, response: Message) -> None:
        self.response = response
        self.requests: list[Message] = []

    def handle(self, message: Message) -> Message:
        self.requests.append(message)
        return self.response


@pytest.mark.parametrize(
    ("mechanism", "algorithm"),
    (
        ("sha256-rsa-pkcs", hashes.SHA256()),
        ("sha384-rsa-pkcs", hashes.SHA384()),
        ("sha512-rsa-pkcs", hashes.SHA512()),
    ),
)
def test_apksigner_signing_helper_signs_with_the_server_key(
    tmp_path: Path,
    yubihsm: Connector,
    mechanism: str,
    algorithm: hashes.HashAlgorithm,
) -> None:
    data = b"apksigner signable content, unhashed" * 100
    digest = hashlib.new(algorithm.name, data).digest()
    yubihsm.device.put_asymmetric_key(0x1100, key=rsa_key("a"))
    yubihsm.device.put_asymmetric_key(0x1200, key=rsa_key("b"))
    key_dir = _certificate(
        tmp_path / "keys",
        "0x1100",
        rsa_key("a").public_key(),
    )

    with _signing_server(tmp_path / "s.sock", yubihsm) as server:
        result = run(
            [HELPER, mechanism, "0x1100"],
            env={
                "SIGNING_SERVER_SOCKET": str(server.socket_path),
                "KEY_DIR": f"{key_dir}/",
            },
            input=data,
            check=False,
            text=False,
        )

    assert result.returncode == 0, result.stderr
    assert verifies(rsa_key("a"), result.stdout, digest, algorithm)
    assert not verifies(rsa_key("b"), result.stdout, digest, algorithm)


def test_apksigner_signing_helper_falls_back_when_the_server_cannot_sign(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, public_key = softhsm_rsa_key
    data = b"apksigner signable content, unhashed"
    handler = _SignHandler({"status": "unavailable"})
    server = SigningServer(tmp_path / "s.sock", {"yubihsm_sign_pkcs1": handler})

    with server:
        result = run(
            [HELPER, "sha256-rsa-pkcs", KEY_ID],
            env={
                **environment,
                "SIGNING_SERVER_SOCKET": str(server.socket_path),
                "KEY_DIR": _softhsm_key_dir(tmp_path / "keys", public_key),
            },
            input=data,
            check=False,
            text=False,
        )

    assert result.returncode == 0, result.stderr
    assert len(handler.requests) == 1
    assert verifies(
        _der_public_key(public_key),
        result.stdout,
        hashlib.sha256(data).digest(),
    )


def test_apksigner_signing_helper_reads_an_empty_key_dir_as_the_cwd(
    tmp_path: Path,
    yubihsm: Connector,
) -> None:
    _certificate(tmp_path, "0x1100", rsa_key("a").public_key())
    yubihsm.device.put_asymmetric_key(0x1100, key=rsa_key("a"))

    with _signing_server(tmp_path / "s.sock", yubihsm) as server:
        result = run(
            [HELPER, "sha256-rsa-pkcs", "0x1100"],
            cwd=tmp_path,
            env={
                "SIGNING_SERVER_SOCKET": str(server.socket_path),
                "KEY_DIR": "",
            },
            input=b"apksigner signable content",
            check=False,
            text=False,
        )

    assert result.returncode == 0, result.stderr


def test_apksigner_signing_helper_refuses_a_certificate_of_another_key(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key
    key_dir = _certificate(tmp_path / "keys", KEY_ID, rsa_key("b").public_key())

    result = run(
        [HELPER, "sha256-rsa-pkcs", KEY_ID],
        env={**environment, "KEY_DIR": f"{key_dir}/"},
        input=b"apksigner signable content",
        check=False,
        text=False,
    )

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"does not verify under the certificate" in result.stderr


def test_apksigner_signing_helper_refuses_to_sign_without_the_certificate(
    tmp_path: Path,
    softhsm_rsa_key: tuple[dict[str, str], Path],
) -> None:
    environment, _ = softhsm_rsa_key

    result = run(
        [HELPER, "sha256-rsa-pkcs", KEY_ID],
        env={
            **environment,
            "KEY_DIR": f"{tmp_path / 'keys'}/",
            "PKCS11_MODULE": str(tmp_path / "missing-module.so"),
        },
        input=b"apksigner signable content",
        check=False,
        text=False,
    )

    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr.startswith(b"no certificate")
