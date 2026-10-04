#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import (
    PKCS11_ENGINE,
    SCRIPTS_DIR,
    SOFTHSM_KEY_ID,
    SOFTHSM_KEY_LABEL,
    SOFTHSM_MODULE,
    SOFTHSM_SO_PIN,
    SOFTHSM_TOKEN_LABEL,
    SOFTHSM_USER_PIN,
    assert_certificate_of,
    install_executable,
    require_softhsm,
    run,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from signing.avb_signing import SHA256_DIGEST_INFO_PREFIX
from signing.models import (
    KeyReference,
    KeySpec,
    SignRequest,
)
from signing.pkcs11 import Pkcs11Backend, Pkcs11Config
from software_rsa import avb_input, der_public_key, verifies


def test_backend_exports_a_public_key_when_listing_needs_no_pin(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    _, _, public_key = pkcs11_token
    no_pin_listing = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            pin=SOFTHSM_USER_PIN,
            token_label=SOFTHSM_TOKEN_LABEL,
            list_requires_no_pin=True,
        ),
    )
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)

    assert no_pin_listing.export_public_key(reference) == (
        public_key.read_bytes()
    )


@pytest.fixture
def pkcs11_token(
    softhsm_rsa_key: tuple[dict[str, str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Pkcs11Backend, dict[str, str], Path]:
    require_softhsm(engine=True)
    environment, public_key = softhsm_rsa_key
    monkeypatch.setenv("SOFTHSM2_CONF", environment["SOFTHSM2_CONF"])
    backend = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            pin=SOFTHSM_USER_PIN,
            token_label=SOFTHSM_TOKEN_LABEL,
            openssl_engine=PKCS11_ENGINE,
            certificate_days=1,
        ),
    )
    return backend, environment, public_key


def test_pkcs11_raw_rsa_signing_contract(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, public_key = pkcs11_token
    digest = bytes(range(32))
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)

    signature = backend.sign(SignRequest(reference, digest, "rsa-pkcs"))

    recovered = der_public_key(public_key).recover_data_from_signature(
        signature,
        padding.PKCS1v15(),
        None,
    )
    assert recovered == digest


def test_pkcs11_raw_rsa_signing_contract_rejects_missing_key(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference("0xffff", SOFTHSM_KEY_LABEL)

    with pytest.raises(subprocess.CalledProcessError):
        backend.sign(SignRequest(reference, bytes(range(32)), "rsa-pkcs"))


def test_pkcs11_backend_discovers_objects(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)

    assert backend.key_exists(reference)
    assert not backend.certificate_exists(reference)


def test_pkcs11_backend_rejects_invalid_id_and_mechanism(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    invalid_id = KeyReference("0x123", SOFTHSM_KEY_LABEL)
    valid = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)

    with pytest.raises(ValueError, match="invalid PKCS#11 key ID"):
        backend.key_exists(invalid_id)
    with pytest.raises(
        ValueError,
        match="unsupported PKCS#11 signing mechanism",
    ):
        backend.sign(SignRequest(valid, b"data", "md5"))


@pytest.mark.parametrize("key_size", (2048, 3072))
def test_pkcs11_key_generation_contract(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
    tmp_path: Path,
    key_size: int,
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference("0x3000", "generated-key")
    backend.generate_key(KeySpec(reference, key_size, exportable=True))

    assert backend.key_exists(reference)
    public_key = tmp_path / "generated-public.der"
    public_key.write_bytes(backend.export_public_key(reference))
    details = run(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            public_key,
            "-text",
            "-noout",
        ],
    )
    assert f"Public-Key: ({key_size} bit)" in details.stdout


def token_object_ids(environment: dict[str, str], key_id: str) -> list[str]:
    listing = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            SOFTHSM_TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--list-objects",
            "--id",
            key_id.removeprefix("0x"),
        ],
        env=environment,
    )
    return [
        line for line in listing.stdout.splitlines() if "ID:" in line.strip()
    ]


def test_pkcs11_backend_rejects_duplicate_key_ids(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, environment, _ = pkcs11_token
    reference = KeyReference("0x3000", "generated-key")
    spec = KeySpec(
        reference,
        2048,
        exportable=True,
    )
    backend.generate_key(spec)
    public_key = backend.export_public_key(reference)

    with pytest.raises(ValueError, match="key already exists: 0x3000"):
        backend.generate_key(spec)

    assert backend.export_public_key(reference) == public_key
    assert len(token_object_ids(environment, "0x3000")) == 2


@pytest.mark.parametrize(
    ("key_id", "key_size"),
    (
        (SOFTHSM_KEY_ID, 2048),
        ("0x2100", 3072),
    ),
)
def test_pkcs11_certificate_contract(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
    tmp_path: Path,
    key_id: str,
    key_size: int,
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference(key_id, SOFTHSM_KEY_LABEL)
    spec = KeySpec(reference, key_size)
    if key_id != SOFTHSM_KEY_ID:
        backend.generate_key(spec)
    subject = "/C=US/O=Calyx Institute/CN=Shared PKCS11 certificate"
    certificate = tmp_path / "certificate.pem"
    certificate.write_bytes(backend.generate_certificate(spec, subject))

    assert backend.certificate_exists(reference)
    assert_certificate_of(
        serialization.load_der_public_key(backend.export_public_key(reference)),
        certificate,
        "CN=Shared PKCS11 certificate,O=Calyx Institute,C=US",
    )
    verified = run(
        ["openssl", "verify", "-CAfile", certificate, certificate],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr


def test_pkcs11_backend_rejects_duplicate_certificates(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, environment, _ = pkcs11_token
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)
    spec = KeySpec(reference, 2048)
    first = backend.generate_certificate(spec, "/CN=First certificate")

    with pytest.raises(ValueError, match="certificate already exists"):
        backend.generate_certificate(spec, "/CN=Second certificate")

    stored = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            SOFTHSM_TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--read-object",
            "--type",
            "cert",
            "--id",
            SOFTHSM_KEY_ID.removeprefix("0x"),
        ],
        env=environment,
        text=False,
    )
    stored_pem = run(
        ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
        input=stored.stdout,
        text=False,
    )
    assert stored_pem.stdout == first


def test_so_pin_backend_refuses_a_key_id_whose_private_key_exists(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    generation_backend, environment, _ = pkcs11_token
    so_pin_backend = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            token_label=SOFTHSM_TOKEN_LABEL,
            openssl_engine=PKCS11_ENGINE,
            pin=SOFTHSM_SO_PIN,
            use_so_pin=True,
            discovery_pin=SOFTHSM_USER_PIN,
        ),
    )
    reference = KeyReference("0x3003", "so-pin-exists-check")
    spec = KeySpec(reference, 2048)
    generation_backend.generate_key(spec)
    run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            SOFTHSM_TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--delete-object",
            "--type",
            "pubkey",
            "--id",
            "3003",
        ],
        env=environment,
    )

    with pytest.raises(ValueError, match="key already exists: 0x3003"):
        so_pin_backend.generate_key(spec)

    assert len(token_object_ids(environment, "0x3003")) == 1


def test_certificate_generation_under_so_pin_against_softhsm(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
    tmp_path: Path,
) -> None:
    """
    An SO-authenticated SoftHSM session cannot use a private key, so
    generate_certificate() must sign through signing_pin, never the SO
    PIN it imports the certificate with.
    """
    generation_backend, _, _ = pkcs11_token
    so_pin_config = Pkcs11Config(
        module=SOFTHSM_MODULE,
        token_label=SOFTHSM_TOKEN_LABEL,
        openssl_engine=PKCS11_ENGINE,
        certificate_days=1,
        pin=SOFTHSM_SO_PIN,
        use_so_pin=True,
        # Without a discovery PIN, the existence checks before signing
        # would fail first, since an SO session cannot see private objects.
        discovery_pin=SOFTHSM_USER_PIN,
    )

    broken_reference = KeyReference("0x3001", "so-pin-broken")
    broken_spec = KeySpec(broken_reference, 2048)
    generation_backend.generate_key(broken_spec)
    broken_backend = Pkcs11Backend(so_pin_config)
    with pytest.raises(subprocess.CalledProcessError):
        broken_backend.generate_certificate(broken_spec, "/CN=so-pin-broken/")
    assert not generation_backend.certificate_exists(broken_reference)

    fixed_reference = KeyReference("0x3002", "so-pin-fixed")
    fixed_spec = KeySpec(fixed_reference, 2048)
    generation_backend.generate_key(fixed_spec)
    fixed_backend = Pkcs11Backend(
        dataclasses.replace(so_pin_config, signing_pin=SOFTHSM_USER_PIN),
    )
    certificate = fixed_backend.generate_certificate(
        fixed_spec,
        "/CN=so-pin-fixed/",
    )

    assert generation_backend.certificate_exists(fixed_reference)
    certificate_path = tmp_path / "certificate.pem"
    certificate_path.write_bytes(certificate)
    rendered_subject = run(
        ["openssl", "x509", "-in", certificate_path, "-noout", "-subject"],
    )
    assert "so-pin-fixed" in rendered_subject.stdout


SO_LOGIN_TOKEN = f"""#!{sys.executable}
import os
import sys

arguments = sys.argv[1:]
with open(os.environ["SO_TOKEN_ARGV_LOG"], "a") as log:
    log.write(" ".join(arguments) + "\\n")
if "--login-type" in arguments:
    login = arguments.index("--login-type")
    pin = arguments.index("--so-pin")
    source = arguments[pin + 1]
    supplied = os.environ.get(source.removeprefix("env:"), source)
    expected = os.environ["SO_TOKEN_SO_PIN"]
    if arguments[login + 1] != "so" or supplied != expected:
        sys.stderr.write(
            "error: PKCS11 function C_Login failed: rv = CKR_PIN_INCORRECT\\n"
        )
        sys.exit(1)
    for index in sorted((login, pin), reverse=True):
        del arguments[index : index + 2]
    arguments += ["--pin", "env:SO_TOKEN_USER_PIN"]
os.execvp("pkcs11-tool", ["pkcs11-tool", *arguments])
"""


@pytest.fixture
def so_login_token(
    tmp_path: Path,
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, dict[str, str], Path, Path]:
    """
    The contract token behind a pkcs11-tool wrapper that grants signing
    only to a security-officer login with SOFTHSM_SO_PIN, as YubiHSM-style
    providers do, and logs every argument vector it receives.
    """
    _, environment, public_key = pkcs11_token
    tool = tmp_path / "so-login-pkcs11-tool"
    install_executable(tool, SO_LOGIN_TOKEN)
    argv_log = tmp_path / "argv.log"
    token_environment = {
        "SOFTHSM2_CONF": environment["SOFTHSM2_CONF"],
        "SO_TOKEN_ARGV_LOG": str(argv_log),
        "SO_TOKEN_SO_PIN": SOFTHSM_SO_PIN,
        "SO_TOKEN_USER_PIN": SOFTHSM_USER_PIN,
    }
    for name, value in token_environment.items():
        monkeypatch.setenv(name, value)
    return tool, token_environment, public_key, argv_log


def so_pin_backend(
    tool: Path,
    pin: str,
    discovery_pin: str,
) -> Pkcs11Backend:
    return Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            token_label=SOFTHSM_TOKEN_LABEL,
            tool=str(tool),
            pin=pin,
            discovery_pin=discovery_pin,
            use_so_pin=True,
        ),
    )


def test_so_pin_backend_signs_with_the_officer_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, _, public_key, argv_log = so_login_token
    backend = so_pin_backend(tool, SOFTHSM_SO_PIN, SOFTHSM_USER_PIN)
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)
    digest = bytes(range(32))

    assert backend.key_exists(reference)
    signature = backend.sign(
        SignRequest(reference, SHA256_DIGEST_INFO_PREFIX + digest, "rsa-pkcs"),
    )

    assert verifies(der_public_key(public_key), signature, digest)
    arguments = argv_log.read_text()
    assert SOFTHSM_SO_PIN not in arguments
    assert SOFTHSM_USER_PIN not in arguments


def test_so_pin_backend_rejects_a_wrong_officer_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, _, _, _ = so_login_token
    backend = so_pin_backend(tool, "87654321", SOFTHSM_USER_PIN)
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)

    assert backend.key_exists(reference)
    with pytest.raises(subprocess.CalledProcessError) as error:
        backend.sign(SignRequest(reference, b"digest", "rsa-pkcs"))
    assert b"CKR_PIN_INCORRECT" in error.value.stderr


def test_so_pin_backend_discovers_with_the_user_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, _, _, _ = so_login_token
    backend = so_pin_backend(tool, SOFTHSM_SO_PIN, "654321")

    with pytest.raises(subprocess.CalledProcessError) as error:
        backend.key_exists(KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL))
    assert b"CKR_PIN_INCORRECT" in error.value.stderr


@pytest.mark.parametrize(
    ("uses_so_pin", "so_pin", "succeeds"),
    (
        ("y", SOFTHSM_SO_PIN, True),
        ("y", "87654321", False),
        ("n", "87654321", True),
    ),
)
def test_avb_helper_signs_with_the_pin_the_environment_selects(
    tmp_path: Path,
    so_login_token: tuple[Path, dict[str, str], Path, Path],
    uses_so_pin: str,
    so_pin: str,
    succeeds: bool,
) -> None:
    tool, token_environment, public_key, _ = so_login_token
    public_key_pem = tmp_path / "0x2000.pem"
    run(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            public_key,
            "-out",
            public_key_pem,
        ],
    )
    digest = bytes(range(32))

    result = run(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            public_key_pem,
        ],
        env={
            **token_environment,
            "PKCS11_MODULE": str(SOFTHSM_MODULE),
            "PKCS11_TOOL_BIN": str(tool),
            "PKCS11_TOKEN_LABEL": SOFTHSM_TOKEN_LABEL,
            "PKCS11_PIN": SOFTHSM_USER_PIN,
            "PKCS11_SO_PIN": so_pin,
            "SIGNING_USES_SO_PIN": uses_so_pin,
            "KEY_DIR": f"{tmp_path}/",
        },
        input=avb_input(digest),
        check=False,
        text=False,
    )

    if succeeds:
        assert result.returncode == 0, result.stderr
        assert verifies(der_public_key(public_key), result.stdout, digest)
    else:
        assert result.returncode != 0
        assert b"CKR_PIN_INCORRECT" in result.stderr
        assert b"Traceback" not in result.stderr


def test_backend_discovers_without_logging_in_when_configured(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference(SOFTHSM_KEY_ID, SOFTHSM_KEY_LABEL)
    backend.generate_certificate(
        KeySpec(reference, 2048),
        "/CN=Unauthenticated discovery",
    )

    def wrong_pin_backend(list_requires_no_pin: bool) -> Pkcs11Backend:
        return Pkcs11Backend(
            Pkcs11Config(
                module=SOFTHSM_MODULE,
                token_label=SOFTHSM_TOKEN_LABEL,
                pin="654321",
                list_requires_no_pin=list_requires_no_pin,
            ),
        )

    unauthenticated = wrong_pin_backend(True)
    assert unauthenticated.key_exists(reference)
    assert unauthenticated.certificate_exists(reference)
    with pytest.raises(subprocess.CalledProcessError):
        unauthenticated.sign(SignRequest(reference, b"digest", "rsa-pkcs"))
    with pytest.raises(subprocess.CalledProcessError):
        wrong_pin_backend(False).certificate_exists(reference)


@pytest.mark.parametrize(
    ("listing", "listed"),
    (
        (b"Private Key Object; RSA\n  ID:         2000\n", True),
        (b"Certificate Object\n  ID:         8192 (0x20:00)\n", True),
        (b"Private Key Object; RSA\n  ID:         3000\n", False),
        (b"Certificate Object\n  label: releasekey\n", False),
    ),
    ids=("plain", "annotated", "other-id", "no-id"),
)
def test_listing_must_name_the_requested_id(
    listing: bytes,
    listed: bool,
) -> None:
    assert Pkcs11Backend.listing_contains_id(listing, "2000") is listed
