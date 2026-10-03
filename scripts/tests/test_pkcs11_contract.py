#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Protocol

import pytest
from conftest import SCRIPTS_DIR, run, run_bytes, run_cli
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from signing.models import (
    KeyReference,
    KeySpec,
    SignRequest,
)
from signing.pkcs11 import Pkcs11Backend, Pkcs11Config

SOFTHSM_MODULE = Path("/usr/lib/pkcs11/libsofthsm2.so")
PKCS11_ENGINE = Path("/usr/lib/engines-3/pkcs11.so")
TOKEN_LABEL = "python-pkcs11-contract"
SO_PIN = "12345678"
USER_PIN = "123456"
KEY_ID = "0x2000"
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420",
)


def test_backend_resolves_a_key_through_its_private_key_label(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token

    assert backend.key_id_for_label("contract-key") == "2000"


def test_backend_exports_a_public_key_when_listing_needs_no_pin(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    _backend, environment, public_key = pkcs11_token
    no_pin_listing = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            pin=USER_PIN,
            token_label=TOKEN_LABEL,
            list_requires_no_pin=True,
            environment={"SOFTHSM2_CONF": environment["SOFTHSM2_CONF"]},
        ),
    )
    reference = KeyReference("0x2000", "contract-key")

    assert no_pin_listing.export_public_key(reference) == (
        public_key.read_bytes()
    )


def test_backend_rejects_missing_private_key_label(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token

    with pytest.raises(KeyError, match="label not found"):
        backend.key_id_for_label("missing")


class SigningRejected(Exception):
    """
    Normalized signing failure raised by a PKCS#11 implementation adapter.
    """


class GenerationRejected(Exception):
    """
    Normalized generation failure raised by a PKCS#11 implementation adapter.
    """


class CertificateRejected(Exception):
    """
    Normalized certificate failure raised by a PKCS#11 implementation adapter.
    """


class Pkcs11SigningImplementation(Protocol):
    """
    Minimal raw RSA signing behavior shared by Bash and Python implementations.
    """

    def sign_digest(self, digest: bytes, key_id: str = KEY_ID) -> bytes:
        """
        Apply RSA PKCS#1 v1.5 signing to a prepared digest.

        Args:
            digest: Prepared digest bytes to sign without additional hashing.
            key_id: Hexadecimal PKCS#11 private-key object ID.

        Returns:
            Raw RSA signature bytes.

        Raises:
            SigningRejected: If the key cannot produce a signature.
        """
        ...


class Pkcs11GenerationImplementation(Protocol):
    """
    Minimal key-generation behavior shared by Bash and Python implementations.
    """

    def generate_key(self, spec: KeySpec) -> None:
        """
        Generate a persistent key pair from a backend-neutral specification.

        Args:
            spec: Object identity, algorithm, and export policy.

        Returns:
            None.

        Raises:
            GenerationRejected: If the key cannot be generated.
        """
        ...


class Pkcs11CertificateImplementation(Protocol):
    """
    Minimal certificate behavior shared by Bash and Python implementations.
    """

    def generate_certificate(self, spec: KeySpec, subject: str) -> bytes:
        """
        Create and import a self-signed certificate for a token-held key.

        Args:
            spec: Identity and algorithm of an existing private key.
            subject: Distinguished name for the certificate.

        Returns:
            PEM-encoded certificate bytes.

        Raises:
            CertificateRejected: If the certificate cannot be generated.
        """
        ...


class BashPkcs11SigningImplementation:
    """
    Exercise signing through the existing ``pkcs11-tool`` Bash helper.
    """

    def __init__(self, environment: dict[str, str]) -> None:
        """
        Configure the Bash helper environment.

        Args:
            environment: SoftHSM and generic PKCS#11 environment variables.

        Returns:
            None.
        """
        self.environment = {
            **environment,
            "FIND_KEYS_BY_ID": "y",
            "KEY_DIR": "keys/",
            "STRIP_HEX_KEY_ID_PREFIX": "y",
        }

    def sign_digest(self, digest: bytes, key_id: str = KEY_ID) -> bytes:
        """
        Sign a digest through ``signing_helper.pkcs11-tool.sh``.

        Args:
            digest: Prepared SHA-256 digest bytes.
            key_id: Hexadecimal PKCS#11 private-key object ID.

        Returns:
            Raw RSA signature bytes.

        Raises:
            SigningRejected: If the helper exits unsuccessfully.
        """
        result = run_bytes(
            [
                SCRIPTS_DIR / "pkcs11/signing_helper.pkcs11-tool.sh",
                "SHA256_RSA2048",
                f"keys/{key_id}.pem",
            ],
            env=self.environment,
            input_data=b"\x00" * 205 + digest,
            check=False,
        )
        if result.returncode:
            raise SigningRejected(result.stderr.decode(errors="replace"))
        return result.stdout


class PythonPkcs11SigningImplementation:
    """
    Exercise signing through ``Pkcs11Backend``.
    """

    def __init__(self, backend: Pkcs11Backend) -> None:
        """
        Retain a configured Python PKCS#11 backend.

        Args:
            backend: Backend connected to the contract-test token.

        Returns:
            None.
        """
        self.backend = backend

    def sign_digest(self, digest: bytes, key_id: str = KEY_ID) -> bytes:
        """
        Sign a digest through ``Pkcs11Backend``.

        Args:
            digest: Prepared digest bytes to sign without additional hashing.
            key_id: Hexadecimal PKCS#11 private-key object ID.

        Returns:
            Raw RSA signature bytes.

        Raises:
            SigningRejected: If the backend cannot produce a signature.
        """
        reference = KeyReference(key_id, "contract-key")
        try:
            return self.backend.sign(SignRequest(reference, digest, "rsa-pkcs"))
        except (
            KeyError,
            ValueError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            raise SigningRejected(str(error)) from error


class BashPkcs11GenerationImplementation:
    """
    Exercise generation through the existing generic Bash PKCS#11 functions.
    """

    def __init__(self, environment: dict[str, str]) -> None:
        """
        Configure the Bash key-generation environment.

        Args:
            environment: SoftHSM and generic PKCS#11 environment variables.

        Returns:
            None.
        """
        self.environment = {
            **environment,
            "STRIP_HEX_KEY_ID_PREFIX": "y",
        }

    def generate_key(self, spec: KeySpec) -> None:
        """
        Generate a key through ``generate_keypair_pkcs11()``.

        Args:
            spec: Object identity, algorithm, and export policy.

        Returns:
            None.

        Raises:
            GenerationRejected: If generation fails.
        """
        algorithm = f"RSA:{spec.key_size}"
        extraction_arguments = "--sensitive"
        if spec.exportable:
            extraction_arguments += " --extractable"
        script = r"""
set -euo pipefail
source "$1"
refresh_pkcs11_tool_args
EXTRACTION_ARGS="$5"
generate_keypair_pkcs11 "$2" "$3" "$6"
"""
        result = run(
            [
                "bash",
                "-c",
                script,
                "pkcs11-generation-contract",
                SCRIPTS_DIR / "pkcs11/keygen.include.sh",
                spec.reference.key_id,
                spec.reference.label,
                "core",
                extraction_arguments,
                algorithm,
            ],
            env=self.environment,
            check=False,
        )
        if result.returncode:
            raise GenerationRejected(result.stderr)


class PythonPkcs11GenerationImplementation:
    """
    Exercise generation through ``Pkcs11Backend``.
    """

    def __init__(self, backend: Pkcs11Backend) -> None:
        """
        Retain a configured Python PKCS#11 backend.

        Args:
            backend: Backend connected to the contract-test token.

        Returns:
            None.
        """
        self.backend = backend

    def generate_key(self, spec: KeySpec) -> None:
        """
        Generate a key through ``Pkcs11Backend``.

        Args:
            spec: Object identity, algorithm, and export policy.

        Returns:
            None.

        Raises:
            GenerationRejected: If the backend rejects generation.
        """
        try:
            self.backend.generate_key(spec)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise GenerationRejected(str(error)) from error


class BashPkcs11CertificateImplementation:
    """
    Exercise certificates through the existing generic Bash PKCS#11 functions.
    """

    def __init__(self, environment: dict[str, str]) -> None:
        """
        Configure the Bash certificate environment.

        Args:
            environment: SoftHSM, OpenSSL engine, and PKCS#11 settings.

        Returns:
            None.
        """
        self.environment = {
            **environment,
            "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
            "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": str(PKCS11_ENGINE),
            "STRIP_HEX_KEY_ID_PREFIX": "y",
        }

    def generate_certificate(self, spec: KeySpec, subject: str) -> bytes:
        """
        Generate and import a certificate through ``generate_cert_pkcs11()``.

        Args:
            spec: Identity and algorithm of an existing private key.
            subject: Distinguished name for the certificate.

        Returns:
            PEM-encoded certificate bytes.

        Raises:
            CertificateRejected: If generation fails.
        """
        algorithm = f"RSA:{spec.key_size}"
        script = r"""
set -euo pipefail
source "$1"
refresh_pkcs11_tool_args
CERT_EXPIRY_DAYS=1
SIGNING_SUBJECT_TEMPLATE="$5"
generate_cert_pkcs11 "$2" "$2" "$3" "$4"
"""
        generated = run(
            [
                "bash",
                "-c",
                script,
                "pkcs11-certificate-contract",
                SCRIPTS_DIR / "pkcs11/keygen.include.sh",
                spec.reference.key_id,
                "core",
                algorithm,
                subject,
            ],
            env=self.environment,
            check=False,
        )
        if generated.returncode:
            raise CertificateRejected(generated.stderr)
        certificate = run_bytes(
            [
                "pkcs11-tool",
                "--module",
                SOFTHSM_MODULE,
                "--token-label",
                TOKEN_LABEL,
                "--pin",
                "env:PKCS11_PIN",
                "--read-object",
                "--type",
                "cert",
                "--id",
                spec.reference.key_id.removeprefix("0x"),
            ],
            env=self.environment,
        )
        encoded = run_bytes(
            ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
            input_data=certificate.stdout,
        )
        return encoded.stdout


class PythonPkcs11CertificateImplementation:
    """
    Exercise certificates through ``Pkcs11Backend``.
    """

    def __init__(self, backend: Pkcs11Backend) -> None:
        """
        Retain a configured Python PKCS#11 backend.

        Args:
            backend: Backend connected to the contract-test token.

        Returns:
            None.
        """
        self.backend = backend

    def generate_certificate(self, spec: KeySpec, subject: str) -> bytes:
        """
        Generate and import a certificate through ``Pkcs11Backend``.

        Args:
            spec: Identity and algorithm of an existing private key.
            subject: Distinguished name for the certificate.

        Returns:
            PEM-encoded certificate bytes.

        Raises:
            CertificateRejected: If the backend rejects generation.
        """
        try:
            return self.backend.generate_certificate(spec, subject)
        except (
            KeyError,
            ValueError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            raise CertificateRejected(str(error)) from error


@pytest.fixture
def pkcs11_token(tmp_path: Path) -> tuple[Pkcs11Backend, dict[str, str], Path]:
    missing = [
        executable
        for executable in ("softhsm2-util", "pkcs11-tool")
        if shutil.which(executable) is None
    ]
    for path in (SOFTHSM_MODULE, PKCS11_ENGINE):
        if not path.is_file():
            missing.append(str(path))
    if missing:
        pytest.skip(
            f"SoftHSM test dependencies are missing: {', '.join(missing)}",
        )

    token_directory = tmp_path / "tokens"
    token_directory.mkdir()
    softhsm_config = tmp_path / "softhsm2.conf"
    softhsm_config.write_text(
        f"""directories.tokendir = {token_directory}
objectstore.backend = file
log.level = WARNING
slots.removable = true
slots.mechanisms = ALL
library.reset_on_fork = false
""",
    )
    environment = {
        "SOFTHSM2_CONF": str(softhsm_config),
        "PKCS11_MODULE": str(SOFTHSM_MODULE),
        "PKCS11_TOOL_BIN": str(shutil.which("pkcs11-tool")),
        "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_PIN": USER_PIN,
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
    generated = run(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--keypairgen",
            "--key-type",
            "rsa:2048",
            "--id",
            KEY_ID.removeprefix("0x"),
            "--label",
            "contract-key",
        ],
        env=environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    backend = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            pin=USER_PIN,
            token_label=TOKEN_LABEL,
            openssl_engine=PKCS11_ENGINE,
            certificate_days=1,
            environment={"SOFTHSM2_CONF": str(softhsm_config)},
        ),
    )
    public_key = tmp_path / "public.der"
    public_key.write_bytes(
        backend.export_public_key(KeyReference(KEY_ID, "contract-key")),
    )
    return backend, environment, public_key


@pytest.fixture(params=("bash", "python"))
def pkcs11_signer(
    request: pytest.FixtureRequest,
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> tuple[Pkcs11SigningImplementation, Path]:
    backend, environment, public_key = pkcs11_token
    if request.param == "bash":
        return BashPkcs11SigningImplementation(environment), public_key
    return PythonPkcs11SigningImplementation(backend), public_key


@pytest.fixture(params=("bash", "python"))
def pkcs11_generator(
    request: pytest.FixtureRequest,
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> tuple[Pkcs11GenerationImplementation, Pkcs11Backend]:
    backend, environment, _ = pkcs11_token
    if request.param == "bash":
        return BashPkcs11GenerationImplementation(environment), backend
    return PythonPkcs11GenerationImplementation(backend), backend


@pytest.fixture(params=("bash", "python"))
def pkcs11_certificate_manager(
    request: pytest.FixtureRequest,
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> tuple[Pkcs11CertificateImplementation, Pkcs11Backend]:
    backend, environment, _ = pkcs11_token
    if request.param == "bash":
        return BashPkcs11CertificateImplementation(environment), backend
    return PythonPkcs11CertificateImplementation(backend), backend


def test_pkcs11_raw_rsa_signing_contract(
    pkcs11_signer: tuple[Pkcs11SigningImplementation, Path],
    tmp_path: Path,
) -> None:
    implementation, public_key = pkcs11_signer
    digest = bytes(range(32))
    signature = tmp_path / "signature.bin"
    digest_file = tmp_path / "digest.bin"
    signature.write_bytes(implementation.sign_digest(digest))
    digest_file.write_bytes(digest)

    verified = run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            public_key,
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


def test_pkcs11_raw_rsa_signing_contract_rejects_missing_key(
    pkcs11_signer: tuple[Pkcs11SigningImplementation, Path],
) -> None:
    implementation, _ = pkcs11_signer

    with pytest.raises(SigningRejected):
        implementation.sign_digest(bytes(range(32)), "0xffff")


def test_pkcs11_backend_discovers_objects(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    reference = KeyReference(KEY_ID, "contract-key")

    assert backend.key_exists(reference)
    assert not backend.certificate_exists(reference)


def test_pkcs11_backend_rejects_invalid_id_and_mechanism(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, _, _ = pkcs11_token
    invalid_id = KeyReference("0x123", "contract-key")
    valid = KeyReference(KEY_ID, "contract-key")

    with pytest.raises(ValueError, match="invalid PKCS#11 key ID"):
        backend.key_exists(invalid_id)
    with pytest.raises(
        ValueError,
        match="unsupported PKCS#11 signing mechanism",
    ):
        backend.sign(SignRequest(valid, b"data", "md5"))


@pytest.mark.parametrize("key_size", (2048, 3072))
def test_pkcs11_key_generation_contract(
    pkcs11_generator: tuple[Pkcs11GenerationImplementation, Pkcs11Backend],
    tmp_path: Path,
    key_size: int,
) -> None:
    implementation, backend = pkcs11_generator
    reference = KeyReference("0x3000", "generated-key")
    implementation.generate_key(KeySpec(reference, key_size, exportable=True))

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
            TOKEN_LABEL,
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
        (KEY_ID, 2048),
        ("0x2100", 3072),
    ),
)
def test_pkcs11_certificate_contract(
    pkcs11_certificate_manager: tuple[
        Pkcs11CertificateImplementation,
        Pkcs11Backend,
    ],
    tmp_path: Path,
    key_id: str,
    key_size: int,
) -> None:
    implementation, backend = pkcs11_certificate_manager
    reference = KeyReference(key_id, "contract-key")
    spec = KeySpec(reference, key_size)
    if key_id != KEY_ID:
        backend.generate_key(spec)
    subject = "/C=US/O=Calyx Institute/CN=Shared PKCS11 certificate"
    certificate = tmp_path / "certificate.pem"
    certificate.write_bytes(implementation.generate_certificate(spec, subject))

    assert backend.certificate_exists(reference)
    rendered_subject = run(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
    )
    assert rendered_subject.stdout.strip() == (
        "subject=CN=Shared PKCS11 certificate,O=Calyx Institute,C=US"
    )
    verified = run(
        ["openssl", "verify", "-CAfile", certificate, certificate],
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    certificate_public_key = run(
        ["openssl", "x509", "-in", certificate, "-pubkey", "-noout"],
    )
    token_public_key = run_bytes(
        ["openssl", "pkey", "-pubin", "-inform", "DER", "-pubout"],
        input_data=backend.export_public_key(reference),
    )
    assert certificate_public_key.stdout.encode() == token_public_key.stdout


def test_pkcs11_backend_rejects_duplicate_certificates(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, environment, _ = pkcs11_token
    reference = KeyReference(KEY_ID, "contract-key")
    spec = KeySpec(reference, 2048)
    first = backend.generate_certificate(spec, "/CN=First certificate")

    with pytest.raises(ValueError, match="certificate already exists"):
        backend.generate_certificate(spec, "/CN=Second certificate")

    stored = run_bytes(
        [
            "pkcs11-tool",
            "--module",
            SOFTHSM_MODULE,
            "--token-label",
            TOKEN_LABEL,
            "--pin",
            "env:PKCS11_PIN",
            "--read-object",
            "--type",
            "cert",
            "--id",
            KEY_ID.removeprefix("0x"),
        ],
        env=environment,
    )
    stored_pem = run_bytes(
        ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
        input_data=stored.stdout,
    )
    assert stored_pem.stdout == first


def test_so_pin_backend_refuses_a_key_id_whose_private_key_exists(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    generation_backend, environment, _ = pkcs11_token
    so_pin_backend = Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            token_label=TOKEN_LABEL,
            openssl_engine=PKCS11_ENGINE,
            pin=SO_PIN,
            use_so_pin=True,
            discovery_pin=USER_PIN,
            environment={"SOFTHSM2_CONF": environment["SOFTHSM2_CONF"]},
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
            TOKEN_LABEL,
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


def test_pkcs11_cli_complete_lifecycle(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
    tmp_path: Path,
) -> None:
    _, token_environment, _ = pkcs11_token
    secret = "123456"
    environment = {
        **token_environment,
        "CLI_PKCS11_PIN": secret,
    }
    common: list[str | Path] = [
        "--module",
        SOFTHSM_MODULE,
        "--token-label",
        TOKEN_LABEL,
        "--pin-env",
        "CLI_PKCS11_PIN",
        "--openssl-engine",
        PKCS11_ENGINE,
        "--certificate-days",
        "1",
        "--key-id",
        "0x4000",
        "--label",
        "cli-key",
    ]

    generated = run_cli(
        [
            "generate-key",
            *common,
            "--algorithm",
            "RSA",
            "--key-size",
            "2048",
        ],
        env=environment,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    assert secret not in generated.stderr

    certificate = tmp_path / "cli-certificate.pem"
    certified = run_cli(
        [
            "generate-certificate",
            *common,
            "--algorithm",
            "RSA",
            "--key-size",
            "2048",
            "--subject",
            "/CN=PKCS11 CLI",
            "--output",
            certificate,
        ],
        env=environment,
        check=False,
    )
    assert certified.returncode == 0, certified.stderr
    assert secret not in certified.stderr

    key_exists = run_cli(
        ["key-exists", *common],
        env=environment,
        check=False,
    )
    certificate_exists = run_cli(
        ["certificate-exists", *common],
        env=environment,
        check=False,
    )
    assert key_exists.stdout == "yes\n"
    assert certificate_exists.stdout == "yes\n"


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
) -> tuple[Path, dict[str, str], Path, Path]:
    """
    The contract token behind a pkcs11-tool wrapper that grants signing
    only to a security-officer login with SO_PIN, as YubiHSM-style
    providers do, and logs every argument vector it receives.
    """
    _, environment, public_key = pkcs11_token
    tool = tmp_path / "so-login-pkcs11-tool"
    tool.write_text(SO_LOGIN_TOKEN)
    tool.chmod(0o755)
    argv_log = tmp_path / "argv.log"
    token_environment = {
        "SOFTHSM2_CONF": environment["SOFTHSM2_CONF"],
        "SO_TOKEN_ARGV_LOG": str(argv_log),
        "SO_TOKEN_SO_PIN": SO_PIN,
        "SO_TOKEN_USER_PIN": USER_PIN,
    }
    return tool, token_environment, public_key, argv_log


def rsa_signature_verifies(
    public_key_der: Path,
    digest: bytes,
    signature: bytes,
) -> bool:
    public_key = serialization.load_der_public_key(public_key_der.read_bytes())
    assert isinstance(public_key, rsa.RSAPublicKey)
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    return True


def so_pin_backend(
    tool: Path,
    environment: dict[str, str],
    pin: str,
    discovery_pin: str,
) -> Pkcs11Backend:
    return Pkcs11Backend(
        Pkcs11Config(
            module=SOFTHSM_MODULE,
            token_label=TOKEN_LABEL,
            tool=str(tool),
            pin=pin,
            discovery_pin=discovery_pin,
            use_so_pin=True,
            environment=environment,
        ),
    )


def test_so_pin_backend_signs_with_the_officer_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, environment, public_key, argv_log = so_login_token
    backend = so_pin_backend(tool, environment, SO_PIN, USER_PIN)
    reference = KeyReference(KEY_ID, "contract-key")
    digest = bytes(range(32))

    assert backend.key_exists(reference)
    signature = backend.sign(
        SignRequest(reference, SHA256_DIGEST_INFO_PREFIX + digest, "rsa-pkcs"),
    )

    assert rsa_signature_verifies(public_key, digest, signature)
    arguments = argv_log.read_text()
    assert SO_PIN not in arguments
    assert USER_PIN not in arguments


def test_so_pin_backend_rejects_a_wrong_officer_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, environment, _, _ = so_login_token
    backend = so_pin_backend(tool, environment, "87654321", USER_PIN)
    reference = KeyReference(KEY_ID, "contract-key")

    assert backend.key_exists(reference)
    with pytest.raises(subprocess.CalledProcessError) as error:
        backend.sign(SignRequest(reference, b"digest", "rsa-pkcs"))
    assert b"CKR_PIN_INCORRECT" in error.value.stderr


def test_so_pin_backend_discovers_with_the_user_pin(
    so_login_token: tuple[Path, dict[str, str], Path, Path],
) -> None:
    tool, environment, _, _ = so_login_token
    backend = so_pin_backend(tool, environment, SO_PIN, "654321")

    with pytest.raises(subprocess.CalledProcessError) as error:
        backend.key_exists(KeyReference(KEY_ID, "contract-key"))
    assert b"CKR_PIN_INCORRECT" in error.value.stderr


@pytest.mark.parametrize(
    ("uses_so_pin", "so_pin", "succeeds"),
    (("y", SO_PIN, True), ("y", "87654321", False), ("n", "87654321", True)),
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

    result = run_bytes(
        [
            SCRIPTS_DIR / "pkcs11" / "signing_helper.py",
            "SHA256_RSA2048",
            public_key_pem,
        ],
        env={
            **token_environment,
            "PKCS11_MODULE": str(SOFTHSM_MODULE),
            "PKCS11_TOOL_BIN": str(tool),
            "PKCS11_TOKEN_LABEL": TOKEN_LABEL,
            "PKCS11_PIN": USER_PIN,
            "PKCS11_SO_PIN": so_pin,
            "SIGNING_USES_SO_PIN": uses_so_pin,
            "KEY_ID": KEY_ID,
            "OPENSSL_PKCS11_URI_USES_HEX_KEY_ID": "y",
        },
        input_data=(
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + SHA256_DIGEST_INFO_PREFIX
            + digest
        ),
        check=False,
    )

    if succeeds:
        assert result.returncode == 0, result.stderr
        assert rsa_signature_verifies(public_key, digest, result.stdout)
    else:
        assert result.returncode != 0
        assert b"CKR_PIN_INCORRECT" in result.stderr


def test_backend_discovers_without_logging_in_when_configured(
    pkcs11_token: tuple[Pkcs11Backend, dict[str, str], Path],
) -> None:
    backend, environment, _ = pkcs11_token
    reference = KeyReference(KEY_ID, "contract-key")
    backend.generate_certificate(
        KeySpec(reference, 2048),
        "/CN=Unauthenticated discovery",
    )

    def wrong_pin_backend(list_requires_no_pin: bool) -> Pkcs11Backend:
        return Pkcs11Backend(
            Pkcs11Config(
                module=SOFTHSM_MODULE,
                token_label=TOKEN_LABEL,
                pin="654321",
                list_requires_no_pin=list_requires_no_pin,
                environment={"SOFTHSM2_CONF": environment["SOFTHSM2_CONF"]},
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
