#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
    serve_connector,
)

if TYPE_CHECKING:
    from signing.vendor_yubihsm import YubiHsmConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
TEST_METADATA = Path(__file__).parent / "fixtures" / "metadata.py"
KEYGEN_METADATA = Path(__file__).parent / "fixtures" / "keygen-metadata.py"
ID2B_KEYMAP = Path(__file__).parent / "fixtures" / "id2b-bramble-redfin.tsv"
sys.path.insert(0, str(SCRIPTS_DIR))

_YUBIHSM_SPEC = importlib.util.find_spec("yubihsm")
assert _YUBIHSM_SPEC is not None and _YUBIHSM_SPEC.origin is not None
YUBIHSM_SDK = str(Path(_YUBIHSM_SPEC.origin).resolve().parents[1])


@pytest.fixture
def yubihsm() -> Iterator[Connector]:
    """An emulated YubiHSM 2 behind a local yubihsm-connector stand-in."""
    with serve_connector() as connector:
        connector.plug(EmulatedYubiHsm())
        yield connector


@pytest.fixture(autouse=True)
def fake_pkcs11_modules(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    from signing import sign_environment

    directory = tmp_path_factory.mktemp("pkcs11-modules")
    modules: dict[str, Path] = {}
    for vendor in ("yubihsm", "softhsm"):
        module = directory / f"{vendor}_pkcs11.so"
        module.touch()
        modules[vendor] = module
    for vendor, module in modules.items():
        monkeypatch.setattr(
            sign_environment.VENDORS[vendor],
            "find_pkcs11_module",
            _find_module_at(module),
        )
    return modules


@pytest.fixture(scope="session")
def aosp_top() -> Path:
    top = REPO_ROOT.parents[1]
    required = (top / "out" / "host" / "linux-x86" / "bin" / "avbtool",)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        pytest.skip(f"the Android tree lacks {', '.join(missing)}")
    return top


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_until(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def aosp_jar_command(aosp_top: Path, jar_name: str) -> list[str]:
    host = aosp_top / "out" / "host" / "linux-x86"
    java = (
        aosp_top / "prebuilts" / "jdk" / "jdk21" / "linux-x86" / "bin" / "java"
    )
    jar = host / "framework" / jar_name
    missing = [str(path) for path in (java, jar) if not path.is_file()]
    if missing:
        pytest.skip(f"the Android tree lacks {', '.join(missing)}")
    return [
        str(java),
        f"-Djava.library.path={host / 'lib64'}",
        "-jar",
        str(jar),
    ]


def default_signal_dispositions() -> None:
    """
    Give a child the default SIGINT, SIGHUP and SIGTERM handling, which a
    test run under nohup or in the background hands down as ignored.
    """
    for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, signal.SIG_DFL)


@overload
def run(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input: str | None = None,
    check: bool = True,
    text: Literal[True] = True,
) -> subprocess.CompletedProcess[str]: ...


@overload
def run(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
    check: bool = True,
    text: Literal[False],
) -> subprocess.CompletedProcess[bytes]: ...


def run(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input: str | bytes | None = None,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    """
    Run a command with env added to the current environment and capture
    its output, as text unless text is False.
    """
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=process_env,
        input=input,
        check=check,
        text=text,
        capture_output=True,
        preexec_fn=default_signal_dispositions,
    )


SOFTHSM_MODULE = Path("/usr/lib/pkcs11/libsofthsm2.so")
PKCS11_ENGINE = Path("/usr/lib/engines-3/pkcs11.so")
SOFTHSM_TOKEN_LABEL = "softhsm-rsa-key-test"
SOFTHSM_SO_PIN = "12345678"
SOFTHSM_USER_PIN = "123456"
SOFTHSM_KEY_ID = "0x2000"
SOFTHSM_KEY_LABEL = "test-key"
YUBIHSM_WRAP_ID = 0x0010


def require_softhsm(*, engine: bool = False) -> None:
    """
    Skip the calling test unless softhsm2-util, pkcs11-tool and the
    SoftHSM module are installed, and the OpenSSL PKCS#11 engine as well
    when engine is True.
    """
    missing = [
        executable
        for executable in ("softhsm2-util", "pkcs11-tool")
        if shutil.which(executable) is None
    ]
    missing.extend(
        str(path)
        for path in (SOFTHSM_MODULE, *((PKCS11_ENGINE,) if engine else ()))
        if not path.is_file()
    )
    if missing:
        pytest.skip(
            f"SoftHSM test dependencies are missing: {', '.join(missing)}",
        )


def softhsm_environment(
    directory: Path,
    label: str,
    *,
    initialize: bool = True,
) -> dict[str, str]:
    """
    Configure SoftHSM to keep its tokens in directory/tokens and return
    the environment that reaches the token label with SOFTHSM_USER_PIN.

    Args:
        directory: Directory for softhsm2.conf and the token directory.
        label: Token label the environment names.
        initialize: Whether to initialize the token with the test PINs.

    Returns:
        SOFTHSM2_CONF and the PKCS11_* variables for the token.
    """
    token_directory = directory / "tokens"
    token_directory.mkdir(parents=True)
    softhsm_config = directory / "softhsm2.conf"
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
        "PKCS11_TOKEN_LABEL": label,
        "PKCS11_PIN": SOFTHSM_USER_PIN,
    }
    if initialize:
        run(
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                label,
                "--so-pin",
                SOFTHSM_SO_PIN,
                "--pin",
                SOFTHSM_USER_PIN,
            ],
            env=environment,
        )
    return environment


@pytest.fixture
def softhsm_rsa_key(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """
    A SoftHSM2 token holding an RSA-2048 keypair under SOFTHSM_KEY_ID,
    plus the environment the PKCS#11 helpers need to reach it.
    """
    require_softhsm()
    environment = softhsm_environment(tmp_path, SOFTHSM_TOKEN_LABEL)
    token: list[str | Path] = [
        "pkcs11-tool",
        "--module",
        SOFTHSM_MODULE,
        "--token-label",
        SOFTHSM_TOKEN_LABEL,
        "--pin",
        "env:PKCS11_PIN",
    ]
    key_id = SOFTHSM_KEY_ID.removeprefix("0x")
    run(
        [
            *token,
            "--keypairgen",
            "--key-type",
            "rsa:2048",
            "--id",
            key_id,
            "--label",
            SOFTHSM_KEY_LABEL,
        ],
        env=environment,
    )
    exported = run(
        [*token, "--read-object", "--type", "pubkey", "--id", key_id],
        env=environment,
        text=False,
    )
    public_key = tmp_path / "public.der"
    public_key.write_bytes(exported.stdout)
    return environment, public_key


def assert_certificate_of(
    public_key: PublicKeyTypes,
    certificate: Path,
    subject: str | None = None,
) -> None:
    """
    Assert that a PEM certificate certifies public_key.

    Args:
        public_key: Public key the certificate must carry.
        certificate: PEM certificate file.
        subject: RFC 4514 subject the certificate must have, if given.
    """
    loaded = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert loaded.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if subject is not None:
        assert loaded.subject.rfc4514_string() == subject


def install_executable(path: Path, text: str) -> Path:
    """
    Write text to path, creating its directory, and make it executable.

    Returns:
        path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def yubihsm_config(
    connector: Connector,
    *,
    auth_key: int = DEFAULT_AUTHKEY_ID,
    password: str = DEFAULT_PASSWORD,
) -> YubiHsmConfig:
    """
    Return the settings that reach the emulated YubiHSM behind connector
    with auth_key and password, wrapping under YUBIHSM_WRAP_ID.
    """
    from signing.vendor_yubihsm import YubiHsmConfig

    return YubiHsmConfig(
        connector_url=connector.url,
        auth_key=f"{auth_key:#06x}",
        password=password,
        wrap_id=f"{YUBIHSM_WRAP_ID:#06x}",
    )


def plug_yubihsm(
    connector: Connector,
    *,
    total_records: int = 256,
) -> EmulatedYubiHsm:
    """
    Plug a new device with room for total_records objects into connector.
    It holds the default authentication key and the wrap key
    YUBIHSM_WRAP_ID, two objects in all.
    """
    device = EmulatedYubiHsm(total_records=total_records)
    device.put_wrap_key(YUBIHSM_WRAP_ID)
    connector.plug(device)
    return device


T = TypeVar("T")


def stub(value: T) -> Callable[..., T]:
    """
    Return a callable that ignores its arguments and returns value.

    Args:
        value: What every call returns.

    Returns:
        The callable.
    """

    def stubbed(*args: object, **kwargs: object) -> T:
        return value

    return stubbed


def parameter_id(request: pytest.FixtureRequest) -> str:
    """
    Return the id of the parameter set the requesting test runs with.

    Args:
        request: The requesting test's fixture request.

    Returns:
        The id pytest gave the parameter set.
    """
    # FixtureRequest.node carries no type annotation.
    node: pytest.Function = getattr(request, "node")
    return node.callspec.id


def _find_module_at(module: Path) -> Callable[[object], str | None]:
    def find_pkcs11_module(self: object) -> str | None:
        return str(module) if module.exists() else None

    return find_pkcs11_module
