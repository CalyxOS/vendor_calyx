#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from yubihsm.defs import OBJECT
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
    self_signed_certificate,
    serve_connector,
)

if TYPE_CHECKING:
    from signing.metadata import SigningMetadata
    from signing.signing_server import Message
    from signing.vendor_yubihsm import YubiHsmConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
AOSP_TOP = REPO_ROOT.parents[1]
_AOSP_AVBTOOL = AOSP_TOP / "out" / "host" / "linux-x86" / "bin" / "avbtool"
SCRIPTS_DIR = REPO_ROOT / "scripts"
HSM_PROVISIONING_DIR = SCRIPTS_DIR / "hsm_provisioning"
PKCS11_DIR = SCRIPTS_DIR / "pkcs11"
SIGNING_HELPER = PKCS11_DIR / "signing_helper.py"
PAYLOAD_SIGNER = PKCS11_DIR / "payload_signer.py"
APKSIGNER_SIGNING_HELPER = PKCS11_DIR / "apksigner_signing_helper.py"
YUBIHSM_INTERCEPTOR = PKCS11_DIR / "vendor.yubihsm.interceptor.py"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST_METADATA = FIXTURES_DIR / "metadata.py"
KEYGEN_METADATA = FIXTURES_DIR / "keygen-metadata.py"
ID2B_KEYMAP = FIXTURES_DIR / "id2b-bramble-redfin.tsv"
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

    module = tmp_path_factory.mktemp("pkcs11-modules") / "softhsm_pkcs11.so"
    module.touch()
    monkeypatch.setattr(
        sign_environment.SoftHsmVendor,
        "find_pkcs11_module",
        _find_module_at(module),
    )
    return {"softhsm": module}


@pytest.fixture(scope="session")
def aosp_top() -> Path:
    required = (_AOSP_AVBTOOL,)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        pytest.skip(f"the Android tree lacks {', '.join(missing)}")
    return AOSP_TOP


@pytest.fixture(scope="session")
def avbtool(aosp_top: Path) -> Path:
    """The avbtool the Android tree built."""
    return _AOSP_AVBTOOL


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


def load_script(path: Path) -> ModuleType:
    """
    Import the script at path as a module without running its entry
    point.
    """
    name = f"{path.stem.replace('.', '_')}_under_test"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


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


def fake_curl(action: str) -> str:
    """
    Return a curl stand-in that reads -o into out and the URL into link,
    then runs the shell command action.
    """
    return (
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        '  case "$1" in\n'
        "    -o) out=$2; shift 2 ;;\n"
        "    -L) shift ;;\n"
        "    *) link=$1; shift ;;\n"
        "  esac\n"
        "done\n"
        f"{action}\n"
    )


def prepare_ceremony_package(
    root: Path,
    curl: str,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    """Run prepare.package.sh in root/out and leave ceremony.zip there.

    The source directory links vendor/calyx to this repository. root/bin
    leads PATH and holds curl as the given script.
    """
    source = root / "source"
    (source / "vendor").mkdir(parents=True)
    (source / "vendor" / "calyx").symlink_to(REPO_ROOT)
    fake_bin = root / "bin"
    fake_bin.mkdir(exist_ok=True)
    install_executable(fake_bin / "curl", curl)
    out = root / "out"
    out.mkdir()
    return run(
        [HSM_PROVISIONING_DIR / "prepare.package.sh"],
        cwd=out,
        env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "TMPDIR": str(root),
            "SOURCE_DIRECTORY": str(source),
            **environment,
        },
        check=False,
    )


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


def assert_same_public_key(
    actual: PublicKeyTypes,
    expected: PublicKeyTypes,
) -> None:
    """Assert that actual and expected are the same public key."""
    assert actual.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == expected.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


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
    assert_same_public_key(loaded.public_key(), public_key)
    if subject is not None:
        assert loaded.subject.rfc4514_string() == subject


@pytest.fixture
def small_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point METADATA_FILE at the test metadata."""
    monkeypatch.setenv("METADATA_FILE", str(TEST_METADATA))


def shipped_metadata() -> SigningMetadata:
    """Load the metadata the scripts ship with."""
    from signing.metadata import load_metadata

    return load_metadata(SCRIPTS_DIR / "metadata.py")


def file_tree(directory: Path) -> dict[str, bytes]:
    """
    Return the content of every file under directory by its path
    relative to directory, in path order, or nothing if directory does not
    exist.
    """
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


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
    free_records: int = 254,
) -> EmulatedYubiHsm:
    """
    Plug a new device into connector that holds the default
    authentication key and the wrap key YUBIHSM_WRAP_ID, with room for
    free_records objects besides them.
    """
    device = EmulatedYubiHsm(total_records=2 + free_records)
    device.put_wrap_key(YUBIHSM_WRAP_ID)
    connector.plug(device)
    return device


def back_up_yubihsm_key(
    device: EmulatedYubiHsm,
    key_dir: Path,
    key_id: int,
) -> Path:
    """
    Write the asymmetric key key_id of device, wrapped under
    YUBIHSM_WRAP_ID, to its base64 backup in key_dir.

    Returns:
        The path of the backup.
    """
    backup = key_dir / f"{key_id:#06x}-asymmetric-key.yhw"
    backup.write_bytes(
        base64.b64encode(
            device.wrapped(key_id, OBJECT.ASYMMETRIC_KEY, YUBIHSM_WRAP_ID),
        ),
    )
    return backup


def back_up_yubihsm_key_and_certificate(
    device: EmulatedYubiHsm,
    key_dir: Path,
    key_id: int,
    *,
    loaded: bool,
) -> None:
    """
    Put a new asymmetric key key_id on device and back it up with a
    self-signed certificate in key_dir.

    Args:
        device: Device the key is generated on.
        key_dir: Directory for the wrapped key and certificate backups.
        key_id: Object ID of the key and certificate.
        loaded: Whether device keeps the key and gets the certificate
            as well, or keeps neither.
    """
    device.put_asymmetric_key(key_id)
    back_up_yubihsm_key(device, key_dir, key_id)
    certificate = self_signed_certificate()
    (key_dir / f"{key_id:#06x}.x509.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    if loaded:
        device.put_certificate(key_id, certificate)
    else:
        del device.objects[(key_id, OBJECT.ASYMMETRIC_KEY)]


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


BUILD_NUMBER = "2026081500"

PKCS11_ENVIRONMENT = {
    "PKCS11_VENDOR": "softhsm",
    "PKCS11_MODULE": "/dev/null",
    "PKCS11_OPENSSL_ENGINE_LIBRARY_PATH": "/dev/null",
    "PKCS11_PIN": "test-only",
}


def make_release_tree(root: Path) -> Path:
    clear_variables = root / "device/common/clear-factory-images-variables.sh"
    clear_variables.parent.mkdir(parents=True)
    clear_variables.touch()
    factory_images_common = (
        root / "device/common/generate-factory-images-common.sh"
    )
    factory_images_common.write_text(
        'cat "$DEVICE-img-$BUILD.zip" > "$DEVICE-$VERSION-factory-fake.zip"'
        " || exit 1\n",
    )
    _install_fake_release_tools(root)
    _write_avb_custom_keys(root)
    return root


def _write_avb_custom_keys(root: Path) -> None:
    from signing.keymap import load_keymapper
    from signing.metadata import load_metadata

    metadata = load_metadata(TEST_METADATA)
    for keymapper in ("legacy", "id2b"):
        mapper = load_keymapper({"KEYMAPPER": keymapper}, metadata)
        for device in metadata.all_devices:
            key = root / "keys" / mapper.avb_custom_key(device)
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text("avb custom key\n")


def write_target_files_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in (
            ("SYSTEM/build.prop", "ro.build.id=TestBuild\n"),
            (
                "OTA/android-info.txt",
                "require version-bootloader=test-bootloader\n"
                "require version-baseband=test-radio\n",
            ),
        ):
            archive.writestr(
                zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)),
                content,
            )


def _install_fake_release_tools(root: Path) -> None:
    for name, content in (
        ("sign_target_files_apks", "signed-target-files"),
        ("ota_from_target_files", "ota-update-zip"),
        ("img_from_target_files", "factory-img-zip"),
    ):
        install_executable(
            root / "bin" / name,
            '#!/bin/sh\neval "out=\\${$#}"\n'
            f'printf %s "{content}" > "$out"\n',
        )


def run_release(
    release_tree: Path,
    device: str,
    *,
    environment: dict[str, str] | None = None,
    dry_run: bool = True,
    target_files_arg: str | None = "_default_",
) -> subprocess.CompletedProcess[str]:
    """
    Run the release entry point with deterministic orchestration settings.

    Args:
        release_tree: Hermetic working directory containing required support
            files.
        device: Android product whose release flow should be exercised.
        environment: Optional release environment overrides.
        dry_run: Whether release tools should only be rendered instead of
            executed.
        target_files_arg: The target-files argument, "_default_" for the
            usual calyx_<device>-target_files-<build>.zip name and None for
            none.

    Returns:
        The completed release process without enforcing successful status.
    """
    tmpdir = release_tree / "tmp"
    tmpdir.mkdir(exist_ok=True)
    variables = {
        "TMPDIR": str(tmpdir),
        "BUILD_NUMBER": BUILD_NUMBER,
        "KEYMAPPER": "id2b",
        "OTA_ONLY": "y",
        **(environment or {}),
    }
    if dry_run:
        variables["DRY_RUN"] = "y"
    argv: list[str | Path] = [SCRIPTS_DIR / "release.sh", device]
    if target_files_arg == "_default_":
        argv.append(f"calyx_{device}-target_files-{BUILD_NUMBER}.zip")
    elif target_files_arg is not None:
        argv.append(target_files_arg)
    return run(argv, cwd=release_tree, env=variables, check=False)


DRY_RUN_FIXTURES = FIXTURES_DIR / "dry-run"


def normalize_dry_run(stderr: str, tree: Path) -> str:
    return stderr.replace(str(SCRIPTS_DIR), "<scripts>").replace(
        str(tree),
        "<tree>",
    )


METADATA_PLACEHOLDERS = (
    "dtbo",
    "com.android.adservices",
    "packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin",
    "com.google.android.apps.photos",
    "repo",
)


def metadata_with_placeholders(
    source: Path,
    path: Path,
    names: tuple[str, ...] = METADATA_PLACEHOLDERS,
) -> Path:
    text = source.read_text()
    for name in names:
        entry = f'    "{name}",\n'
        assert text.count(entry) == 1, name
        text = text.replace(entry, '    "",\n')
    path.write_text(text)
    return path


class RecordingHandler:
    """
    A signing server handler that records each request and answers with
    response, or raises it if it is an exception.
    """

    def __init__(self, response: Message | Exception) -> None:
        self.response = response
        self.requests: list[Message] = []
        self.closed = 0

    def handle(self, request: Message) -> Message:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed += 1


def _find_module_at(module: Path) -> Callable[[object], str | None]:
    def find_pkcs11_module(self: object) -> str | None:
        return str(module) if module.exists() else None

    return find_pkcs11_module
