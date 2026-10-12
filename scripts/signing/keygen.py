#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Release key generation for the vendor keygen scripts, which generate the
keys on a PKCS#11 token or YubiHSM and export their certificates and public
keys.
"""

from __future__ import annotations

import abc
import base64
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from pathlib import Path

from . import sign_environment
from .confirmation import ask_variable
from .files import write_file_atomically
from .keymap import Keymapper, load_keymapper
from .metadata import SigningMetadata, load_metadata
from .models import KeyReference, KeySpec
from .pkcs11 import (
    Pkcs11Backend,
    Pkcs11Config,
    initialize_pkcs11_token,
    is_any_pkcs11_token_initialized,
)
from .sign_orchestration import load_devices_file
from .vendor_yubihsm import (
    YubiHsmConfig,
    attest_key,
    export_wrapped_key,
    extract_and_save_audit_log,
    generate_asymmetric_key,
    get_certificate,
    get_device_identity,
    get_loaded_key_ids,
    get_public_key,
    limit_ondemand_objects,
)

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
DEFAULT_TOKEN_LABEL = "androsign"
DEFAULT_SUBJECT_TEMPLATE = (
    "/C=US/ST=New York/L=Rochester/O=Android/OU=Android/CN=_KEY_LABEL_"
    "/emailAddress=android@example.com/"
)


class KeygenError(RuntimeError):
    """A keygen step failed after printing its own explanation."""


class KeygenDriver(abc.ABC):
    """The per-vendor steps of key generation."""

    uses_pkcs11_to_generate_key = False
    uses_pkcs11_to_generate_cert = False

    def __init__(
        self,
        environment: MutableMapping[str, str],
        key_out_dir: Path,
    ) -> None:
        self.environment = environment
        self.key_out_dir = key_out_dir
        self.keymapper: Keymapper | None = None

    def initialize_pre_metadata(self) -> None:
        """Prepare what metadata loading needs. Does nothing by default."""

    def initialize_post_metadata(self) -> None:
        """Prepare key generation. Does nothing by default."""

    @abc.abstractmethod
    def key_exists(self, mapped_value: str) -> bool:
        """Return whether the key a keymapper value names exists."""

    def complete_existing_certificate(
        self,
        mapped_value: str,
        key_type: str,
    ) -> None:
        """
        Derive the missing public key files of an AVB or APEX key from its
        certificate in the output directory, as left by a run that failed
        after writing the certificate. Writes nothing under DRY_RUN=y.
        """
        if self.environment.get("DRY_RUN") == "y":
            return
        certificate = self.key_out_dir / f"{mapped_value}.x509.pem"
        if certificate.exists():
            export_public_keys(
                self.environment,
                certificate,
                key_type,
                self.derived_public_key_written,
                quiet=True,
            )

    def derived_public_key_written(self, path: Path) -> None:
        """
        Keep a public key file that complete_existing_certificate() wrote.
        Does nothing by default.
        """

    @abc.abstractmethod
    def cert_exists(self, mapped_value: str) -> bool:
        """Return whether the certificate a keymapper value names exists."""

    def complete_existing_key(self, mapped_value: str) -> None:
        """
        Finish what generating an existing key left undone. Does nothing by
        default.
        """

    @abc.abstractmethod
    def generate_keypair(
        self,
        key_id: str,
        label: str,
        algorithm: str,
    ) -> None:
        """Generate one key pair."""

    @abc.abstractmethod
    def generate_cert(
        self,
        key_id: str,
        key_type: str,
        algorithm: str,
    ) -> None:
        """Generate and export one key's certificate."""

    def key_algorithm(self, key_type: str) -> str:
        """Return RSA of RSA_KEY_SIZE bits, 4096 by default."""
        return f"RSA:{self.environment.get('RSA_KEY_SIZE') or 4096}"

    def cleanup(self) -> bool:
        """
        Release what the driver set up, and return whether that succeeded.
        Succeeds without doing anything by default.
        """
        return True

    def tool(self, name: str, variable: str) -> str | None:
        """Return the tool a variable names, or the one on PATH."""
        return self.environment.get(variable) or shutil.which(name)


def initialize_post_metadata_common(
    environment: MutableMapping[str, str],
    driver: KeygenDriver,
) -> None:
    """
    Find openssl and avbtool and apply the defaults of PKCS#11 generation.

    Raises:
        KeygenError: If openssl or avbtool cannot be found.
    """
    missing = False
    openssl = driver.tool("openssl", "OPENSSL_BIN")
    if openssl is None:
        print(
            "Please install openssl, or set OPENSSL_BIN to its path.",
            file=sys.stderr,
        )
        missing = True
    else:
        environment["OPENSSL_BIN"] = openssl
    avbtool = driver.tool("avbtool", "AVBTOOL_BIN")
    if avbtool is None:
        candidate = Path.cwd() / "bin" / "avbtool"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            avbtool = str(candidate)
        else:
            print(
                "Could not find avbtool. Please set AVBTOOL_BIN to its "
                "location, or run this from otatools-keys-package's "
                "extracted folder.",
                file=sys.stderr,
            )
            missing = True
    if avbtool is not None:
        environment["AVBTOOL_BIN"] = avbtool
    if missing:
        raise KeygenError("missing tools")
    if driver.uses_pkcs11_to_generate_key:
        if not environment.get("RSA_KEY_SIZE"):
            environment["RSA_KEY_SIZE"] = "4096"
            print("RSA_KEY_SIZE not specified. Using 4096.", file=sys.stderr)
        if not environment.get("EXTRACTION_ARGS"):
            environment["EXTRACTION_ARGS"] = "--sensitive --extractable"
            print(
                "EXTRACTION_ARGS not specified. Using --sensitive "
                "--extractable.",
                file=sys.stderr,
            )
    if driver.uses_pkcs11_to_generate_cert:
        if not environment.get("CERT_EXPIRY_DAYS"):
            environment["CERT_EXPIRY_DAYS"] = "7200"
            print(
                "CERT_EXPIRY_DAYS not specified. Using 7200.",
                file=sys.stderr,
            )
        if not environment.get("SIGNING_SUBJECT_TEMPLATE"):
            environment["SIGNING_SUBJECT_TEMPLATE"] = DEFAULT_SUBJECT_TEMPLATE
            print(
                "SIGNING_SUBJECT_TEMPLATE not specified. Using "
                f"{DEFAULT_SUBJECT_TEMPLATE}.",
                file=sys.stderr,
            )


def generate_keys(
    environment: MutableMapping[str, str],
    driver: KeygenDriver,
    metadata: SigningMetadata,
    keymapper: Keymapper,
    devices: Sequence[str],
) -> tuple[bool, bool]:
    """
    Generate every missing key and certificate the metadata names for the
    devices, once per keymapper value.

    Returns:
        Whether any key and whether any certificate was generated.

    Raises:
        KeygenError: If no devices are given.
    """
    if not devices:
        print(
            "ERROR: No defined devices for which to generate keys.\n"
            "       Ensure the devices array is populated in $DEVICES_FILE "
            f"({environment.get('DEVICES_FILE', '')}).",
            file=sys.stderr,
        )
        raise KeygenError("no devices")
    already_generated: dict[str, str] = {}
    any_key = False
    any_cert = False
    for key_type in metadata.key_types:
        print("###################################")
        print(f"### GENERATING KEYS: {key_type}")
        print("###################################")
        for key_name in metadata.keys_for_type(key_type):
            print(f"# KEY: {key_name}")
            per_device = keymapper.is_per_device(key_type, key_name)
            for device in devices if per_device else ("",):
                mapped = keymapper.key(key_type, key_name, device)
                if not mapped:
                    continue
                label = device or key_type
                message = (
                    f"# VALUE: {mapped}"
                    + (f" (DEVICE: {device})" if device else "")
                    + f" LABEL: {label}"
                )
                if mapped in already_generated:
                    print(
                        f"{message}: skipping, generated "
                        f"{already_generated[mapped]}",
                        file=sys.stderr,
                    )
                    continue
                key_exists = driver.key_exists(mapped)
                cert_exists = driver.cert_exists(mapped)
                if cert_exists and not key_exists:
                    print(
                        f"{message}: certificate exists without its key",
                        file=sys.stderr,
                    )
                    print(
                        "Restore the key from a backup, or delete its "
                        "certificate.",
                        file=sys.stderr,
                    )
                    raise KeygenError(mapped)
                algorithm = driver.key_algorithm(key_type)
                if not key_exists:
                    print(message, flush=True)
                    driver.generate_keypair(
                        mapped,
                        label,
                        algorithm,
                    )
                    any_key = True
                else:
                    print(f"{message}: key already exists", flush=True)
                    driver.complete_existing_key(mapped)
                    already_generated[mapped] = "before this run"
                if not cert_exists:
                    if key_exists:
                        print(f"{message}: generating missing cert", flush=True)
                    driver.generate_cert(mapped, key_type, algorithm)
                    any_cert = True
                else:
                    driver.complete_existing_certificate(mapped, key_type)
                if not key_exists or not cert_exists:
                    already_generated[mapped] = "just now"
    return any_key, any_cert


OPENSSL_ENGINE_PATHS = tuple(
    f"/usr{prefix}/lib{arch}/engines-3/libpkcs11.so"
    for prefix in ("/local", "")
    for arch in ("/x86_64-linux-gnu", "/aarch64-linux-gnu", "64", "")
)


class Pkcs11KeygenDriver(KeygenDriver):
    """
    Generate keys and self-signed certificates on a PKCS#11 token through
    the PKCS#11 backend.
    """

    uses_pkcs11_to_generate_key = True
    uses_pkcs11_to_generate_cert = True

    def initialize_pre_metadata(self) -> None:
        """Find pkcs11-tool and require the OpenSSL PKCS#11 engine."""
        missing = False
        tool = self.tool("pkcs11-tool", "PKCS11_TOOL_BIN")
        if tool is None:
            print(
                "Please install pkcs11-tool, or set PKCS11_TOOL_BIN to its "
                "path.",
                file=sys.stderr,
            )
            missing = True
        else:
            self.environment["PKCS11_TOOL_BIN"] = tool
        if not self.environment.get("PKCS11_OPENSSL_ENGINE_LIBRARY_PATH"):
            engine = next(
                (path for path in OPENSSL_ENGINE_PATHS if Path(path).exists()),
                None,
            )
            if engine is not None:
                self.environment["PKCS11_OPENSSL_ENGINE_LIBRARY_PATH"] = engine
        if not self.environment.get("PKCS11_OPENSSL_ENGINE_LIBRARY_PATH"):
            print(
                "Please install the OpenSSL engine for PKCS#11 modules "
                "(libengine-pkcs11-openssl),\n"
                "or set PKCS11_OPENSSL_ENGINE_LIBRARY_PATH to its path.",
                file=sys.stderr,
            )
            missing = True
        if missing:
            raise KeygenError("missing PKCS#11 tools")

    def initialize_post_metadata(self) -> None:
        """Resolve the token PINs and require PKCS11_MODULE."""
        environment = self.environment
        testing = (environment.get("PKCS11_TESTING") or "n") != "n"
        if not environment.get("PKCS11_SO_PIN") and (
            environment.get("MODIFICATION_USES_SO_PIN") == "y"
            or environment.get("PKCS11_TESTING") == "y"
        ):
            if not testing:
                print(
                    "PKCS11_SO_PIN environment variable must be supplied for "
                    "production!\nIf you are just testing, please supply "
                    "PKCS11_TESTING=y.",
                    file=sys.stderr,
                )
                raise KeygenError("no PKCS11_SO_PIN")
            environment["PKCS11_SO_PIN"] = "12345678"
            print(
                "PKCS11_SO_PIN not specified. Using 12345678.",
                file=sys.stderr,
            )
        if not environment.get("PKCS11_PIN"):
            if not testing:
                print(
                    "PKCS11_PIN environment variable must be supplied for "
                    "production!\nIf you are just testing, please supply "
                    "PKCS11_TESTING=y.",
                    file=sys.stderr,
                )
                raise KeygenError("no PKCS11_PIN")
            environment["PKCS11_PIN"] = "123456"
            print("PKCS11_PIN not specified. Using 123456.", file=sys.stderr)
        if not environment.get("PKCS11_MODULE"):
            print(
                "Could not find PKCS#11 module. Please set PKCS11_MODULE to "
                "its location.",
                file=sys.stderr,
            )
            raise KeygenError("no PKCS#11 module")

    def maybe_initialize_token(self) -> None:
        """Initialize the token unless one is initialized already."""
        environment = self.environment
        tool = environment["PKCS11_TOOL_BIN"]
        module = Path(environment["PKCS11_MODULE"])
        if is_any_pkcs11_token_initialized(tool=tool, module=module):
            return
        if not environment.get("PKCS11_SO_PIN"):
            print(
                "Cannot initialize PKCS#11 token: you must set PKCS11_SO_PIN.",
                file=sys.stderr,
            )
            raise KeygenError("no PKCS11_SO_PIN")
        testing = (environment.get("PKCS11_TESTING") or "n") != "n"
        if not testing and not environment.get("PKCS11_TOKEN_LABEL"):
            print(
                "Neither PKCS11_TOKEN_LABEL nor PKCS11_TESTING=y specified!\n"
                "If you are just testing, please supply PKCS11_TESTING=y to "
                "use the default label.\nOtherwise, please set a label via "
                f"PKCS11_TOKEN_LABEL, e.g. {DEFAULT_TOKEN_LABEL}.",
                file=sys.stderr,
            )
            raise KeygenError("no PKCS11_TOKEN_LABEL")
        if not environment.get("PKCS11_TOKEN_LABEL"):
            environment["PKCS11_TOKEN_LABEL"] = DEFAULT_TOKEN_LABEL
        initialize_pkcs11_token(
            tool=tool,
            module=module,
            label=environment["PKCS11_TOKEN_LABEL"],
            so_pin=environment["PKCS11_SO_PIN"],
            user_pin=environment["PKCS11_PIN"],
        )

    def _backend(self, *, discovery: bool = False) -> Pkcs11Backend:
        """
        Build the PKCS#11 backend from the environment, for key discovery
        or for modification.
        """
        environment = self.environment
        user_pin = environment.get("PKCS11_PIN") or None
        pin = signing_pin = discovery_pin = None
        use_so_pin = list_requires_no_pin = False
        if discovery:
            if environment.get("LIST_REQUIRES_NO_PIN", "n") == "y":
                list_requires_no_pin = True
            else:
                pin = user_pin
        elif environment.get("MODIFICATION_USES_SO_PIN") == "y":
            if environment.get("PKCS11_SO_PIN"):
                use_so_pin = True
                pin = environment["PKCS11_SO_PIN"]
            signing_pin = discovery_pin = user_pin
        else:
            pin = user_pin
        engine = environment.get("PKCS11_OPENSSL_ENGINE_LIBRARY_PATH")
        return Pkcs11Backend(
            Pkcs11Config(
                module=Path(environment["PKCS11_MODULE"]),
                pin=pin,
                discovery_pin=discovery_pin,
                signing_pin=signing_pin,
                token_label=environment.get("PKCS11_TOKEN_LABEL") or None,
                slot=environment.get("PKCS11_SLOT") or None,
                tool=environment["PKCS11_TOOL_BIN"],
                openssl=environment.get("OPENSSL_BIN", "openssl"),
                openssl_engine=Path(engine) if engine else None,
                certificate_days=int(environment["CERT_EXPIRY_DAYS"]),
                use_so_pin=use_so_pin,
                list_requires_no_pin=list_requires_no_pin,
            ),
        )

    def _reference(self, key_id: str, label: str = "") -> KeyReference:
        return KeyReference(key_id=key_id, label=label)

    def key_exists(self, mapped_value: str) -> bool:
        return self._backend(discovery=True).key_exists(
            self._reference(mapped_value),
        )

    def cert_exists(self, mapped_value: str) -> bool:
        return self._backend(discovery=True).certificate_exists(
            self._reference(mapped_value),
        )

    def spec(
        self,
        key_id: str,
        label: str,
        algorithm: str,
    ) -> KeySpec:
        size = algorithm.partition(":")[2]
        extraction = self.environment.get("EXTRACTION_ARGS", "")
        if extraction == "--sensitive --extractable":
            exportable = True
        elif extraction == "--sensitive":
            exportable = False
        else:
            message = (
                f"Unsupported EXTRACTION_ARGS='{extraction}'. Use "
                "'--sensitive --extractable' or '--sensitive'."
            )
            print(message, file=sys.stderr)
            raise KeygenError(message)
        return KeySpec(
            reference=self._reference(key_id, label),
            key_size=int(size),
            exportable=exportable,
        )

    def generate_keypair(
        self,
        key_id: str,
        label: str,
        algorithm: str,
    ) -> None:
        """Generate one key pair on the token."""
        self._backend().generate_key(self.spec(key_id, label, algorithm))

    def generate_cert(
        self,
        key_id: str,
        key_type: str,
        algorithm: str,
    ) -> None:
        """
        Certify the key on the token, and export its certificate, and
        for AVB and APEX keys its public key, into the key output
        directory.
        """
        escaped_label = key_id.replace("/", "\\/")
        subject = self.environment["SIGNING_SUBJECT_TEMPLATE"].replace(
            "_KEY_LABEL_",
            escaped_label,
        )
        certificate = self._backend().generate_certificate(
            self.spec(key_id, key_id, algorithm),
            subject,
        )
        destination = self.key_out_dir / Path(key_id).parent
        destination.mkdir(parents=True, exist_ok=True)
        certificate_path = destination / f"{Path(key_id).name}.x509.pem"
        certificate_path.write_bytes(certificate)
        export_public_keys(self.environment, certificate_path, key_type)


def export_public_keys(
    environment: Mapping[str, str],
    certificate: Path,
    key_type: str,
    written: Callable[[Path], None] = lambda path: None,
    *,
    quiet: bool = False,
) -> None:
    """
    For AVB and APEX keys, write the public key of a .x509.pem
    certificate next to it as .pem and, for AVB and APEX payload keys,
    .avbpubkey, keeping a file that is already there.

    Args:
        environment: Environment naming OPENSSL_BIN and AVBTOOL_BIN.
        certificate: The .x509.pem certificate.
        key_type: The key's type.
        written: Called with each file as soon as it is written.
        quiet: Say nothing about a file that is already there.
    """
    if key_type not in {"avb", "apex_payload", "apex_container"}:
        return
    name = certificate.name.removesuffix(".x509.pem")
    public_key = certificate.with_name(f"{name}.pem")
    if public_key.exists():
        if not quiet:
            print(
                f"Public key file already exists: {public_key}",
                file=sys.stderr,
            )
    else:
        subprocess.run(
            [
                environment["OPENSSL_BIN"],
                "x509",
                "-pubkey",
                "-noout",
                "-in",
                str(certificate),
                "-out",
                str(public_key),
            ],
            check=True,
        )
        written(public_key)
    if key_type not in {"avb", "apex_payload"}:
        return
    avb_public_key = certificate.with_name(f"{name}.avbpubkey")
    if avb_public_key.exists():
        if not quiet:
            print(
                f"avbpubkey file already exists: {avb_public_key}",
                file=sys.stderr,
            )
    else:
        subprocess.run(
            [
                environment["AVBTOOL_BIN"],
                "extract_public_key",
                "--key",
                str(public_key),
                "--output",
                str(avb_public_key),
            ],
            check=True,
        )
        written(avb_public_key)


_SOFTHSM_CONFIG = """\
# SoftHSM v2 configuration file

directories.tokendir = {token_dir}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
#log.level = DEBUG
log.level = INFO

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = true

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
"""


class SoftHsmKeygenDriver(Pkcs11KeygenDriver):
    """Generate keys on a SoftHSM token."""

    def initialize_post_metadata(self) -> None:
        """
        Create the SoftHSM configuration and token directory if missing,
        then initialize the token.
        """
        environment = self.environment
        home = Path.home()
        config = Path(
            environment.get("SOFTHSM2_CONF")
            or home / ".config/softhsm/softhsm2.conf",
        )
        environment["SOFTHSM2_CONF"] = str(config)
        token_dir = environment.get("SOFTHSM_TOKEN_DIR") or (
            f"{home}/.local/share/softhsm/tokens/"
        )
        if not config.exists():
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(_SOFTHSM_CONFIG.format(token_dir=token_dir))
        if (
            f"directories.tokendir = {token_dir}"
            in config.read_text().splitlines()
        ):
            try:
                Path(token_dir).mkdir(parents=True, exist_ok=True)
            except OSError as error:
                print(
                    f"ERROR: Failed to create '{token_dir}' directory for "
                    f"SoftHSM.\n       Please edit '{config}' to point "
                    "directories.tokendir\n       wherever you'd like, or set "
                    "SOFTHSM2_CONF to your own config file.",
                    file=sys.stderr,
                )
                raise KeygenError("no SoftHSM token directory") from error
        super().initialize_post_metadata()
        self.maybe_initialize_token()


class YubiHsmKeygenDriver(KeygenDriver):
    """
    Generate keys on the YubiHSM, back each up wrapped,
    and use its attestation certificate as its certificate, recording
    every device operation in the audit log.
    """

    def __init__(
        self,
        environment: MutableMapping[str, str],
        key_out_dir: Path,
    ) -> None:
        super().__init__(environment, key_out_dir)
        self.unique_key_out_dir = key_out_dir
        self.hsm_key_out_dir = key_out_dir

    def _config(self) -> YubiHsmConfig:
        return sign_environment.yubihsm_config_from_environment(
            self.environment,
        )

    def _connection_arguments(self) -> list[str]:
        return [
            "--connector",
            self.environment["YUBIHSM_CONNECTOR"],
            "--authkey",
            self.environment["YUBIHSM_AUTHKEY"],
        ]

    def derived_public_key_written(self, path: Path) -> None:
        """
        Copy a derived public key file into the HSM's directory unless one
        is there already.
        """
        hsm_copy = self.hsm_key_out_dir / path.relative_to(self.key_out_dir)
        if not hsm_copy.exists():
            hsm_copy.parent.mkdir(parents=True, exist_ok=True)
            write_file_atomically(hsm_copy, path.read_bytes())

    def _dry_run(self) -> bool:
        return self.environment.get("DRY_RUN") == "y"

    def _extract_logs(self, comment: str) -> None:
        """Append the device audit log with a comment, unless DRY_RUN=y."""
        if self._dry_run():
            return
        config = self._config()
        extract_and_save_audit_log(
            config,
            Path(self.environment["AUDIT_LOG_PATH"]),
            comment,
        )

    def logged(
        self,
        command: Sequence[str],
        operation: Callable[[], object],
    ) -> None:
        """
        Run one device operation and record it in the audit log, named
        with its arguments and followed by its result, or under DRY_RUN=y
        print the record instead.
        """
        if self._dry_run():
            print(f"Operation: {' '.join(command)}", file=sys.stderr)
            return
        error: BaseException | None = None
        try:
            operation()
        except Exception as caught:
            error = caught
        self._record(
            f"Operation: {' '.join(command)} "
            f"Result: {0 if error is None else 1}",
            failed=error is not None,
        )
        if error is not None:
            raise error

    def _record(self, comment: str, *, failed: bool = False) -> None:
        """
        Append the audit log with a comment, unless DRY_RUN=y. A failed
        extraction is reported, and raised unless the operation recorded
        failed or NO_LOG_FAIL=y.
        """
        try:
            self._extract_logs(comment)
        except Exception:
            print("Failed to extract logs", file=sys.stderr)
            if not failed and self.environment.get("NO_LOG_FAIL") != "y":
                raise

    def key_algorithm(self, key_type: str) -> str:
        """
        Return RSA of RSA_KEY_SIZE bits for AVB and APEX payload keys, and
        RSA-4096 for every other key.
        """
        if key_type in {"avb", "apex_payload"}:
            return super().key_algorithm(key_type)
        return "RSA:4096"

    def initialize_pre_metadata(self) -> None:
        """
        Read YUBIHSM_PASSWORD_FILE, ask for a missing YUBIHSM_PASSWORD and
        default the other credentials.
        """
        environment = self.environment
        sign_environment.read_yubihsm_password_file(environment)
        if not environment.get("YUBIHSM_PASSWORD"):
            ask_variable(
                "YUBIHSM_PASSWORD",
                environment,
                default="",
                private=True,
                needs_value=True,
            )
        if environment.get("GENERATE_USING_PKCS11") == "y":
            print("GENERATE_USING_PKCS11=y is not supported.", file=sys.stderr)
            raise KeygenError("GENERATE_USING_PKCS11=y is not supported")
        if not environment.get("YUBIHSM_AUTHKEY"):
            environment["YUBIHSM_AUTHKEY"] = "1"
            print("YUBIHSM_AUTHKEY not specified. Using 1.", file=sys.stderr)
        if environment.get("PKCS11_PIN"):
            print(
                "WARNING: Specified PKCS11_PIN is ignored! It is constructed "
                "from YUBIHSM_AUTHKEY and YUBIHSM_PASSWORD.",
                file=sys.stderr,
            )
        print(
            "Using additional YUBIHSM_KEY_CAPABILITIES: "
            f"{environment.get('YUBIHSM_KEY_CAPABILITIES') or '(none)'}.",
            file=sys.stderr,
        )
        environment.setdefault("YUBIHSM_KEY_CAPABILITIES", "")

    def initialize_post_metadata(self) -> None:
        """
        Name the output directories and audit log after the device, save
        its attestation certificate, identity and keymap, and limit the
        on-demand objects.
        """
        environment = self.environment
        identity = get_device_identity(self._config())
        name = identity.name
        self.unique_key_out_dir = Path(
            environment.get("UNIQUE_KEY_OUT_DIR")
            or self.key_out_dir / f"{name}-{sign_environment.formatted_date()}",
        )
        self.hsm_key_out_dir = Path(
            environment.get("HSM_KEY_OUT_DIR") or self.key_out_dir / name,
        )
        logs_dir = environment.get("YUBIHSM_LOGS_DIR") or f"{Path.cwd()}/logs"
        environment["AUDIT_LOG_PATH"] = (
            f"{logs_dir}/{name}/{sign_environment.formatted_date()}-keygen.log"
        )
        if self._dry_run():
            self._limit_ondemand_objects()
            return

        self.unique_key_out_dir.mkdir(parents=True, exist_ok=True)
        attestation_key = self.unique_key_out_dir / "YubiHSM_attestation.pem"
        attestation_key.write_bytes(get_certificate(self._config(), "0x0000"))
        self._copy_to_other_dirs(attestation_key)

        device_info = self.unique_key_out_dir / "hsm_info.txt"
        device_info.write_text(identity.device_info)
        self._copy_to_other_dirs(device_info)

        keymap = self.unique_key_out_dir / "keymap.tsv"
        keymap.write_bytes(Path(environment["KEYMAP_FILE"]).read_bytes())
        self._copy_to_other_dirs(keymap)

        self._limit_ondemand_objects()

    def _copy_to_other_dirs(self, source: Path) -> None:
        """
        Copy a file into the HSM's directory, replacing it, and into the
        main output directory unless it is already there. Copies nothing
        under DRY_RUN=y.
        """
        if self._dry_run():
            return
        relative = source.relative_to(self.unique_key_out_dir)
        hsm_copy = self.hsm_key_out_dir / relative
        main_copy = self.key_out_dir / relative
        hsm_copy.parent.mkdir(parents=True, exist_ok=True)
        main_copy.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        write_file_atomically(hsm_copy, data)
        if not main_copy.exists():
            write_file_atomically(main_copy, data)

    def _limit_ondemand_objects(self) -> None:
        """
        Evict on-demand objects whose backup is in the output directory
        until the device has room.
        """
        limit_ondemand_objects(
            self._config(),
            self.key_out_dir,
            self.environment["YUBIHSM_ONDEMAND_DOMAIN"],
            self._record,
            dry_run=self._dry_run(),
        )

    def _domains(self, key_id: str) -> str:
        """
        Return a key's domains. Every key is exportable, and an on-demand
        key also goes into the on-demand domain.
        """
        environment = self.environment
        domains = environment["YUBIHSM_EXPORTABLE_DOMAIN"]
        assert self.keymapper is not None
        if self.keymapper.key_id_is_per_device(key_id):
            domains += f",{environment['YUBIHSM_ONDEMAND_DOMAIN']}"
        return domains

    def key_exists(self, mapped_value: str) -> bool:
        if (self.key_out_dir / f"{mapped_value}-asymmetric-key.yhw").exists():
            return True
        return self._key_is_loaded(mapped_value)

    def _key_is_loaded(self, key_id: str) -> bool:
        return int(key_id, 16) in get_loaded_key_ids(self._config())

    def complete_existing_key(self, mapped_value: str) -> None:
        """
        Back up a key the device holds without a wrapped copy, as left by a
        run that failed after generating it.
        """
        if (self.key_out_dir / f"{mapped_value}-asymmetric-key.yhw").exists():
            return
        print(f"# VALUE: {mapped_value}: backing up the loaded key", flush=True)
        self._back_up(mapped_value)

    def _back_up(self, key_id: str) -> None:
        """
        Back a key up wrapped into the device's output directory and copy
        the backup into the other output directories.
        """
        output = self.unique_key_out_dir / f"{key_id}-asymmetric-key.yhw"
        if not self._dry_run():
            self.unique_key_out_dir.mkdir(parents=True, exist_ok=True)
        self.back_up_wrapped_key(key_id, output)
        self._copy_to_other_dirs(output)

    def cert_exists(self, mapped_value: str) -> bool:
        return (self.key_out_dir / f"{mapped_value}.x509.pem").exists()

    def generate_keypair(
        self,
        key_id: str,
        label: str,
        algorithm: str,
    ) -> None:
        """Generate one key pair on the device and back it up wrapped."""
        environment = self.environment
        domains = self._domains(key_id)
        capabilities = (
            f"{environment['YUBIHSM_KEY_CAPABILITIES']},exportable-under-wrap"
        )
        self.logged(
            [
                "generate-asymmetric-key",
                *self._connection_arguments(),
                "--key-id",
                key_id,
                "--label",
                label,
                "--domain",
                domains,
                "--capabilities",
                capabilities,
                "--algorithm",
                algorithm,
            ],
            lambda: generate_asymmetric_key(
                self._config(),
                key_id=key_id,
                label=label,
                domains=domains,
                capabilities=capabilities,
                algorithm=algorithm,
            ),
        )
        self._back_up(key_id)

    def back_up_wrapped_key(self, key_id: str, output: Path) -> None:
        """
        Write a key wrapped under YUBIHSM_WRAP_KEY_ID to output, and
        record the export in the audit log, or under DRY_RUN=y print the
        record instead.

        Args:
            key_id: The key's ID, e.g. "0x2000".
            output: The backup file.
        """

        def export() -> None:
            wrapped = export_wrapped_key(self._config(), key_id)
            write_file_atomically(output, base64.b64encode(wrapped))

        self.logged(
            [
                "export-wrapped-key",
                *self._connection_arguments(),
                "--wrap-id",
                self.environment["YUBIHSM_WRAP_KEY_ID"],
                "--key-id",
                key_id,
                "--output",
                str(output),
            ],
            export,
        )

    def _write_stored_certificate(self, key_id: str, certificate: Path) -> bool:
        """
        Write the certificate stored on the HSM under a key's ID, if there
        is one and it certifies the key, except under DRY_RUN.

        Args:
            key_id: The key's ID, e.g. "0x2000".
            certificate: File to write the certificate to.

        Returns:
            Whether the HSM holds a certificate of the key.
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        from cryptography.x509 import load_pem_x509_certificate
        from yubihsm.defs import ERROR
        from yubihsm.exceptions import YubiHsmDeviceError

        try:
            stored = get_certificate(self._config(), key_id)
            public_key = get_public_key(self._config(), key_id)
        except YubiHsmDeviceError as error:
            if error.code == ERROR.OBJECT_NOT_FOUND:
                return False
            raise
        certified_key = load_pem_x509_certificate(stored).public_key()
        if (
            certified_key.public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo,
            )
            != public_key
        ):
            return False
        if not self._dry_run():
            certificate.write_bytes(stored)
        return True

    def generate_cert(
        self,
        key_id: str,
        key_type: str,
        algorithm: str,
    ) -> None:
        """
        Use the key's attestation certificate as its certificate, kept on
        disk only, since signing never reads it from the HSM. A certificate
        of the key an older version of the scripts stored on the HSM is
        written out instead, since releases have signed with it.

        Raises:
            KeygenError: If the key is backed up but not on the HSM, outside
                DRY_RUN.
        """
        environment = self.environment
        if not self._dry_run():
            if not self._key_is_loaded(key_id):
                print(
                    f"Key {key_id} is not on the HSM. Load it from its "
                    "backup before keygen writes its certificate.",
                    file=sys.stderr,
                )
                raise KeygenError(f"key {key_id} is not on the HSM")
            self.unique_key_out_dir.mkdir(parents=True, exist_ok=True)
        certificate = self.unique_key_out_dir / f"{key_id}.x509.pem"
        if not self._write_stored_certificate(key_id, certificate):
            attestation = self.unique_key_out_dir / f"{key_id}.attestation.pem"

            def attest() -> None:
                attestation.write_bytes(
                    attest_key(self._config(), key_id),
                )

            self.logged(
                [
                    "attest-key",
                    *self._connection_arguments(),
                    "--key-id",
                    key_id,
                    "--attestation-id",
                    "0",
                    "--output",
                    str(attestation),
                ],
                attest,
            )
            self._copy_to_other_dirs(attestation)
            if not self._dry_run():
                shutil.copy2(attestation, certificate)
        self._copy_to_other_dirs(certificate)
        if not self._dry_run():
            export_public_keys(
                environment,
                certificate,
                key_type,
                self._copy_to_other_dirs,
            )
        self._limit_ondemand_objects()

    def cleanup(self) -> bool:
        """
        Upload a non-empty audit log, and return whether the upload
        succeeded.
        """
        environment = self.environment
        audit_log = environment.get("AUDIT_LOG_PATH")
        if (
            audit_log
            and Path(audit_log).is_file()
            and Path(audit_log).stat().st_size
        ):
            try:
                uploaded = subprocess.run(
                    [
                        f"{environment['YUBIHSM_LOGS_DIR']}/upload.py",
                        "-f",
                        audit_log,
                    ],
                    check=False,
                )
            except OSError as error:
                print(
                    f"Could not upload the audit log ({error})",
                    file=sys.stderr,
                )
                return False
            if uploaded.returncode != 0:
                print(
                    "Could not upload the audit log (exit status "
                    f"{uploaded.returncode})",
                    file=sys.stderr,
                )
                return False
        return True


_DRIVERS: dict[str, type[KeygenDriver]] = {
    "softhsm": SoftHsmKeygenDriver,
    "yubihsm": YubiHsmKeygenDriver,
}


def keygen_usage() -> None:
    print("usage: keygen public_key_output_dir")
    print()
    print("Generate the release keys on the SoftHSM2 token or the YubiHSM 2")
    print("that PKCS11_VENDOR selects, and write their certificates and public")
    print("keys to public_key_output_dir.")
    print()
    print("Most functionality is controlled by environment variables. Check")
    print("out SoftHsmKeygenDriver and YubiHsmKeygenDriver in")
    print("signing/keygen.py.")


def keygen_main(
    environment: MutableMapping[str, str],
    arguments: Sequence[str],
) -> int:
    """
    Generate every key for the vendor PKCS11_VENDOR names into the
    token, exporting their certificates and public keys into the output
    directory.

    Args:
        environment: Process environment, mutated in place.
        arguments: The keygen script's arguments.

    Returns:
        0 on success, 1 on failure.

    Raises:
        OSError: If the key output directory cannot be created.
    """
    output_argument = None
    for argument in arguments or [""]:
        if argument in ("", "--help") or (
            len(argument) == 2 and argument.startswith("-")
        ):
            keygen_usage()
            return 0
        if output_argument is not None:
            print(
                "Expected just one argument, the key output directory.",
                file=sys.stderr,
            )
            return 1
        output_argument = argument
    key_out_dir = Path(output_argument or "")
    key_out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    inherited = dict(environment)
    vendor = None
    vendor_name = environment.get("PKCS11_VENDOR", "")
    yubihsm_errors: tuple[type[Exception], ...] = ()
    if vendor_name == "yubihsm":
        from yubihsm.exceptions import YubiHsmError

        yubihsm_errors = (YubiHsmError,)
    try:
        driver = _DRIVERS[vendor_name](environment, key_out_dir)
    except KeyError:
        print(
            f"keygen does not support PKCS11_VENDOR={vendor_name!r}.",
            file=sys.stderr,
        )
        return 1
    try:
        driver.initialize_pre_metadata()
        if not environment.get("METADATA_FILE"):
            environment["METADATA_FILE"] = str(SCRIPTS_DIR / "metadata.py")
        metadata_file = Path(environment["METADATA_FILE"])
        devices_file = environment.get("DEVICES_FILE") or str(
            (SCRIPTS_DIR / "../../../calyx/scripts/vars/devices").resolve(),
        )
        environment["DEVICES_FILE"] = devices_file
        missing = False
        if not metadata_file.exists():
            print(
                "ERROR: Please set METADATA_FILE to the path of a metadata.py "
                "module.\n"
                "       Note that this module will be run as a script, so it "
                "should be trusted!",
                file=sys.stderr,
            )
            missing = True
        if not Path(devices_file).exists():
            print(
                "ERROR: Please set DEVICES_FILE to the path of a file that "
                "includes a list of\n"
                "       devices in the 'devices' array. Note that this file "
                "will be sourced as\n"
                "       a script, so it should be trusted!",
                file=sys.stderr,
            )
            missing = True
        if missing:
            return 1
        metadata = load_metadata(metadata_file)
        devices = load_devices_file(Path(devices_file))
        print(f"Loaded devices from {devices_file}")
        print(f"Loaded metadata from {metadata_file}")
        vendor = sign_environment.load_vendor(environment)
        keymapper = load_keymapper(environment, metadata)
        keymapper.key_dir(environment)
        driver.keymapper = keymapper
        sign_environment.maybe_initialize_vendor_interactive(
            environment,
            assume_yes=environment.get("SIGN_ASSUME_YES") == "y",
        )
        sign_environment.maybe_initialize_vendor(
            environment,
            tmpdir=Path(environment.get("TMPDIR") or "/dev/shm"),
        )
        initialize_post_metadata_common(environment, driver)
        driver.initialize_post_metadata()
        any_key, any_cert = generate_keys(
            environment,
            driver,
            metadata,
            keymapper,
            devices,
        )
        print("Key generation finished successfully.")
        if not any_key:
            print("No keys generated during the process.")
        if not any_cert:
            print("No certs generated during the process.")
    except (
        OSError,
        KeyError,
        RuntimeError,
        ValueError,
        subprocess.CalledProcessError,
    ) as error:
        if isinstance(error, subprocess.CalledProcessError):
            sys.stderr.write(os.fsdecode(error.stderr or b""))
        if isinstance(error, KeyError) and error.args:
            print(f"error: {error.args[0]}", file=sys.stderr)
        elif not isinstance(error, KeygenError):
            print(f"error: {error}", file=sys.stderr)
        return 1
    except yubihsm_errors as error:
        print(f"error: YubiHSM failure: {error}", file=sys.stderr)
        return 1
    finally:
        try:
            cleaned = driver.cleanup()
        finally:
            if vendor is not None:
                vendor.cleanup(environment, inherited=inherited)
    return 0 if cleaned else 1
