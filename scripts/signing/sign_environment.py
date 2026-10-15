#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
PKCS#11 vendor initialization.

Every function mutates the environment mapping it is given, so that
release.sh and generate_delta.sh jobs started afterward see
PKCS11_VENDOR_INITIALIZED and every value the vendor resolved.
"""

from __future__ import annotations

import abc
import contextlib
import datetime
import shutil
import sys
import tempfile
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from pathlib import Path

from .confirmation import ask_variable, confirm
from .keymap import Keymapper, normalize_key_dir
from .vendor_yubihsm import (
    YubiHsmConfig,
    audit_logged,
    ensure_keys_are_available,
    extract_and_save_audit_log,
    get_device_identity,
    get_loaded_key_ids,
    yubihsm_lock,
)
from .vendor_yubihsm_connector import (
    DEFAULT_CONNECTOR_URL,
    YubiHsmConnector,
    YubiHsmConnectorConfig,
    connector_config_from_environment,
)

_YUBIHSM_PKCS11_CONF_TEMPLATE = """\
# This is a sample configuration file for the YubiHSM PKCS#11 module
# Uncomment the various options as needed

# URL of the connector to use. This can be a comma-separated list
connector = {connector_url}

# Enables general debug output in the module
#
# debug

# Enables function tracing (ingress/egress) debug output in the module
#
# dinout

# Enables libyubihsm debug output in the module
#
# libdebug

# Redirects the debug output to a specific file. The file is created
# if it does not exist. The content is appended
#
# debug-file = /tmp/yubihsm_pkcs11_debug

# CA certificate to use for HTTPS validation. Point this variable to
# a file containing one or more certificates to use when verifying
# a peer. Currently not supported on Windows
#
# cacert = /tmp/cacert.pem

# Proxy server to use for the connector
# Currently not supported on Windows
#
# proxy = http://proxyserver.local.com:8080

# Timeout in seconds to use for the initial connection to the connector
# timeout = 5
"""


class UnsupportedVendorError(RuntimeError):
    """Raised for a PKCS11_VENDOR this module cannot initialize."""


def is_audit_log_repository(logs_dir: Path) -> bool:
    """
    Tell whether logs_dir is the audit-log git repository.

    Args:
        logs_dir: Candidate YUBIHSM_LOGS_DIR.

    Returns:
        True if logs_dir/upload.py is a nonempty file.
    """
    upload = logs_dir / "upload.py"
    return upload.is_file() and upload.stat().st_size > 0


def key_id_is_ondemand(keymapper: Keymapper) -> Callable[[int], bool]:
    """
    Build the YubiHSM's on-demand test from a keymapper, under which a
    key is on-demand when it is per-device.

    Args:
        keymapper: The release's keymapper.

    Returns:
        A test taking a numeric object ID.
    """
    return lambda object_id: keymapper.key_id_is_per_device(
        f"0x{object_id:04x}",
    )


def load_vendor(environment: MutableMapping[str, str]) -> Vendor | None:
    """
    Pick the vendor PKCS11_VENDOR names, and set the variables the vendor
    and the keymapper define.

    Args:
        environment: Process environment to read PKCS11_VENDOR from,
            mutated in place.

    Returns:
        The vendor, or None when no vendor is set.

    Raises:
        UnsupportedVendorError: If PKCS11_VENDOR is set to anything
            other than "yubihsm"/"softhsm", PKCS11_VENDOR_FILE is set, or
            PKCS11_MODULE is set without PKCS11_VENDOR.
        RuntimeError: If PKCS11_MODULE is unset and no module for the
            vendor exists at any of its search paths.
    """
    if environment.get("PKCS11_VENDOR_FILE"):
        raise UnsupportedVendorError(
            "PKCS11_VENDOR_FILE is no longer supported. Set PKCS11_VENDOR "
            "to yubihsm or softhsm",
        )
    name = environment.get("PKCS11_VENDOR", "")
    if environment.get("PKCS11_MODULE") and not name:
        raise UnsupportedVendorError(
            "PKCS11_MODULE needs PKCS11_VENDOR, since keys are looked up by "
            "their hex object ID. Set PKCS11_VENDOR to yubihsm or softhsm",
        )
    vendor: Vendor | None = None
    if name:
        try:
            vendor = VENDORS[name]()
        except KeyError as error:
            raise UnsupportedVendorError(
                f"PKCS11_VENDOR={name!r} is not supported. Set PKCS11_VENDOR "
                "to yubihsm or softhsm",
            ) from error
        vendor.apply_source_exports(environment)
        if not environment.get("PKCS11_MODULE"):
            module = vendor.find_pkcs11_module()
            if module is None:
                raise RuntimeError(
                    f"Please install the {vendor.display_name} PKCS#11 "
                    "module, or set PKCS11_MODULE to its path.",
                )
            environment["PKCS11_MODULE"] = module
    if not environment.get("KEYMAPPER_FILE"):
        if (environment.get("KEYMAPPER") or "legacy") == "legacy":
            environment["KEY_DIR"] = "keys/"
        else:
            normalize_key_dir(environment)
    return vendor


def _module_paths(arches: tuple[str, ...], name: str) -> tuple[str, ...]:
    return tuple(
        f"/usr{prefix}/lib{arch}{subdirectory}/{name}"
        for prefix in ("/local", "")
        for arch in arches
        for subdirectory in ("/pkcs11", "")
    )


def _default(
    environment: MutableMapping[str, str],
    name: str,
    value: str,
) -> None:
    """Set a variable that is unset or empty."""
    if not environment.get(name):
        environment[name] = value


def read_yubihsm_password_file(environment: MutableMapping[str, str]) -> bool:
    """
    Set YUBIHSM_PASSWORD from YUBIHSM_PASSWORD_FILE when only the file is
    given.

    Args:
        environment: Process environment, mutated in place.

    Returns:
        Whether the password was read from the file.

    Raises:
        RuntimeError: If the file is not a private file of one line.
    """
    password_file = environment.get("YUBIHSM_PASSWORD_FILE")
    if environment.get("YUBIHSM_PASSWORD") or not password_file:
        return False
    path = Path(password_file)
    if not path.is_file():
        raise RuntimeError(
            f"YUBIHSM_PASSWORD_FILE ({password_file}) is not a file.",
        )
    if path.stat().st_mode & 0o077:
        raise RuntimeError(
            f"YUBIHSM_PASSWORD_FILE ({password_file}) must not have group or "
            "other permissions.",
        )
    try:
        text = path.read_bytes().decode()
    except OSError as error:
        raise RuntimeError(
            f"YUBIHSM_PASSWORD_FILE ({password_file}) cannot be read "
            f"({error.strerror}).",
        ) from error
    except UnicodeDecodeError as error:
        raise RuntimeError(
            f"YUBIHSM_PASSWORD_FILE ({password_file}) is not valid UTF-8.",
        ) from error
    lines = text.removesuffix("\n").split("\n") if text else []
    if len(lines) != 1 or not lines[0].removesuffix("\r"):
        raise RuntimeError(
            f"YUBIHSM_PASSWORD_FILE ({password_file}) must contain exactly "
            "one non-empty line.",
        )
    environment["YUBIHSM_PASSWORD"] = lines[0].removesuffix("\r")
    print("Using YUBIHSM_PASSWORD from YUBIHSM_PASSWORD_FILE.")
    return True


def ask_yubihsm_credentials(environment: MutableMapping[str, str]) -> None:
    """
    Ask for YUBIHSM_AUTHKEY, and for YUBIHSM_PASSWORD unless
    YUBIHSM_PASSWORD_FILE supplies it.

    Args:
        environment: Process environment, mutated in place.

    Raises:
        RuntimeError: See read_yubihsm_password_file().
    """
    ask_variable(
        "YUBIHSM_AUTHKEY",
        environment,
        default="0x0001",
        needs_value=True,
    )
    if not read_yubihsm_password_file(environment):
        ask_variable(
            "YUBIHSM_PASSWORD",
            environment,
            default="",
            private=True,
            needs_value=True,
        )


def maybe_initialize_vendor_interactive(
    environment: MutableMapping[str, str],
    vendor: Vendor | None,
    *,
    assume_yes: bool,
) -> None:
    """
    Run the vendor's interactive initialization once, when there is a
    vendor.

    Args:
        environment: Process environment, mutated in place with any
            resolved values.
        vendor: The vendor load_vendor() returned.
        assume_yes: Auto-answer any confirmation prompt yes.

    Returns:
        None.

    Raises:
        RuntimeError: If interactive initialization fails or is
            declined.
    """
    if vendor is None:
        return
    if environment.get("PKCS11_VENDOR_INITIALIZED_INTERACTIVE") == "y":
        return
    vendor.initialize_interactive(environment, assume_yes=assume_yes)
    environment["PKCS11_VENDOR_INITIALIZED_INTERACTIVE"] = "y"


def maybe_initialize_vendor(
    environment: MutableMapping[str, str],
    vendor: Vendor | None,
    *,
    tmpdir: Path,
) -> None:
    """
    Run the vendor's initialization once, when there is a vendor.

    Args:
        environment: Process environment, mutated in place with any
            resolved values.
        vendor: The vendor load_vendor() returned.
        tmpdir: Directory to create vendor-specific scratch space under.

    Returns:
        None.

    Raises:
        RuntimeError: If initialization fails (e.g. a required tool or
            directory is missing).
    """
    if vendor is None:
        return
    if environment.get("PKCS11_VENDOR_INITIALIZED") == "y":
        return
    vendor.initialize(environment, tmpdir=tmpdir)
    environment["PKCS11_VENDOR_INITIALIZED"] = "y"


def yubihsm_config_from_environment(
    environment: MutableMapping[str, str],
) -> YubiHsmConfig:
    """
    Build the YubiHSM connection settings from the environment.

    Args:
        environment: Variables naming the connector, the authentication
            key, its password and the wrap key.

    Returns:
        The settings, with the vendor's defaults for unset variables.
    """
    return YubiHsmConfig(
        connector_url=environment.get(
            "YUBIHSM_CONNECTOR",
            DEFAULT_CONNECTOR_URL,
        ),
        auth_key=environment.get("YUBIHSM_AUTHKEY", "0x0001"),
        password=environment.get("YUBIHSM_PASSWORD", ""),
        wrap_id=environment.get("YUBIHSM_WRAP_KEY_ID", "0x0010"),
    )


def formatted_date() -> str:
    """Format the current UTC time as YYYY-mm-dd_HH-MM-SS-mmm."""
    now = datetime.datetime.now(datetime.UTC)
    return now.strftime("%Y-%m-%d_%H-%M-%S-") + f"{now.microsecond // 1000:03d}"


class Vendor(abc.ABC):
    """
    A PKCS#11 vendor.
    """

    name = ""
    display_name = ""
    pkcs11_module_paths: tuple[str, ...] = ()

    @abc.abstractmethod
    def apply_source_exports(
        self,
        environment: MutableMapping[str, str],
    ) -> None:
        """
        Set the variables the vendor defines.

        Args:
            environment: Process environment to mutate in place.

        Returns:
            None.
        """

    def find_pkcs11_module(self) -> str | None:
        """
        Search for the vendor's PKCS#11 module.

        Returns:
            The first existing path of pkcs11_module_paths, or None.
        """
        for path in self.pkcs11_module_paths:
            if Path(path).exists():
                return path
        return None

    def initialize_interactive(
        self,
        environment: MutableMapping[str, str],
        *,
        assume_yes: bool,
    ) -> None:
        """
        Ask for what initialization needs. Does nothing by default.

        Args:
            environment: Process environment to mutate in place.
            assume_yes: Auto-answer any confirmation prompt yes.

        Returns:
            None.
        """

    @abc.abstractmethod
    def initialize(
        self,
        environment: MutableMapping[str, str],
        *,
        tmpdir: Path,
    ) -> None:
        """
        Prepare the vendor for signing.

        Args:
            environment: Process environment to mutate in place.
            tmpdir: Directory for vendor scratch space.

        Returns:
            None.
        """

    @abc.abstractmethod
    def initialize_release(
        self,
        environment: MutableMapping[str, str],
        *,
        device: str,
        build_number: str,
        keymapper: Keymapper,
        command: str,
    ) -> None:
        """
        Prepare one release.

        Args:
            environment: Process environment to mutate in place.
            device: Device being released.
            build_number: Requested build number.
            keymapper: The release's keymapper.
            command: Base name of the script being run, without .sh.

        Returns:
            None.
        """

    def finalize_release(
        self,
        environment: MutableMapping[str, str],
        *,
        device: str,
        build_number: str,
        record_finish: bool,
        command: str,
    ) -> None:
        """
        Close one release. Does nothing by default.

        Args:
            environment: Process environment.
            device: Device being released.
            build_number: Requested build number.
            record_finish: Whether initialize_release() completed.
            command: Base name of the script being run, without .sh.

        Returns:
            None.
        """

    @abc.abstractmethod
    def split_devices_by_loaded_keys(
        self,
        environment: MutableMapping[str, str],
        keymapper: Keymapper,
        devices: Sequence[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """
        Partition devices by whether their keys are loaded.

        Args:
            environment: Process environment.
            keymapper: The keymapper naming each device's keys.
            devices: Devices to partition.

        Returns:
            The devices with every key loaded, then the others, each in
            the order of devices.
        """

    def ensure_keys_for_devices(
        self,
        environment: MutableMapping[str, str],
        keymapper: Keymapper,
        devices: Sequence[str],
    ) -> None:
        """
        Load the keys the devices need. Does nothing by default.

        Args:
            environment: Process environment.
            keymapper: The keymapper naming each device's keys.
            devices: Devices whose keys must be loaded.

        Returns:
            None.
        """

    def cleanup(
        self,
        environment: MutableMapping[str, str],
        *,
        inherited: Mapping[str, str],
    ) -> None:
        """
        Stop what this process started for the vendor. Does nothing by
        default.

        Args:
            environment: Process environment.
            inherited: The environment the process started with.

        Returns:
            None.
        """


class SoftHsmVendor(Vendor):
    """The SoftHSM vendor."""

    name = "softhsm"
    display_name = "SoftHSM"
    pkcs11_module_paths = _module_paths(
        ("/x86_64-linux-gnu", "64", ""),
        "libsofthsm2.so",
    )

    def apply_source_exports(
        self,
        environment: MutableMapping[str, str],
    ) -> None:
        environment["KEYMAPPER"] = "id2b"
        environment["USE_APKSIGNER"] = "y"
        _default(environment, "SOFTHSM_LOGS_DIR", str(Path.cwd() / "logs"))

    def initialize(
        self,
        environment: MutableMapping[str, str],
        *,
        tmpdir: Path,
    ) -> None:
        """SoftHSM needs no initialization."""

    def initialize_release(
        self,
        environment: MutableMapping[str, str],
        *,
        device: str,
        build_number: str,
        keymapper: Keymapper,
        command: str,
    ) -> None:
        """
        Create SOFTHSM_LOGS_DIR if missing, and put a relative EXEC_LOG_PATH
        under it.

        Raises:
            RuntimeError: If SOFTHSM_LOGS_DIR cannot be created.
        """
        logs_dir_raw = environment["SOFTHSM_LOGS_DIR"]
        logs_dir = Path(logs_dir_raw)
        if not logs_dir.is_dir() and environment.get("DRY_RUN") != "y":
            try:
                logs_dir.mkdir()
            except OSError as error:
                raise RuntimeError(
                    f"SOFTHSM_LOGS_DIR ({logs_dir_raw}) does not exist, and "
                    "failed to create it",
                ) from error
        date_format = environment.get("DATE_FORMAT") or "%Y%m%d-%H%M%S"
        timestamp = datetime.datetime.now(datetime.UTC).strftime(date_format)
        default_prefix = f"{build_number}-{device}-{timestamp}-{command}"
        _default(environment, "EXEC_LOG_PATH", f"{default_prefix}-exec.log")
        environment["EXEC_LOG_PATH"] = str(
            logs_dir / environment["EXEC_LOG_PATH"],
        )

    def split_devices_by_loaded_keys(
        self,
        environment: MutableMapping[str, str],
        keymapper: Keymapper,
        devices: Sequence[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Every device counts as loaded."""
        return tuple(devices), ()


class YubiHsmVendor(Vendor):
    """The YubiHSM vendor."""

    name = "yubihsm"
    display_name = "YubiHSM"
    pkcs11_module_paths = _module_paths(
        ("/x86_64-linux-gnu", "/aarch64-linux-gnu", "64", ""),
        "yubihsm_pkcs11.so",
    )

    def apply_source_exports(
        self,
        environment: MutableMapping[str, str],
    ) -> None:
        environment["KEYMAPPER"] = "static"
        environment["USE_APKSIGNER"] = "y"
        _default(environment, "YUBIHSM_CONNECTOR", DEFAULT_CONNECTOR_URL)
        _default(environment, "YUBIHSM_WRAP_KEY_ID", "0x0010")
        _default(
            environment,
            "YUBIHSM_KEY_CAPABILITIES",
            "sign-pkcs,sign-pss,sign-ecdsa,sign-eddsa",
        )
        _default(environment, "YUBIHSM_ONDEMAND_DOMAIN", "2")
        _default(environment, "YUBIHSM_EXPORTABLE_DOMAIN", "3")
        _default(
            environment,
            "KEYMAP_FILE",
            str(Path(__file__).resolve().parents[1] / "pkcs11/keymap.tsv"),
        )

    def initialize_interactive(
        self,
        environment: MutableMapping[str, str],
        *,
        assume_yes: bool,
    ) -> None:
        """
        Ask for the YubiHSM credentials, and for confirmation when a
        yubihsm-connector that this process cannot restart is already running.
        """
        if environment.get("NEVER_START_YUBIHSM_CONNECTOR") != "y":
            connector = YubiHsmConnector(
                connector_config_from_environment(
                    environment,
                    Path("/dev/null"),
                ),
            )
            if connector.is_running():
                print()
                print("yubihsm-connector is already running.")
                print(
                    "This means we will not be able to restart it if it "
                    "messes up.",
                )
                print(
                    "Before running this script, please stop the existing "
                    "connector by stopping its service,",
                )
                print("if any, or by running killall yubihsm-connector")
                if not confirm("Continue anyway?", assume_yes=assume_yes):
                    raise RuntimeError("yubihsm-connector is already running")

        ask_yubihsm_credentials(environment)

    def initialize(
        self,
        environment: MutableMapping[str, str],
        *,
        tmpdir: Path,
    ) -> None:
        """
        Prepare the YubiHSM for signing, failing when no password is given or
        the audit-log repository is missing.
        """
        read_yubihsm_password_file(environment)
        missing = [
            name
            for name in ("YUBIHSM_AUTHKEY", "YUBIHSM_PASSWORD")
            if name not in environment
        ]
        if missing:
            raise RuntimeError(f"{' and '.join(missing)} not set")
        auth_key = environment["YUBIHSM_AUTHKEY"]
        password = environment["YUBIHSM_PASSWORD"]
        environment["PKCS11_PIN"] = (
            auth_key.removeprefix("0x").rjust(4, "0") + password
        )

        environment["SIGNING_COMMAND_INTERCEPTOR"] = str(
            Path(__file__).resolve().parents[1]
            / "pkcs11"
            / "vendor.yubihsm.interceptor.py",
        )

        if environment.get("DRY_RUN") != "y":
            yubihsm_tmpdir = environment.get("YUBIHSM_TMPDIR")
            if not yubihsm_tmpdir:
                yubihsm_tmpdir = tempfile.mkdtemp(
                    prefix="yubihsm.",
                    dir=str(tmpdir),
                )
                Path(yubihsm_tmpdir).chmod(0o700)
                environment["YUBIHSM_TMPDIR"] = yubihsm_tmpdir

            pkcs11_conf = environment.get("YUBIHSM_PKCS11_CONF")
            if not pkcs11_conf:
                pkcs11_conf = str(Path(yubihsm_tmpdir) / "yubihsm_pkcs11.conf")
                Path(pkcs11_conf).write_text(
                    _YUBIHSM_PKCS11_CONF_TEMPLATE.format(
                        connector_url=environment.get(
                            "YUBIHSM_CONNECTOR",
                            DEFAULT_CONNECTOR_URL,
                        ),
                    ),
                )
                environment["YUBIHSM_PKCS11_CONF"] = pkcs11_conf

            if environment.get("NEVER_START_YUBIHSM_CONNECTOR") != "y":
                pid_file = Path(yubihsm_tmpdir) / "yubihsm_connector.pid"
                connector = YubiHsmConnector(
                    connector_config_from_environment(environment, pid_file),
                )
                connector.start()
                if pid_file.exists():
                    environment["YUBIHSM_CONNECTOR_PIDFILE"] = str(pid_file)

            _default(
                environment,
                "YUBIHSM_LOCKFILE",
                str(Path(yubihsm_tmpdir) / "yubihsm.lock"),
            )

            logs_dir = Path.cwd() / "logs"
            if not is_audit_log_repository(logs_dir):
                raise RuntimeError(
                    f"YUBIHSM_LOGS_DIR ({logs_dir}) is not the expected git "
                    "repository.\n"
                    "Are you sure you are calling this script from the right "
                    "place?\n"
                    "Did you clone the audit log git repository already?",
                )
            environment["YUBIHSM_LOGS_DIR"] = str(logs_dir)
        else:
            environment["YUBIHSM_TMPDIR"] = ""
            environment["YUBIHSM_LOCKFILE"] = ""

    def initialize_release(
        self,
        environment: MutableMapping[str, str],
        *,
        device: str,
        build_number: str,
        keymapper: Keymapper,
        command: str,
    ) -> None:
        """
        Name the release's audit and exec logs, save the audit log, and load
        the device's vbmeta key unless ENSURE_KEY_IS_AVAILABLE is not "y".

        Raises:
            RuntimeError: If the YubiHSM refuses an operation or cannot be
                reached.
        """
        if environment.get("DRY_RUN") == "y":
            return
        from yubihsm.exceptions import YubiHsmError

        config = yubihsm_config_from_environment(environment)
        with yubihsm_lock(environment.get("YUBIHSM_LOCKFILE")):
            try:
                identity = get_device_identity(config)
                name = identity.name
                logs_dir = Path(environment["YUBIHSM_LOGS_DIR"])
                default_prefix = f"{build_number}-{device}-{command}"
                audit_log_path = (
                    logs_dir / name / f"{formatted_date()}-{default_prefix}.log"
                )
                environment["AUDIT_LOG_PATH"] = str(audit_log_path)
                exec_dir = logs_dir / name / "exec"
                exec_dir.mkdir(parents=True, exist_ok=True)
                environment["EXEC_LOG_PATH"] = str(
                    exec_dir / f"{formatted_date()}-{default_prefix}.log",
                )

                key_id = keymapper.key_id("avb", "vbmeta", device)

                extract_and_save_audit_log(
                    config,
                    audit_log_path,
                    comment=f"BUILD_NUMBER={build_number} DEVICE={device} "
                    f"{command}.sh",
                )

                if (environment.get("ENSURE_KEY_IS_AVAILABLE") or "y") == "y":
                    is_ondemand = key_id_is_ondemand(keymapper)
                    with audit_logged(
                        config,
                        audit_log_path,
                        "Function: ensure_key_is_available",
                    ):
                        ensure_keys_are_available(
                            config,
                            Path(environment.get("KEY_DIR", "keys/")),
                            (key_id,) if is_ondemand(int(key_id, 16)) else (),
                            is_ondemand=is_ondemand,
                            lookup_domains=environment[
                                "YUBIHSM_ONDEMAND_DOMAIN"
                            ],
                        )
            except YubiHsmError as error:
                raise RuntimeError(f"YubiHSM failure: {error}") from error
            except ValueError as error:
                raise RuntimeError(str(error)) from error

    def finalize_release(
        self,
        environment: MutableMapping[str, str],
        *,
        device: str,
        build_number: str,
        record_finish: bool,
        command: str,
    ) -> None:
        """
        Record the end of the release in the audit log when the release
        initialization completed. Failures are reported and ignored.
        """
        if (
            not record_finish
            or not environment.get("AUDIT_LOG_PATH")
            or environment.get("DRY_RUN") == "y"
        ):
            return
        config = yubihsm_config_from_environment(environment)
        try:
            with yubihsm_lock(environment.get("YUBIHSM_LOCKFILE")):
                extract_and_save_audit_log(
                    config,
                    Path(environment["AUDIT_LOG_PATH"]),
                    comment=f"Finished BUILD_NUMBER={build_number} "
                    f"DEVICE={device} {command}.sh",
                )
        except Exception as error:
            print(f"Failed to extract logs: {error}", file=sys.stderr)

    def split_devices_by_loaded_keys(
        self,
        environment: MutableMapping[str, str],
        keymapper: Keymapper,
        devices: Sequence[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        config = yubihsm_config_from_environment(environment)
        key_ids_by_device = {
            device: keymapper.device_key_ids(device) for device in devices
        }
        for device, key_ids in key_ids_by_device.items():
            if not key_ids:
                raise RuntimeError(f"The keymapper has no keys for {device}")
        if environment.get("DRY_RUN") == "y":
            return (), tuple(devices)
        loaded = get_loaded_key_ids(config)
        with_loaded_keys: list[str] = []
        without_loaded_keys: list[str] = []
        for device in devices:
            if all(
                int(key_id, 16) in loaded
                for key_id in key_ids_by_device[device]
            ):
                with_loaded_keys.append(device)
            else:
                without_loaded_keys.append(device)
        return tuple(with_loaded_keys), tuple(without_loaded_keys)

    def ensure_keys_for_devices(
        self,
        environment: MutableMapping[str, str],
        keymapper: Keymapper,
        devices: Sequence[str],
    ) -> None:
        """
        Load the keys the devices need under YUBIHSM_LOCKFILE, and extract
        the audit log after each key, into AUDIT_LOG_PATH or a load-keys
        log named after the HSM, and once more if loading fails.
        """
        config = yubihsm_config_from_environment(environment)
        with yubihsm_lock(environment.get("YUBIHSM_LOCKFILE")):
            audit_log_path: Path | None = None
            if environment.get("DRY_RUN") != "y":
                if environment.get("AUDIT_LOG_PATH"):
                    audit_log_path = Path(environment["AUDIT_LOG_PATH"])
                else:
                    identity = get_device_identity(config)
                    audit_log_path = (
                        Path(environment["YUBIHSM_LOGS_DIR"])
                        / identity.name
                        / f"{formatted_date()}-load-keys.log"
                    )

            def extract(comment: str) -> None:
                if audit_log_path is not None:
                    extract_and_save_audit_log(
                        config,
                        audit_log_path,
                        comment=comment,
                    )

            try:
                key_dir = Path(environment.get("KEY_DIR", "keys/"))
                ondemand_domain = environment["YUBIHSM_ONDEMAND_DOMAIN"]
                key_ids_by_device = {
                    device: keymapper.device_key_ids(device)
                    for device in devices
                }
                needed_keys: set[str] = set()
                for device, key_ids in key_ids_by_device.items():
                    if not key_ids:
                        raise RuntimeError(
                            f"The keymapper has no keys for {device}",
                        )
                    needed_keys.update(key_ids)
                ensure_keys_are_available(
                    config,
                    key_dir,
                    tuple(sorted(needed_keys)),
                    is_ondemand=key_id_is_ondemand(keymapper),
                    lookup_domains=ondemand_domain,
                    after_key=lambda key_id: extract(
                        "Function: ensure_key_is_available "
                        f"Key: {key_id} Result: 0",
                    ),
                )
            except Exception:
                with contextlib.suppress(Exception):
                    extract(
                        "Function: ensure_all_keys_available_for_devices "
                        "Result: 1",
                    )
                raise

    def cleanup(
        self,
        environment: MutableMapping[str, str],
        *,
        inherited: Mapping[str, str],
    ) -> None:
        """
        Stop the connector this process started, if any, and remove the
        YUBIHSM_TMPDIR it created.
        """
        pid_file = environment.get("YUBIHSM_CONNECTOR_PIDFILE")
        if pid_file and pid_file != inherited.get("YUBIHSM_CONNECTOR_PIDFILE"):
            try:
                YubiHsmConnector(
                    YubiHsmConnectorConfig(
                        connector_url="",
                        pid_file=Path(pid_file),
                    ),
                ).stop()
            except RuntimeError as error:
                print(error, file=sys.stderr)
        tmpdir = environment.get("YUBIHSM_TMPDIR")
        if tmpdir and tmpdir != inherited.get("YUBIHSM_TMPDIR"):
            shutil.rmtree(tmpdir, ignore_errors=True)


VENDORS: dict[str, type[Vendor]] = {
    SoftHsmVendor.name: SoftHsmVendor,
    YubiHsmVendor.name: YubiHsmVendor,
}
