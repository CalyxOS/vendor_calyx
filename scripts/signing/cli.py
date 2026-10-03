#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Command-line entry points for backend-neutral signing operations.
"""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import write_file_atomically

if TYPE_CHECKING:
    from .configuration import (
        PinSource,
        Pkcs11BackendConfiguration,
    )
    from .keymap import Keymapper
    from .metadata import SigningMetadata
    from .models import KeyReference, KeySpec
    from .pkcs11 import Pkcs11Backend
    from .vendor_yubihsm import YubiHsmConfig

_BACKEND_COMMANDS = (
    "key-exists",
    "certificate-exists",
    "generate-key",
    "generate-certificate",
)


class _RejectRawValue(argparse.Action):
    """
    Reject a raw secret value without echoing it in an argparse error.
    """

    def __init__(
        self,
        *args: Any,
        message: str,
        **kwargs: Any,
    ) -> None:
        """
        Store the error message this action reports when triggered.

        Args:
            *args: Positional arguments forwarded to argparse.Action.
            message: Error message directing callers to the accepted
                external sources for this value.
            **kwargs: Keyword arguments forwarded to argparse.Action.

        Returns:
            None.
        """
        self._message = message
        super().__init__(*args, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        """
        Stop parsing and direct callers to an external value source.

        Args:
            parser: Parser handling the rejected option.
            namespace: Partially populated argument namespace.
            values: Raw value intentionally ignored to avoid disclosure.
            option_string: Option spelling used by the caller.

        Returns:
            None.

        Raises:
            SystemExit: Always, because raw command-line secrets are
                forbidden.
        """
        del namespace, values, option_string
        parser.error(self._message)


def _add_pin_group(
    parser: argparse.ArgumentParser,
    prefix: str,
    *,
    required: bool = False,
) -> None:
    """
    Add a mutually exclusive env/file/raw PIN-source group to a command.

    Args:
        parser: Subcommand parser to configure.
        prefix: Flag prefix identifying which PIN this group supplies,
            e.g. "pin" for --pin-env/--pin-file/--pin, or "so-pin" for
            --so-pin-env/--so-pin-file/--so-pin.
        required: Whether the group must supply exactly one source.

    Returns:
        None.
    """
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument(f"--{prefix}-env")
    group.add_argument(
        f"--{prefix}-file",
        type=Path,
    )
    group.add_argument(
        f"--{prefix}",
        action=_RejectRawValue,
        message=(
            f"raw PINs are forbidden, use --{prefix}-env or --{prefix}-file"
        ),
        help=argparse.SUPPRESS,
    )


def _add_backend_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add backend selection and typed configuration arguments to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    parser.add_argument(
        "--module",
        type=Path,
    )
    token = parser.add_mutually_exclusive_group()
    token.add_argument("--token-label")
    token.add_argument("--slot")
    _add_pin_group(parser, "pin")
    _add_pin_group(parser, "discovery-pin")
    _add_pin_group(parser, "signing-pin")
    parser.add_argument(
        "--use-so-pin",
        action="store_true",
    )
    parser.add_argument(
        "--list-requires-no-pin",
        action="store_true",
    )
    parser.add_argument("--pkcs11-tool")
    parser.add_argument(
        "--openssl",
        default="openssl",
    )
    parser.add_argument(
        "--openssl-engine",
        type=Path,
    )
    parser.add_argument(
        "--certificate-days",
        type=int,
    )


def _add_reference_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add backend-neutral key-reference arguments to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    parser.add_argument(
        "--key-id",
        default="",
    )
    parser.add_argument(
        "--label",
        default="",
    )


def _add_algorithm_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add key-algorithm and export-policy arguments to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    parser.add_argument(
        "--algorithm",
        choices=("RSA",),
        required=True,
    )
    parser.add_argument(
        "--key-size",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--exportable",
        action="store_true",
    )


def _add_yubihsm_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add YubiHSM connector and credential arguments to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    parser.add_argument(
        "--connector",
        default="http://127.0.0.1:12345",
    )
    parser.add_argument(
        "--authkey",
        default="0x0001",
    )
    password = parser.add_mutually_exclusive_group(required=True)
    password.add_argument("--password-env")
    password.add_argument(
        "--password-file",
        type=Path,
    )
    password.add_argument(
        "--password",
        action=_RejectRawValue,
        message=(
            "raw passwords are forbidden, use --password-env or --password-file"
        ),
        help=argparse.SUPPRESS,
    )


def _add_yubihsm_connector_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add local yubihsm-connector process management arguments to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    parser.add_argument(
        "--connector",
        default="http://127.0.0.1:12345",
    )
    parser.add_argument(
        "--pid-file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--binary",
        default="yubihsm-connector",
    )


def _positive_int(value: str) -> int:
    """
    Parse a job count, which must be a positive integer, unlike the
    0, N% and +N forms GNU parallel's -j also takes.

    Raises:
        argparse.ArgumentTypeError: If value is not a positive integer.
    """
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(
            f"must be a positive number, not {value!r}",
        )
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser without reading configuration or state.

    Returns:
        The configured top-level argument parser.
    """
    parser = argparse.ArgumentParser(prog="python3 -m signing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keymap = subparsers.add_parser("generate-keymap")
    keymap.add_argument(
        "--metadata",
        type=Path,
        default=None,
    )
    keymap.add_argument(
        "--devices",
        nargs="+",
        required=True,
    )
    keymap.add_argument(
        "--keymapper",
        choices=("id2b", "legacy"),
        default="id2b",
    )

    release_args = subparsers.add_parser("build-release-args")
    release_args.add_argument(
        "--metadata",
        type=Path,
        default=None,
    )
    release_args.add_argument(
        "--keymapper",
        choices=("id2b", "legacy"),
        default="id2b",
    )
    release_args.add_argument(
        "--device",
        required=True,
    )
    release_args.add_argument(
        "--key-dir",
        default="keys/",
    )
    release_args.add_argument(
        "--key-suffix",
        default=".pem",
    )
    release_args.add_argument(
        "--avb-algorithm",
        default="SHA256_RSA4096",
    )
    release_args.add_argument(
        "--avb-rollback-index-override",
        default=None,
    )
    release_args.add_argument(
        "--extra-signing-arg",
        action="append",
        default=[],
    )
    release_args.add_argument(
        "--extra-ota-arg",
        action="append",
        default=[],
    )

    signable_devices = subparsers.add_parser("gather-signable-devices")
    signable_devices.add_argument(
        "--devices",
        nargs="*",
        default=[],
    )
    signable_devices.add_argument(
        "--all-devices",
        nargs="+",
        required=True,
    )

    device_builds = subparsers.add_parser("gather-device-builds")
    device_builds.add_argument(
        "--target-files",
        nargs="*",
        default=[],
    )
    device_builds.add_argument("--build-numbers", nargs="*")

    prev_builds = subparsers.add_parser("find-prev-builds")
    prev_builds.add_argument(
        "--archive-dirs",
        nargs="*",
        default=[],
    )
    prev_builds.add_argument(
        "--device-next-build",
        action="append",
        default=[],
    )
    prev_builds.add_argument(
        "--build-numbers",
        nargs="*",
        default=[],
    )
    prev_builds.add_argument(
        "--prev-build-numbers",
        nargs="*",
        default=None,
    )
    prev_builds.add_argument(
        "--avb-rollback-index-override",
        default=None,
    )

    partition = subparsers.add_parser("partition-signing-plan")
    partition.add_argument(
        "--devices-with-loaded-keys",
        nargs="*",
        default=[],
    )
    partition.add_argument(
        "--devices-without-loaded-keys",
        nargs="*",
        default=[],
    )
    partition.add_argument(
        "--device-next-build",
        action="append",
        default=[],
    )
    partition.add_argument(
        "--device-prev-build",
        action="append",
        default=[],
    )
    partition.add_argument(
        "--device-preexisting-build",
        action="append",
        default=[],
    )
    partition.add_argument(
        "--avb-rollback-index-override",
        default=None,
    )

    subparsers.add_parser("run-release-tool")

    checksum = subparsers.add_parser("compute-sha256sum")
    checksum.add_argument("path")

    sign_builds_parser = subparsers.add_parser("sign-builds")
    sign_builds_parser.add_argument(
        "--pairs",
        nargs="+",
        required=True,
        help="device,build,target_build entries",
    )
    sign_builds_parser.add_argument(
        "--release-script",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "release.sh",
    )
    sign_builds_parser.add_argument(
        "--archive-dir",
        type=Path,
        default=Path("archive"),
    )
    sign_builds_parser.add_argument("--jobs", type=_positive_int, required=True)
    sign_builds_parser.add_argument(
        "--original-tmpdir",
        type=Path,
        default=Path(os.environ.get("ORIGINAL_TMPDIR", "/dev/shm")),
    )

    generate_incrementals_parser = subparsers.add_parser(
        "generate-incrementals",
    )
    generate_incrementals_parser.add_argument(
        "--triples",
        nargs="+",
        required=True,
        help="device,old_build,new_build entries (new_build may be empty)",
    )
    generate_incrementals_parser.add_argument(
        "--generate-delta-script",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "generate_delta.sh",
    )
    generate_incrementals_parser.add_argument(
        "--jobs",
        type=_positive_int,
        required=True,
    )
    generate_incrementals_parser.add_argument(
        "--original-tmpdir",
        type=Path,
        default=Path(os.environ.get("ORIGINAL_TMPDIR", "/dev/shm")),
    )
    subparsers.add_parser("mkkey", add_help=False)

    provision_avb = subparsers.add_parser("provision-avb-key")
    provision_avb.add_argument(
        "--private-key",
        type=Path,
        required=True,
    )
    provision_avb.add_argument(
        "--public-key",
        type=Path,
        required=True,
    )
    provision_avb.add_argument(
        "--avbtool",
        required=True,
    )

    provision_rsa = subparsers.add_parser("provision-rsa-key")
    provision_rsa.add_argument(
        "--private-key",
        type=Path,
        required=True,
    )

    migrate_runtime = subparsers.add_parser("migrate-runtime-key")
    migrate_runtime.add_argument(
        "--key-directory",
        type=Path,
        required=True,
    )

    update_keys = subparsers.add_parser("update-keys")
    update_keys.add_argument(
        "--metadata",
        type=Path,
        default=None,
    )
    update_keys.add_argument(
        "--keymapper",
        choices=("id2b", "legacy"),
        required=True,
    )
    update_keys.add_argument(
        "--key-directory",
        type=Path,
        required=True,
    )
    update_keys.add_argument(
        "--device",
        required=True,
    )
    update_keys.add_argument(
        "--subject",
        required=True,
    )
    update_keys.add_argument(
        "--avbtool",
        required=True,
    )

    generate_asymmetric_key_parser = subparsers.add_parser(
        "generate-asymmetric-key",
    )
    _add_yubihsm_arguments(generate_asymmetric_key_parser)
    generate_asymmetric_key_parser.add_argument(
        "--key-id",
        required=True,
    )
    generate_asymmetric_key_parser.add_argument(
        "--label",
        required=True,
    )
    generate_asymmetric_key_parser.add_argument(
        "--domain",
        required=True,
    )
    generate_asymmetric_key_parser.add_argument(
        "--capabilities",
        required=True,
    )
    generate_asymmetric_key_parser.add_argument(
        "--algorithm",
        required=True,
    )

    attest_key = subparsers.add_parser("attest-key")
    _add_yubihsm_arguments(attest_key)
    attest_key.add_argument(
        "--key-id",
        required=True,
    )
    attest_key.add_argument(
        "--attestation-id",
        default="0",
    )
    attest_key.add_argument(
        "--output",
        default="-",
    )

    extract_audit_log = subparsers.add_parser("extract-audit-log")
    _add_yubihsm_arguments(extract_audit_log)
    extract_audit_log.add_argument(
        "--log-file",
        type=Path,
        required=True,
    )
    extract_audit_log.add_argument("--comment")

    export_wrapped_key = subparsers.add_parser("export-wrapped-key")
    _add_yubihsm_arguments(export_wrapped_key)
    export_wrapped_key.add_argument(
        "--wrap-id",
        default="0x0010",
    )
    export_wrapped_key.add_argument(
        "--key-id",
        required=True,
    )
    export_wrapped_key.add_argument(
        "--output",
        default="-",
    )

    import_wrapped_key = subparsers.add_parser("import-wrapped-key")
    _add_yubihsm_arguments(import_wrapped_key)
    import_wrapped_key.add_argument(
        "--wrap-id",
        default="0x0010",
    )
    import_wrapped_key.add_argument(
        "--key-id",
        required=True,
    )
    import_wrapped_key.add_argument(
        "--input",
        default="-",
    )

    get_certificate_parser = subparsers.add_parser("get-certificate")
    _add_yubihsm_arguments(get_certificate_parser)
    get_certificate_parser.add_argument(
        "--key-id",
        required=True,
    )
    get_certificate_parser.add_argument(
        "--output",
        default="-",
    )

    import_certificate_parser = subparsers.add_parser("import-certificate")
    _add_yubihsm_arguments(import_certificate_parser)
    import_certificate_parser.add_argument(
        "--key-id",
        required=True,
    )
    import_certificate_parser.add_argument(
        "--input",
        default="-",
    )
    import_certificate_parser.add_argument(
        "--domain",
        required=True,
    )
    import_certificate_parser.add_argument(
        "--capabilities",
        required=True,
    )

    limit_ondemand_objects_parser = subparsers.add_parser(
        "limit-ondemand-objects",
    )
    _add_yubihsm_arguments(limit_ondemand_objects_parser)
    limit_ondemand_objects_parser.add_argument(
        "--key-dir",
        type=Path,
        required=True,
    )
    limit_ondemand_objects_parser.add_argument(
        "--ondemand-domain",
        required=True,
    )
    limit_ondemand_objects_parser.add_argument(
        "--audit-log",
        type=Path,
    )
    limit_ondemand_objects_parser.add_argument(
        "--no-log-fail",
        action="store_true",
    )
    limit_ondemand_objects_parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    ensure_keys_available = subparsers.add_parser("ensure-keys-available")
    _add_yubihsm_arguments(ensure_keys_available)
    ensure_keys_available.add_argument(
        "--wrap-id",
        default="0x0010",
    )
    ensure_keys_available.add_argument(
        "--key-dir",
        type=Path,
        required=True,
    )
    ensure_keys_available.add_argument(
        "--key-id",
        dest="key_ids",
        action="append",
        required=True,
    )
    ensure_keys_available.add_argument(
        "--ondemand-key-id",
        dest="ondemand_key_ids",
        action="append",
        default=[],
    )
    ensure_keys_available.add_argument(
        "--restore-mode",
        action="store_true",
    )
    ensure_keys_available.add_argument(
        "--no-verify-key-ids",
        action="store_true",
    )
    ensure_keys_available.add_argument(
        "--exportable-domain",
        required=True,
    )
    ensure_keys_available.add_argument(
        "--ondemand-domain",
        required=True,
    )
    ensure_keys_available.add_argument(
        "--opaque-capabilities",
        required=True,
    )
    ensure_keys_available.add_argument(
        "--audit-log",
        type=Path,
    )

    partition_devices = subparsers.add_parser(
        "partition-devices-by-key-availability",
    )
    _add_yubihsm_arguments(partition_devices)
    partition_devices.add_argument(
        "--keymap-file",
        type=Path,
        required=True,
    )
    partition_devices.add_argument(
        "--device",
        dest="devices",
        action="append",
        default=[],
    )

    ensure_all_keys_for_devices = subparsers.add_parser(
        "ensure-all-keys-available-for-devices",
    )
    _add_yubihsm_arguments(ensure_all_keys_for_devices)
    ensure_all_keys_for_devices.add_argument(
        "--wrap-id",
        default="0x0010",
    )
    ensure_all_keys_for_devices.add_argument(
        "--keymap-file",
        type=Path,
        required=True,
    )
    ensure_all_keys_for_devices.add_argument(
        "--key-dir",
        type=Path,
        required=True,
    )
    ensure_all_keys_for_devices.add_argument(
        "--device",
        dest="devices",
        action="append",
        default=[],
    )
    ensure_all_keys_for_devices.add_argument(
        "--ondemand-key-id",
        dest="ondemand_key_ids",
        action="append",
        default=[],
    )
    ensure_all_keys_for_devices.add_argument(
        "--exportable-domain",
        required=True,
    )
    ensure_all_keys_for_devices.add_argument(
        "--ondemand-domain",
        required=True,
    )
    ensure_all_keys_for_devices.add_argument(
        "--audit-log",
        type=Path,
    )
    ensure_all_keys_for_devices.add_argument(
        "--opaque-capabilities",
        required=True,
    )

    restore_all_keys = subparsers.add_parser("restore-all-keys-and-certs")
    _add_yubihsm_arguments(restore_all_keys)
    restore_all_keys.add_argument(
        "--wrap-id",
        default="0x0010",
    )
    restore_all_keys.add_argument(
        "--key-dir",
        type=Path,
        required=True,
    )
    restore_all_keys.add_argument(
        "--log-file",
        type=Path,
        required=True,
    )
    restore_all_keys.add_argument(
        "--ondemand-key-id",
        dest="ondemand_key_ids",
        action="append",
        default=[],
    )
    restore_all_keys.add_argument(
        "--exportable-domain",
        required=True,
    )
    restore_all_keys.add_argument(
        "--ondemand-domain",
        required=True,
    )
    restore_all_keys.add_argument(
        "--opaque-capabilities",
        required=True,
    )

    get_device_identity_parser = subparsers.add_parser("get-device-identity")
    _add_yubihsm_arguments(get_device_identity_parser)

    get_loaded_key_status_parser = subparsers.add_parser(
        "get-loaded-key-status",
    )
    _add_yubihsm_arguments(get_loaded_key_status_parser)

    object_exists_parser = subparsers.add_parser("yubihsm-object-exists")
    _add_yubihsm_arguments(object_exists_parser)
    object_exists_parser.add_argument("--key-id", required=True)
    object_exists_parser.add_argument(
        "--type",
        choices=("key", "certificate"),
        required=True,
    )

    start_connector = subparsers.add_parser("start-yubihsm-connector")
    _add_yubihsm_connector_arguments(start_connector)

    stop_connector = subparsers.add_parser("stop-yubihsm-connector")
    _add_yubihsm_connector_arguments(stop_connector)

    init_token = subparsers.add_parser("init-pkcs11-token")
    init_token.add_argument(
        "--module",
        type=Path,
        required=True,
    )
    init_token.add_argument(
        "--pkcs11-tool",
        default="pkcs11-tool",
    )
    init_token.add_argument(
        "--label",
        required=True,
    )
    _add_pin_group(init_token, "so-pin", required=True)
    _add_pin_group(init_token, "pin", required=True)

    for name in _BACKEND_COMMANDS:
        command = subparsers.add_parser(name)
        _add_backend_arguments(command)
        _add_reference_arguments(command)
        if name in {"generate-key", "generate-certificate"}:
            _add_algorithm_arguments(command)
        if name == "generate-certificate":
            command.add_argument(
                "--subject",
                required=True,
            )
            command.add_argument("--output")
    return parser


def _pkcs11_configuration_from_args(
    args: argparse.Namespace,
) -> Pkcs11BackendConfiguration:
    """
    Validate and construct the PKCS#11 backend's configuration.

    Args:
        args: Parsed command-line namespace.

    Returns:
        The PKCS#11 backend configuration.

    Raises:
        _UsageError: If --module is missing.
    """
    from .configuration import (
        EnvironmentPin,
        FilePin,
        Pkcs11BackendConfiguration,
    )
    from .models import DEFAULT_CERTIFICATE_DAYS

    if args.module is None:
        raise _UsageError("--module is required for the PKCS#11 backend")
    pin_source: PinSource | None = None
    if args.pin_env is not None:
        pin_source = EnvironmentPin(args.pin_env)
    elif args.pin_file is not None:
        pin_source = FilePin(args.pin_file)
    discovery_pin_source: PinSource | None = None
    if args.discovery_pin_env is not None:
        discovery_pin_source = EnvironmentPin(args.discovery_pin_env)
    elif args.discovery_pin_file is not None:
        discovery_pin_source = FilePin(args.discovery_pin_file)
    signing_pin_source: PinSource | None = None
    if args.signing_pin_env is not None:
        signing_pin_source = EnvironmentPin(args.signing_pin_env)
    elif args.signing_pin_file is not None:
        signing_pin_source = FilePin(args.signing_pin_file)
    return Pkcs11BackendConfiguration(
        module=args.module,
        pin_source=pin_source,
        discovery_pin_source=discovery_pin_source,
        signing_pin_source=signing_pin_source,
        token_label=args.token_label,
        slot=args.slot,
        tool=args.pkcs11_tool or "pkcs11-tool",
        openssl=args.openssl,
        openssl_engine=args.openssl_engine,
        certificate_days=(
            DEFAULT_CERTIFICATE_DAYS
            if args.certificate_days is None
            else args.certificate_days
        ),
        use_so_pin=args.use_so_pin,
        list_requires_no_pin=args.list_requires_no_pin,
    )


def _keymapper_from_args(
    args: argparse.Namespace,
    metadata: SigningMetadata,
) -> Keymapper:
    """
    Construct the explicitly selected metadata keymapper.

    Args:
        args: Parsed namespace containing a ``keymapper`` selection.
        metadata: Validated signing metadata to map.

    Returns:
        Legacy path mapper or the default two-byte ID mapper.
    """
    from .keymap import Id2bKeymapper, LegacyKeymapper

    if args.keymapper == "legacy":
        return LegacyKeymapper(metadata)
    return Id2bKeymapper(metadata)


def _yubihsm_password_from_args(args: argparse.Namespace) -> str:
    """
    Resolve the YubiHSM password from its configured external source.

    Args:
        args: Parsed namespace containing a password source selection.

    Returns:
        The resolved password.

    Raises:
        KeyError: If a configured environment variable is absent.
        OSError: If a configured password file cannot be read.
        ValueError: If the resolved password is invalid.
    """
    from .configuration import EnvironmentPin, FilePin

    if args.password_env is not None:
        return EnvironmentPin(args.password_env).resolve()
    return FilePin(args.password_file).resolve()


def _yubihsm_config_from_args(
    args: argparse.Namespace,
    *,
    attestation_id: str = "0",
    wrap_id: str = "0x0010",
) -> YubiHsmConfig:
    """
    Construct a YubiHSM connector configuration from parsed arguments.

    Args:
        args: Parsed namespace containing connector and credential
            fields.
        attestation_id: Attestation key ID, for attest-key.
        wrap_id: Wrap key ID, for the wrapped-key commands.

    Returns:
        The configuration supplied to YubiHSM backend operations.

    Raises:
        KeyError: If a configured environment variable is absent.
        OSError: If a configured password file cannot be read.
        ValueError: If the resolved password is invalid.
    """
    from .vendor_yubihsm import YubiHsmConfig

    return YubiHsmConfig(
        connector_url=args.connector,
        auth_key=args.authkey,
        password=_yubihsm_password_from_args(args),
        attestation_id=attestation_id,
        wrap_id=wrap_id,
    )


def _reference_from_args(args: argparse.Namespace) -> KeyReference:
    """
    Construct a backend-neutral key reference from parsed arguments.

    Args:
        args: Parsed namespace containing key identity fields.

    Returns:
        The key reference supplied to backend operations.
    """
    from .models import KeyReference

    return KeyReference(key_id=args.key_id, label=args.label)


def _spec_from_args(args: argparse.Namespace) -> KeySpec:
    """
    Construct a key-generation specification from parsed arguments.

    Args:
        args: Parsed namespace containing identity and algorithm fields.

    Returns:
        The key specification supplied to backend operations.

    Raises:
        ValueError: If the key size is not positive.
    """
    from .models import KeySpec

    return KeySpec(
        reference=_reference_from_args(args),
        key_size=args.key_size,
        exportable=args.exportable,
    )


def _parse_key_value_ints(values: list[str]) -> dict[str, int]:
    """
    Parse repeated --flag=key=value build number arguments into a mapping.

    Args:
        values: Strings of the form "key=value", value a build number.

    Returns:
        The parsed key to BuildNumber mapping.

    Raises:
        ValueError: If a value is malformed or missing its "=" separator.
    """
    from .sign_planning import BuildNumber

    result: dict[str, int] = {}
    for entry in values:
        key, separator, value = entry.partition("=")
        if not separator:
            raise ValueError(f"expected key=value, got: {entry}")
        result[key] = BuildNumber(value)
    return result


def _parse_sign_pair(value: str) -> tuple[str, int, int]:
    """Parse one "device,build,target_build" --pairs entry."""
    from .sign_planning import BuildNumber

    device, build, target_build = value.split(",")
    return device, BuildNumber(build), BuildNumber(target_build)


def _parse_incremental_triple(value: str) -> tuple[str, int, int | None]:
    """Parse one "device,old_build,new_build" --triples entry."""
    from .sign_planning import BuildNumber

    device, old_build, new_build = value.split(",")
    return (
        device,
        BuildNumber(old_build),
        BuildNumber(new_build) if new_build else None,
    )


def _read_binary(location: str) -> bytes:
    """
    Read binary input from a file or standard input.

    Args:
        location: File path, or ``-`` for standard input.

    Returns:
        Complete binary input contents.

    Raises:
        OSError: If a selected input file cannot be read.
    """
    if location == "-":
        return sys.stdin.buffer.read()
    return Path(location).read_bytes()


def write_binary(location: str, contents: bytes) -> None:
    """
    Write binary output to a file or standard output.

    A file is written through a temporary file in the same directory and
    renamed into place, so that an interrupted write never leaves a
    partial file at the destination.

    Args:
        location: File path, or ``-`` for standard output.
        contents: Bytes to write.

    Returns:
        None.

    Raises:
        OSError: If a selected output file cannot be written.
    """
    if location == "-":
        sys.stdout.buffer.write(contents)
        return
    write_file_atomically(Path(location), contents)


def _build_backend(args: argparse.Namespace) -> Pkcs11Backend:
    """
    Construct the backend the key commands' arguments configure.

    Args:
        args: Parsed namespace containing the backend fields.

    Returns:
        The constructed backend instance.

    Raises:
        _UsageError: If required backend-specific arguments are missing.
    """
    return _pkcs11_configuration_from_args(args).create_backend()


def _cmd_run_release_tool(args: argparse.Namespace) -> int:
    """
    Run the wrapped release tool with the arguments following ``--``.

    Args:
        args: Parsed namespace carrying the pre-separated ``tool_argv``.

    Returns:
        The wrapped tool's exit status.

    Raises:
        _UsageError: If no tool invocation followed ``--``.
    """
    from .release_execution import run_release_tool

    if not args.tool_argv:
        raise _UsageError("run-release-tool requires -- <tool> [args...]")
    return run_release_tool(args.tool_argv)


def _cmd_compute_sha256sum(args: argparse.Namespace) -> int:
    """
    Print the release tool's sha256sum-format digest of one file.

    Args:
        args: Parsed namespace containing the target path.

    Returns:
        Zero on success.
    """
    from .release_execution import format_sha256sum

    print(format_sha256sum(args.path), end="")
    return 0


def _cmd_sign_builds(args: argparse.Namespace) -> int:
    """
    Sign the requested device/build pairs and archive them.

    Args:
        args: Parsed namespace containing pairs and executor settings.

    Returns:
        The signing executor's exit status.
    """
    from .sign_execution import sign_builds

    return sign_builds(
        [_parse_sign_pair(pair) for pair in args.pairs],
        release_script=args.release_script,
        archive_dir=args.archive_dir,
        jobs=args.jobs,
        original_tmpdir=args.original_tmpdir,
    )


def _cmd_generate_incrementals(args: argparse.Namespace) -> int:
    """
    Generate incremental OTAs for the requested device/build triples.

    Args:
        args: Parsed namespace containing triples and executor settings.

    Returns:
        The incremental-generation executor's exit status.
    """
    from .sign_execution import generate_incrementals

    return generate_incrementals(
        [_parse_incremental_triple(triple) for triple in args.triples],
        generate_delta_script=args.generate_delta_script,
        jobs=args.jobs,
        original_tmpdir=args.original_tmpdir,
    )


def _cmd_mkkey(args: argparse.Namespace) -> int:
    """
    Generate one key for mkkey.sh.

    Args:
        args: Parsed namespace containing the script path and arguments.

    Returns:
        The script's exit status.
    """
    from .key_scripts import mkkey_main

    program, *arguments = args.arguments or ["mkkey.sh"]
    return mkkey_main(program, arguments)


def _cmd_generate_keymap(args: argparse.Namespace) -> int:
    """
    Print the TSV keymap for the requested devices.

    Args:
        args: Parsed namespace containing metadata path and devices.

    Returns:
        Zero on success.
    """
    from .metadata import default_metadata_path, load_metadata

    metadata = load_metadata(args.metadata or default_metadata_path())
    mapper = _keymapper_from_args(args, metadata)
    print(mapper.to_tsv(args.devices), end="")
    return 0


def _cmd_build_release_args(args: argparse.Namespace) -> int:
    """
    Print a release's null-delimited avb/signing/ota argument streams.

    Args:
        args: Parsed namespace containing metadata path and device.

    Returns:
        Zero on success, one if the device has no rollback support.
    """
    from .metadata import default_metadata_path, load_metadata
    from .release_arguments import (
        UnsupportedRollbackDeviceError,
        build_release_arguments,
        make_get_key,
    )

    metadata = load_metadata(args.metadata or default_metadata_path())
    keymapper = _keymapper_from_args(args, metadata)
    get_key = make_get_key(
        keymapper,
        device=args.device,
        key_dir=args.key_dir,
        key_suffix=args.key_suffix,
    )
    try:
        result = build_release_arguments(
            metadata,
            get_key,
            device=args.device,
            avb_rollback_index_override=args.avb_rollback_index_override,
            avb_algorithm=args.avb_algorithm,
            extra_signing_args=tuple(args.extra_signing_arg),
            extra_ota_args=tuple(args.extra_ota_arg),
        )
    except UnsupportedRollbackDeviceError as error:
        print(error)
        return 1
    out = sys.stdout.buffer
    for stream, values in (
        ("avb", result.avb_arguments),
        ("signing", result.signing_args),
        ("ota", result.ota_args),
    ):
        for value in values:
            out.write(stream.encode() + b"\0" + value.encode() + b"\0")
    return 0


def _cmd_gather_signable_devices(args: argparse.Namespace) -> int:
    """
    Print the null-delimited subset of devices eligible to be signed.

    Args:
        args: Parsed namespace containing device selection.

    Returns:
        Zero on success.
    """
    from .sign_planning import gather_signable_devices

    result = gather_signable_devices(args.devices, args.all_devices)
    out = sys.stdout.buffer
    for device in result:
        out.write(device.encode() + b"\0")
    return 0


def _cmd_gather_device_builds(args: argparse.Namespace) -> int:
    """
    Print the null-delimited device-to-build mapping to sign.

    Args:
        args: Parsed namespace containing target files and build numbers.

    Returns:
        Zero on success.
    """
    from .sign_planning import (
        gather_device_builds_to_sign,
        gather_latest_device_builds,
        parse_build_numbers,
    )

    if args.build_numbers is not None:
        device_to_build = gather_device_builds_to_sign(
            args.target_files,
            parse_build_numbers(args.build_numbers),
        )
    else:
        device_to_build = gather_latest_device_builds(args.target_files)
    out = sys.stdout.buffer
    for device, build in device_to_build.items():
        out.write(device.encode() + b"\0" + str(build).encode() + b"\0")
    return 0


def _cmd_find_prev_builds(args: argparse.Namespace) -> int:
    """
    Print the null-delimited previously-signed and preexisting builds.

    Args:
        args: Parsed namespace containing archive dirs and build numbers.

    Returns:
        Zero on success.
    """
    from .sign_planning import (
        find_prev_signed_device_builds,
        parse_build_numbers,
    )

    device_to_next_build = _parse_key_value_ints(args.device_next_build)

    def target_files_exists(
        archive_dir: str,
        device: str,
        build: int,
    ) -> bool:
        return Path(
            f"archive/{archive_dir}/{device}-target_files-{build}.zip",
        ).is_file()

    prev_result = find_prev_signed_device_builds(
        args.archive_dirs,
        device_to_next_build=device_to_next_build,
        build_numbers=parse_build_numbers(args.build_numbers),
        prev_build_numbers=(
            None
            if args.prev_build_numbers is None
            else parse_build_numbers(args.prev_build_numbers)
        ),
        avb_rollback_index_override=args.avb_rollback_index_override,
        target_files_exists=target_files_exists,
    )
    out = sys.stdout.buffer
    for device, build in prev_result.device_to_prev_build.items():
        out.write(
            b"prev\0" + device.encode() + b"\0" + str(build).encode() + b"\0",
        )
    for device, build in prev_result.device_to_preexisting_build.items():
        out.write(
            b"preexisting\0"
            + device.encode()
            + b"\0"
            + str(build).encode()
            + b"\0",
        )
    for build in prev_result.prev_builds_sorted:
        out.write(b"sorted\0" + str(build).encode() + b"\0")
    return 0


def _cmd_partition_signing_plan(args: argparse.Namespace) -> int:
    """
    Print the null-delimited signing plan partitioned by key availability.

    Args:
        args: Parsed namespace containing device and build buckets.

    Returns:
        Zero on success.
    """
    from .sign_planning import partition_by_key_availability

    plan = partition_by_key_availability(
        args.devices_with_loaded_keys,
        args.devices_without_loaded_keys,
        device_to_next_build=_parse_key_value_ints(args.device_next_build),
        device_to_prev_build=_parse_key_value_ints(args.device_prev_build),
        device_to_preexisting_build=_parse_key_value_ints(
            args.device_preexisting_build,
        ),
        avb_rollback_index_override=args.avb_rollback_index_override,
    )
    out = sys.stdout.buffer
    for bucket, sign_pairs in (
        ("sign_with", plan.sign_pairs_with_loaded_keys),
        ("sign_without", plan.sign_pairs_without_loaded_keys),
    ):
        for pair in sign_pairs:
            value = f"{pair.device},{pair.build},{pair.target_build}"
            out.write(bucket.encode() + b"\0" + value.encode() + b"\0")
    for bucket, triples in (
        ("incr_with", plan.incremental_triples_with_loaded_keys),
        ("incr_without", plan.incremental_triples_without_loaded_keys),
    ):
        for triple in triples:
            new_build = (
                "" if triple.new_build is None else str(triple.new_build)
            )
            value = f"{triple.device},{triple.old_build},{new_build}"
            out.write(bucket.encode() + b"\0" + value.encode() + b"\0")
    return 0


def _cmd_provision_avb_key(args: argparse.Namespace) -> int:
    """
    Provision an AVB signing key pair.

    Args:
        args: Parsed namespace containing the key paths and avbtool.

    Returns:
        Zero on success.
    """
    from .key_scripts import provision_avb_key

    provision_avb_key(args.avbtool, args.private_key, args.public_key)
    return 0


def _cmd_provision_rsa_key(args: argparse.Namespace) -> int:
    """
    Provision a plain RSA private key.

    Args:
        args: Parsed namespace containing the key path.

    Returns:
        Zero on success.
    """
    from .key_scripts import generate_rsa_key

    generate_rsa_key(args.private_key)
    return 0


def _cmd_migrate_runtime_key(args: argparse.Namespace) -> int:
    """
    Migrate a runtime key directory to the current layout.

    Args:
        args: Parsed namespace containing the key directory.

    Returns:
        Zero on success.
    """
    from .key_scripts import migrate_runtime_key

    migrate_runtime_key(args.key_directory)
    return 0


def _cmd_update_keys(args: argparse.Namespace) -> int:
    """
    Update a device's on-disk keys and certificate metadata.

    Args:
        args: Parsed namespace containing metadata path and key settings.

    Returns:
        Zero on success, one when a key or one of its tools fails.
    """
    from .key_scripts import update_keys
    from .metadata import default_metadata_path, load_metadata

    metadata = load_metadata(args.metadata or default_metadata_path())
    try:
        update_keys(
            keymapper=_keymapper_from_args(args, metadata),
            key_directory=args.key_directory,
            device=args.device,
            subject=args.subject,
            avbtool=args.avbtool,
            key_suffix=os.environ.get("KEY_SUFFIX", ".pem"),
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def _cmd_generate_asymmetric_key(args: argparse.Namespace) -> int:
    """
    Generate an asymmetric key on the YubiHSM.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import generate_asymmetric_key

    config = _yubihsm_config_from_args(args)
    generate_asymmetric_key(
        config,
        key_id=args.key_id,
        label=args.label,
        domains=args.domain,
        capabilities=args.capabilities,
        algorithm=args.algorithm,
    )
    return 0


def _cmd_attest_key(args: argparse.Namespace) -> int:
    """
    Write a YubiHSM key's attestation certificate.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import attest_key

    config = _yubihsm_config_from_args(
        args,
        attestation_id=args.attestation_id,
    )
    certificate = attest_key(config, args.key_id)
    write_binary(args.output, certificate)
    return 0


def _cmd_export_wrapped_key(args: argparse.Namespace) -> int:
    """
    Export a wrapped YubiHSM key.

    Args:
        args: Parsed namespace containing connector and wrap settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import (
        export_wrapped_key,
    )

    config = _yubihsm_config_from_args(args, wrap_id=args.wrap_id)
    wrapped = export_wrapped_key(config, args.key_id)
    write_binary(args.output, base64.b64encode(wrapped))
    return 0


def _cmd_import_wrapped_key(args: argparse.Namespace) -> int:
    """
    Import a wrapped YubiHSM key.

    Args:
        args: Parsed namespace containing connector and wrap settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import (
        decode_wrapped_key_backup,
        import_wrapped_key,
    )

    config = _yubihsm_config_from_args(args, wrap_id=args.wrap_id)
    import_wrapped_key(
        config,
        args.key_id,
        decode_wrapped_key_backup(_read_binary(args.input), args.input),
    )
    return 0


def _cmd_get_certificate(args: argparse.Namespace) -> int:
    """
    Write a YubiHSM key's certificate.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import get_certificate

    config = _yubihsm_config_from_args(args)
    write_binary(args.output, get_certificate(config, args.key_id))
    return 0


def _cmd_import_certificate(args: argparse.Namespace) -> int:
    """
    Import a certificate onto the YubiHSM.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import import_certificate

    config = _yubihsm_config_from_args(args)
    import_certificate(
        config,
        key_id=args.key_id,
        domains=args.domain,
        capabilities=args.capabilities,
        certificate_pem=_read_binary(args.input),
    )
    return 0


def _cmd_limit_ondemand_objects(args: argparse.Namespace) -> int:
    """
    Limit on-demand YubiHSM objects to those backed by a key directory.

    Args:
        args: Parsed namespace containing connector and key directory.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import (
        extract_and_save_audit_log,
        limit_ondemand_objects,
    )

    config = _yubihsm_config_from_args(args)
    after_delete: Callable[[str], None] | None = None
    if args.audit_log is not None:

        def log_delete(comment: str) -> None:
            try:
                extract_and_save_audit_log(config, args.audit_log, comment)
            except Exception:
                print("Failed to extract logs", file=sys.stderr)
                if not args.no_log_fail:
                    raise

        after_delete = log_delete

    limit_ondemand_objects(
        config,
        args.key_dir,
        args.ondemand_domain,
        after_delete,
        dry_run=args.dry_run,
    )
    return 0


def _cmd_ensure_keys_available(args: argparse.Namespace) -> int:
    """
    Ensure the requested YubiHSM keys are loaded and available, and with
    --audit-log extract the audit log into it after each key.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import (
        ensure_keys_are_available,
        extract_and_save_audit_log,
    )

    config = _yubihsm_config_from_args(args, wrap_id=args.wrap_id)
    ondemand_ids = frozenset(
        int(key_id, 16) for key_id in args.ondemand_key_ids
    )

    def after_key(key_id: str) -> None:
        if args.audit_log is not None:
            extract_and_save_audit_log(
                config,
                args.audit_log,
                f"Function: ensure_key_is_available Key: {key_id} Result: 0",
            )

    ensure_keys_are_available(
        config,
        args.key_dir,
        args.key_ids,
        restore_mode=args.restore_mode,
        is_ondemand=lambda object_id: object_id in ondemand_ids,
        verify_key_ids=not args.no_verify_key_ids,
        exportable_domain=args.exportable_domain,
        ondemand_domain=args.ondemand_domain,
        opaque_capabilities=args.opaque_capabilities,
        after_key=after_key,
    )
    return 0


def _cmd_partition_devices_by_key_availability(args: argparse.Namespace) -> int:
    """
    Print devices partitioned by whether their keys are all loaded.

    Args:
        args: Parsed namespace containing connector and device settings.

    Returns:
        Zero on success.
    """
    from .keymap import StaticKeymapper
    from .vendor_yubihsm import populate_devices_with_loaded_keys_arrays

    config = _yubihsm_config_from_args(args)
    with_loaded, without_loaded = populate_devices_with_loaded_keys_arrays(
        config,
        StaticKeymapper.from_file(args.keymap_file),
        args.devices,
    )
    out = sys.stdout.buffer
    for bucket, devices in (
        ("with", with_loaded),
        ("without", without_loaded),
    ):
        for device in devices:
            out.write(bucket.encode() + b"\0" + device.encode() + b"\0")
    return 0


def _cmd_ensure_all_keys_available_for_devices(args: argparse.Namespace) -> int:
    """
    Ensure every per-device key the given devices need is loaded, and
    with --audit-log extract the audit log into it after each key.

    Args:
        args: Parsed namespace containing connector and device settings.

    Returns:
        Zero on success.
    """
    from .keymap import StaticKeymapper
    from .vendor_yubihsm import (
        ensure_all_keys_available_for_devices,
        extract_and_save_audit_log,
    )

    config = _yubihsm_config_from_args(args, wrap_id=args.wrap_id)
    ondemand_ids = frozenset(
        int(key_id, 16) for key_id in args.ondemand_key_ids
    )

    def after_key(key_id: str) -> None:
        if args.audit_log is not None:
            extract_and_save_audit_log(
                config,
                args.audit_log,
                f"Function: ensure_key_is_available Key: {key_id} Result: 0",
            )

    ensure_all_keys_available_for_devices(
        config,
        StaticKeymapper.from_file(args.keymap_file),
        args.key_dir,
        args.devices,
        is_ondemand=lambda object_id: object_id in ondemand_ids,
        exportable_domain=args.exportable_domain,
        ondemand_domain=args.ondemand_domain,
        opaque_capabilities=args.opaque_capabilities,
        after_key=after_key,
    )
    return 0


def _cmd_restore_all_keys_and_certs(args: argparse.Namespace) -> int:
    """
    Bulk-restore every key/cert backed up in a key directory.

    Args:
        args: Parsed namespace containing connector and key settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import restore_all_keys_and_certs

    config = _yubihsm_config_from_args(args, wrap_id=args.wrap_id)
    ondemand_ids = frozenset(
        int(key_id, 16) for key_id in args.ondemand_key_ids
    )
    restore_all_keys_and_certs(
        config,
        args.key_dir,
        args.log_file,
        is_ondemand=lambda object_id: object_id in ondemand_ids,
        exportable_domain=args.exportable_domain,
        ondemand_domain=args.ondemand_domain,
        opaque_capabilities=args.opaque_capabilities,
    )
    return 0


def _cmd_get_device_identity(args: argparse.Namespace) -> int:
    """
    Print the YubiHSM's device information as yubihsm-shell's
    get-device-info prints it.

    Args:
        args: Parsed namespace containing connector settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import get_device_identity

    config = _yubihsm_config_from_args(args)
    print(get_device_identity(config).device_info, end="")
    return 0


def _cmd_get_loaded_key_status(args: argparse.Namespace) -> int:
    """
    Print the object IDs of fully loaded YubiHSM keys.

    Args:
        args: Parsed namespace containing connector settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import get_loaded_key_status

    config = _yubihsm_config_from_args(args)
    status = get_loaded_key_status(config)
    for object_id in sorted(status.fully_loaded_ids):
        print(f"{object_id:#06x}")
    return 0


def _cmd_yubihsm_object_exists(args: argparse.Namespace) -> int:
    """
    Print "yes" if the YubiHSM holds the key's asymmetric key or X.509
    certificate object, or "no".

    Args:
        args: Parsed namespace containing connector settings, the key ID
            and which of its objects to look for.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import get_loaded_key_status

    status = get_loaded_key_status(_yubihsm_config_from_args(args))
    if args.type == "key":
        loaded = status.loaded_key_ids
    else:
        loaded = status.loaded_cert_ids
    print("yes" if int(args.key_id, 16) in loaded else "no")
    return 0


def _cmd_extract_audit_log(args: argparse.Namespace) -> int:
    """
    Extract and save the YubiHSM audit log.

    Args:
        args: Parsed namespace containing connector and log settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm import (
        extract_and_save_audit_log,
    )

    config = _yubihsm_config_from_args(args)
    extract_and_save_audit_log(config, args.log_file, args.comment)
    return 0


def _cmd_start_yubihsm_connector(args: argparse.Namespace) -> int:
    """
    Start the local yubihsm-connector process.

    Args:
        args: Parsed namespace containing connector process settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm_connector import (
        YubiHsmConnector,
        YubiHsmConnectorConfig,
    )

    connector_config = YubiHsmConnectorConfig(
        connector_url=args.connector,
        pid_file=args.pid_file,
        binary=args.binary,
    )
    YubiHsmConnector(connector_config).restart()
    return 0


def _cmd_stop_yubihsm_connector(args: argparse.Namespace) -> int:
    """
    Stop the local yubihsm-connector process.

    Args:
        args: Parsed namespace containing connector process settings.

    Returns:
        Zero on success.
    """
    from .vendor_yubihsm_connector import (
        YubiHsmConnector,
        YubiHsmConnectorConfig,
    )

    connector_config = YubiHsmConnectorConfig(
        connector_url=args.connector,
        pid_file=args.pid_file,
        binary=args.binary,
    )
    YubiHsmConnector(connector_config).stop()
    return 0


def _cmd_init_pkcs11_token(args: argparse.Namespace) -> int:
    """
    Initialize a PKCS#11 token with the requested label and PINs.

    Args:
        args: Parsed namespace containing token and PIN source settings.

    Returns:
        Zero on success.
    """
    from .configuration import EnvironmentPin, FilePin
    from .pkcs11 import initialize_pkcs11_token

    so_pin_source = (
        EnvironmentPin(args.so_pin_env)
        if args.so_pin_env is not None
        else FilePin(args.so_pin_file)
    )
    pin_source = (
        EnvironmentPin(args.pin_env)
        if args.pin_env is not None
        else FilePin(args.pin_file)
    )
    initialize_pkcs11_token(
        tool=args.pkcs11_tool,
        module=args.module,
        label=args.label,
        so_pin=so_pin_source.resolve(),
        user_pin=pin_source.resolve(),
    )
    return 0


def _cmd_key_exists(args: argparse.Namespace) -> int:
    """
    Print whether the referenced key exists.

    Args:
        args: Parsed namespace containing backend and key reference fields.

    Returns:
        Zero on success.
    """
    backend = _build_backend(args)
    reference = _reference_from_args(args)
    print("yes" if backend.key_exists(reference) else "no")
    return 0


def _cmd_certificate_exists(args: argparse.Namespace) -> int:
    """
    Print whether the referenced certificate exists.

    Args:
        args: Parsed namespace containing backend and key reference fields.

    Returns:
        Zero on success.
    """
    backend = _build_backend(args)
    reference = _reference_from_args(args)
    print("yes" if backend.certificate_exists(reference) else "no")
    return 0


def _cmd_generate_key(args: argparse.Namespace) -> int:
    """
    Generate the referenced key.

    Args:
        args: Parsed namespace containing backend and key spec fields.

    Returns:
        Zero on success.
    """
    backend = _build_backend(args)
    backend.generate_key(_spec_from_args(args))
    return 0


def _cmd_generate_certificate(args: argparse.Namespace) -> int:
    """
    Generate the referenced key's certificate.

    Args:
        args: Parsed namespace containing backend and key spec fields.

    Returns:
        Zero on success.
    """
    backend = _build_backend(args)
    certificate = backend.generate_certificate(
        _spec_from_args(args),
        args.subject,
    )
    if args.output is not None:
        write_binary(args.output, certificate)
    return 0


class _UsageError(Exception):
    """
    A command-line usage error, which main() reports through the parser.
    """


_CommandHandler = Callable[[argparse.Namespace], int]

_HANDLERS: dict[str, _CommandHandler] = {
    "run-release-tool": _cmd_run_release_tool,
    "compute-sha256sum": _cmd_compute_sha256sum,
    "sign-builds": _cmd_sign_builds,
    "generate-incrementals": _cmd_generate_incrementals,
    "mkkey": _cmd_mkkey,
    "generate-keymap": _cmd_generate_keymap,
    "build-release-args": _cmd_build_release_args,
    "gather-signable-devices": _cmd_gather_signable_devices,
    "gather-device-builds": _cmd_gather_device_builds,
    "find-prev-builds": _cmd_find_prev_builds,
    "partition-signing-plan": _cmd_partition_signing_plan,
    "provision-avb-key": _cmd_provision_avb_key,
    "provision-rsa-key": _cmd_provision_rsa_key,
    "migrate-runtime-key": _cmd_migrate_runtime_key,
    "update-keys": _cmd_update_keys,
    "generate-asymmetric-key": _cmd_generate_asymmetric_key,
    "attest-key": _cmd_attest_key,
    "export-wrapped-key": _cmd_export_wrapped_key,
    "import-wrapped-key": _cmd_import_wrapped_key,
    "get-certificate": _cmd_get_certificate,
    "import-certificate": _cmd_import_certificate,
    "limit-ondemand-objects": _cmd_limit_ondemand_objects,
    "ensure-keys-available": _cmd_ensure_keys_available,
    "partition-devices-by-key-availability": (
        _cmd_partition_devices_by_key_availability
    ),
    "ensure-all-keys-available-for-devices": (
        _cmd_ensure_all_keys_available_for_devices
    ),
    "restore-all-keys-and-certs": _cmd_restore_all_keys_and_certs,
    "get-device-identity": _cmd_get_device_identity,
    "get-loaded-key-status": _cmd_get_loaded_key_status,
    "yubihsm-object-exists": _cmd_yubihsm_object_exists,
    "extract-audit-log": _cmd_extract_audit_log,
    "start-yubihsm-connector": _cmd_start_yubihsm_connector,
    "stop-yubihsm-connector": _cmd_stop_yubihsm_connector,
    "init-pkcs11-token": _cmd_init_pkcs11_token,
    "key-exists": _cmd_key_exists,
    "certificate-exists": _cmd_certificate_exists,
    "generate-key": _cmd_generate_key,
    "generate-certificate": _cmd_generate_certificate,
}


def main(argv: list[str] | None = None) -> int:
    """
    Run a signing subcommand and return its process exit status.

    Args:
        argv: Arguments to parse, or ``None`` to use ``sys.argv``.

    Returns:
        Zero when the selected command completes successfully.

    Raises:
        SystemExit: If command-line arguments or capabilities are invalid.
    """
    if argv is None:
        argv = sys.argv[1:]
    tool_argv: list[str] | None = None
    if argv[:1] == ["run-release-tool"] and "--" in argv:
        separator = argv.index("--")
        tool_argv = argv[separator + 1 :]
        argv = argv[:separator]
    script_argv: list[str] = []
    if argv[:1] == ["mkkey"]:
        script_argv = argv[1:]
        argv = argv[:1]

    parser = build_parser()
    args = parser.parse_args(argv)
    args.tool_argv = tool_argv
    args.arguments = script_argv
    try:
        return _HANDLERS[args.command](args)
    except _UsageError as error:
        parser.error(str(error))
    except subprocess.CalledProcessError as error:
        if isinstance(error.stderr, bytes):
            sys.stderr.buffer.write(error.stderr)
        elif error.stderr:
            sys.stderr.write(error.stderr)
        return 1
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        message = (
            error.args[0]
            if isinstance(error, KeyError) and error.args
            else error
        )
        print(f"error: {message}", file=sys.stderr)
        return 1
