#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Command-line entry points for backend-neutral signing operations.
"""

from __future__ import annotations

import argparse
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
    from .models import KeyReference, KeySpec
    from .pkcs11 import Pkcs11Backend

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


def _add_pin_group(parser: argparse.ArgumentParser) -> None:
    """
    Add a mutually exclusive --pin-env/--pin-file/--pin group to a command.

    Args:
        parser: Subcommand parser to configure.

    Returns:
        None.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pin-env")
    group.add_argument(
        "--pin-file",
        type=Path,
    )
    group.add_argument(
        "--pin",
        action=_RejectRawValue,
        message="raw PINs are forbidden, use --pin-env or --pin-file",
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
    _add_pin_group(parser)
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
    subparsers.add_parser("mkkey", add_help=False)

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
    return Pkcs11BackendConfiguration(
        module=args.module,
        pin_source=pin_source,
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
    from .keymap import Id2bKeymapper
    from .metadata import default_metadata_path, load_metadata

    metadata = load_metadata(args.metadata or default_metadata_path())
    print(Id2bKeymapper(metadata).to_tsv(args.devices), end="")
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
    "mkkey": _cmd_mkkey,
    "generate-keymap": _cmd_generate_keymap,
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
    script_argv: list[str] = []
    if argv[:1] == ["mkkey"]:
        script_argv = argv[1:]
        argv = argv[:1]

    parser = build_parser()
    args = parser.parse_args(argv)
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
