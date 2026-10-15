#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Command-line entry points of the signing scripts.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .metadata import SCRIPTS_DIR, default_devices_path

_SCRIPT_COMMANDS = (
    "release-orchestrate",
    "generate-delta",
    "keygen",
    "yubihsm-provision",
    "mkkey",
    "updatekeys",
    "updatecommonkeys",
    "sign-app",
)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser without reading configuration or state.

    Returns:
        The configured top-level argument parser.
    """
    parser = argparse.ArgumentParser(prog="python3 -m signing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("print-keymap")

    sign_orchestrate_parser = subparsers.add_parser("sign-orchestrate")
    sign_orchestrate_parser.add_argument(
        "--metadata",
        type=Path,
        default=None,
    )
    sign_orchestrate_parser.add_argument(
        "--devices-file",
        type=Path,
        default=default_devices_path().resolve(),
    )
    sign_orchestrate_parser.add_argument(
        "--release-script",
        type=Path,
        default=SCRIPTS_DIR / "release.sh",
    )
    sign_orchestrate_parser.add_argument(
        "--generate-delta-script",
        type=Path,
        default=SCRIPTS_DIR / "generate_delta.sh",
    )

    for command in _SCRIPT_COMMANDS:
        subparsers.add_parser(command, add_help=False)

    prepare_ceremony_package = subparsers.add_parser("prepare-ceremony-package")
    prepare_ceremony_package.add_argument(
        "--script-dir",
        type=Path,
        default=SCRIPTS_DIR / "hsm_provisioning",
    )
    return parser


def _cmd_sign_orchestrate(args: argparse.Namespace) -> int:
    """
    Sign the builds sign.sh is run on.

    Args:
        args: Parsed namespace containing metadata/devices-file settings.

    Returns:
        The orchestration's exit status, 0 on success.
    """
    from .metadata import default_metadata_path, load_metadata
    from .sign_orchestration import SignOrchestrator

    metadata = load_metadata(args.metadata or default_metadata_path())
    orchestrator = SignOrchestrator(
        os.environ,
        cwd=Path.cwd(),
        devices_file=args.devices_file,
        metadata=metadata,
        release_script=args.release_script,
        generate_delta_script=args.generate_delta_script,
    )
    return orchestrator.run()


def _cmd_release_orchestrate(args: argparse.Namespace) -> int:
    """
    Sign one device's target files for release.sh.

    Args:
        args: Parsed namespace containing release.sh's arguments.

    Returns:
        The orchestration's exit status, 0 on success.
    """
    from .metadata import default_metadata_path, load_metadata
    from .release_orchestration import ReleaseOrchestrator

    program, *arguments = args.arguments or ["release.sh"]
    if not 1 <= len(arguments) <= 2:
        print(
            "error: incorrect number of arguments, please try again",
            file=sys.stderr,
        )
        print(f"Usage: {program} {ReleaseOrchestrator.usage}")
        return 1
    orchestrator = ReleaseOrchestrator(
        os.environ,
        cwd=Path.cwd(),
        metadata=load_metadata(default_metadata_path()),
        program=program,
        device=arguments[0],
        target_files_arg=arguments[1] if len(arguments) > 1 else None,
    )
    return orchestrator.run()


def _cmd_generate_delta(args: argparse.Namespace) -> int:
    """
    Generate an incremental OTA update for generate_delta.sh.

    Args:
        args: Parsed namespace containing generate_delta.sh's own
            arguments.

    Returns:
        The orchestration's exit status, 0 on success, 1 on a usage
        error.
    """
    from .metadata import default_metadata_path, load_metadata
    from .release_orchestration import DeltaOrchestrator

    program, *arguments = args.arguments or ["generate_delta.sh"]
    if len(arguments) != 3:
        print(
            "error: incorrect number of arguments, please try again",
            file=sys.stderr,
        )
        print(f"Usage: {program} {DeltaOrchestrator.usage}")
        return 1
    device, old, new = arguments
    orchestrator = DeltaOrchestrator(
        os.environ,
        cwd=Path.cwd(),
        metadata=load_metadata(default_metadata_path()),
        program=program,
        device=device,
        old=old,
        new=new,
    )
    return orchestrator.run()


def _cmd_keygen(args: argparse.Namespace) -> int:
    """
    Generate keys for a vendor keygen script.

    Args:
        args: Parsed namespace containing the keygen script's arguments.

    Returns:
        The keygen script's exit status.
    """
    from .keygen import keygen_main

    return keygen_main(os.environ, args.arguments)


def _cmd_yubihsm_provision(args: argparse.Namespace) -> int:
    """
    Run the YubiHSM provisioning wizard.

    Args:
        args: Parsed namespace containing the wizard's arguments.

    Returns:
        The wizard's exit status.
    """
    from .yubihsm_provision import provision_main

    return provision_main(os.environ, args.arguments)


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


def _cmd_updatekeys(args: argparse.Namespace) -> int:
    """
    Create or update a device's keys for updatekeys.sh, or for mkkeys.sh
    with --create-directory.

    Args:
        args: Parsed namespace containing the script path and arguments.

    Returns:
        The script's exit status.
    """
    from .key_scripts import updatekeys_main

    return updatekeys_main(os.environ, args.arguments)


def _cmd_updatecommonkeys(args: argparse.Namespace) -> int:
    """
    Create or update the common keys for updatecommonkeys.sh, or for
    mkcommonkeys.sh with --create-directory.

    Args:
        args: Parsed namespace containing the script path and arguments.

    Returns:
        The script's exit status.
    """
    from .key_scripts import updatecommonkeys_main

    return updatecommonkeys_main(os.environ, args.arguments)


def _cmd_prepare_ceremony_package(args: argparse.Namespace) -> int:
    """
    Build ceremony.zip in the current directory.

    Args:
        args: Parsed namespace containing the directory of manifest.tsv.

    Returns:
        The exit status of prepare_package().
    """
    from .ceremony_package import prepare_package

    return prepare_package(os.environ, args.script_dir, Path.cwd())


def _cmd_sign_app(args: argparse.Namespace) -> int:
    """
    Sign an app for sign-app.sh.

    Args:
        args: Parsed namespace containing sign-app.sh's own arguments.

    Returns:
        sign-app.sh's exit status.
    """
    from .metadata import default_metadata_path, load_metadata
    from .sign_app import sign_app

    program, *arguments = args.arguments or ["sign-app.sh"]
    return sign_app(
        os.environ,
        load_metadata(default_metadata_path()),
        arguments,
        program=program,
    )


def _cmd_print_keymap(args: argparse.Namespace) -> int:
    """
    Print the keymap of the keymapper and devices the environment
    selects for generate_keymap.sh through KEYMAPPER (legacy by default),
    KEYMAPPER_FILE, KEYMAP_FILE, EXTRA_DEVICES and the devices array of
    DEVICES_FILE.

    Args:
        args: Unused, since the command takes no arguments.

    Returns:
        Zero on success, one when no keymapper or no device is found.
    """
    from .keymap import load_keymapper
    from .metadata import default_metadata_path, load_metadata
    from .sign_orchestration import load_devices_file

    del args
    devices_file = default_devices_path()
    try:
        devices = load_devices_file(devices_file)
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stderr)
        return 1
    environment = {**os.environ}
    environment["KEYMAPPER"] = environment.get("KEYMAPPER") or "legacy"
    metadata = load_metadata(default_metadata_path())
    try:
        keymapper = load_keymapper(environment, metadata)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if not devices:
        print(
            "ERROR: No defined devices for which to generate keys.",
            file=sys.stderr,
        )
        print(
            "       Ensure the devices array is populated in $DEVICES_FILE "
            f"({devices_file}).",
            file=sys.stderr,
        )
        return 1
    try:
        print(keymapper.to_tsv(devices), end="")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


_CommandHandler = Callable[[argparse.Namespace], int]

_HANDLERS: dict[str, _CommandHandler] = {
    "sign-orchestrate": _cmd_sign_orchestrate,
    "release-orchestrate": _cmd_release_orchestrate,
    "generate-delta": _cmd_generate_delta,
    "keygen": _cmd_keygen,
    "yubihsm-provision": _cmd_yubihsm_provision,
    "mkkey": _cmd_mkkey,
    "updatekeys": _cmd_updatekeys,
    "updatecommonkeys": _cmd_updatecommonkeys,
    "prepare-ceremony-package": _cmd_prepare_ceremony_package,
    "sign-app": _cmd_sign_app,
    "print-keymap": _cmd_print_keymap,
}


def main(argv: list[str] | None = None) -> int:
    """
    Run a signing subcommand and return its process exit status.

    Args:
        argv: Arguments to parse, or ``None`` to use ``sys.argv``.

    Returns:
        Zero when the selected command completes successfully.

    Raises:
        SystemExit: If the command-line arguments are invalid.
    """
    if argv is None:
        argv = sys.argv[1:]
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(line_buffering=True)
    script_argv: list[str] = []
    if argv[:1] and argv[0] in _SCRIPT_COMMANDS:
        script_argv = argv[1:]
        argv = argv[:1]

    args = build_parser().parse_args(argv)
    args.arguments = script_argv
    try:
        return _HANDLERS[args.command](args)
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        message = (
            error.args[0]
            if isinstance(error, KeyError) and error.args
            else error
        )
        print(f"error: {message}", file=sys.stderr)
        return 1
