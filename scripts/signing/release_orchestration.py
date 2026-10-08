#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Run the release and generate_delta commands.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Generator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import sign_environment
from .apksigner_batch import ApksignerBatch
from .keymap import (
    Keymapper,
    LegacyKeymapper,
    apply_keymapper_exports,
    load_keymapper,
)
from .metadata import SigningMetadata
from .release_arguments import (
    ReleaseArguments,
    UnsupportedRollbackDeviceError,
    build_release_arguments,
    make_get_key,
)
from .release_execution import (
    Transcript,
    exit_on_signals,
    format_sha256sum,
    render_release_tool,
    run_release_tool,
)
from .signing_server import Handler, SigningServer

_PKCS11_DIR = Path(__file__).resolve().parents[1] / "pkcs11"

_CLEAR_FACTORY_VARIABLES = "device/common/clear-factory-images-variables.sh"

_FACTORY_IMAGE_SCRIPT = """
set -uo pipefail
out_dir=$1 common_script=$2 clear_script=$3
shift 3
source "$clear_script"
for assignment in "$@"; do
  export "$assignment"
done
cd "$out_dir"
source "$common_script"
"""

_QCOM_BOOTLOADER_RADIO_DEVICES = frozenset(
    {
        "redfin",
        "bramble",
        "barbet",
        "oriole",
        "raven",
        "bluejay",
        "panther",
        "cheetah",
        "lynx",
        "felix",
        "shiba",
        "husky",
        "akita",
        "tokay",
        "caiman",
        "komodo",
        "comet",
        "tegu",
        "stallion",
    },
)


class ReleaseUsageError(Exception):
    """Raised to print an error and the usage message, and exit 1."""


def avb_algorithm_for(
    environment: Mapping[str, str],
    keymapper: Keymapper,
) -> str:
    """
    Pick the AVB algorithm for the keymapper in use.

    The legacy keymapper takes AVB_RSA_KEY_SIZE. With PKCS#11 signing,
    the other keymappers take the keys' RSA_KEY_SIZE, and without it
    AVB_RSA_KEY_SIZE, then RSA_KEY_SIZE. Each defaults to 4096.

    Args:
        environment: Process environment to read PKCS11_MODULE/
            PKCS11_VENDOR and the key sizes from.
        keymapper: The keymapper the release resolves keys with.

    Returns:
        The AVB algorithm, such as "SHA256_RSA4096".
    """
    if isinstance(keymapper, LegacyKeymapper):
        size = environment.get("AVB_RSA_KEY_SIZE") or "4096"
    elif environment.get("PKCS11_MODULE") or environment.get("PKCS11_VENDOR"):
        size = environment.get("RSA_KEY_SIZE") or "4096"
    else:
        size = (
            environment.get("AVB_RSA_KEY_SIZE")
            or environment.get("RSA_KEY_SIZE")
            or "4096"
        )
    return f"SHA256_RSA{size}"


class ReleaseAbort(Exception):
    """Raised to exit with a code, without a usage message."""

    def __init__(self, code: int) -> None:
        super().__init__(f"release orchestration aborted (code {code})")
        self.code = code


_HELPER_SUFFIXES = {"python": ".py", "server": ".server.py"}


def _extract_android_info_field(target_files: Path, field: str) -> str:
    """
    Read the second "="-separated field of each OTA/android-info.txt line
    in the target-files zip that mentions field.

    Args:
        target_files: The target-files zip.
        field: Text to look for, such as "version-bootloader".

    Returns:
        The values, one per line, or "" when no line mentions field.

    Raises:
        ReleaseAbort: If the zip or its android-info.txt cannot be read.
    """
    try:
        with zipfile.ZipFile(target_files) as archive:
            text = archive.read("OTA/android-info.txt").decode()
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        print(
            f"error: cannot read OTA/android-info.txt from {target_files} "
            f"({error})",
            file=sys.stderr,
        )
        raise ReleaseAbort(1) from error
    return "\n".join(
        line.split("=")[1] if "=" in line else line
        for line in text.splitlines()
        if field in line
    )


def resolve_device_family_environment(
    device: str,
    extra_devices: Sequence[str],
    target_files: Path,
) -> dict[str, str]:
    """
    Resolve the device family's BOOTLOADER/RADIO versions and the vendor
    flags the factory-image assembly script reads.

    Args:
        device: The device being released.
        extra_devices: EXTRA_DEVICES opt-in list. A device here skips
            the hardcoded family checks with no vendor flags set at
            all, for a device tree that needs none of them.
        target_files: Path to the target-files zip, read for
            BOOTLOADER/RADIO only when needed.

    Returns:
        Environment variables to add for the factory-image step, with
        no key for a flag the device leaves unset.

    Raises:
        ReleaseUsageError: If the device is not recognized and not
            present in extra_devices.
    """
    if device in _QCOM_BOOTLOADER_RADIO_DEVICES:
        return {
            "BOOTLOADER": _extract_android_info_field(
                target_files,
                "version-bootloader",
            ),
            "RADIO": _extract_android_info_field(
                target_files,
                "version-baseband",
            ),
        }
    if device == "tangorpro":
        return {
            "BOOTLOADER": _extract_android_info_field(
                target_files,
                "version-bootloader",
            ),
        }
    if device == "FP4":
        return {"FP4": "true", "QCOM_FIRMWARE": "true"}
    if device == "FP5":
        return {"FP5": "true", "QCOM_FIRMWARE": "true"}
    if device == "FP6":
        return {"FP6": "true", "QCOM_FIRMWARE": "true"}
    if device in ("devon", "hawao", "rhode"):
        return {"MOTO_BENGAL": "true", "QCOM_FIRMWARE": "true"}
    if device in ("fogos", "bangkk", "fogo"):
        return {"MOTO_BLAIR": "true", "QCOM_FIRMWARE": "true"}
    if device == "otter":
        return {
            "OTTER": "true",
            "QCOM_FIRMWARE": "true",
            "SKIP_AVB_CUSTOM_KEY": "true",
        }
    if device in extra_devices:
        return {}
    raise ReleaseUsageError(f"Unsupported device {device}")


_SUNPKCS11_CONFIG_TEMPLATE = """\
name = PKCS11
description = SunPKCS11
library = {module}
slotListIndex = 0
"""


def generate_sunpkcs11_config(environment: MutableMapping[str, str]) -> str:
    """
    Render the SunPKCS11 provider config.

    Args:
        environment: Read PKCS11_MODULE/PKCS11_SUN_CONFIG_EXTRA from.

    Returns:
        The SunPKCS11 provider config file's text.
    """
    text = _SUNPKCS11_CONFIG_TEMPLATE.format(
        module=environment.get("PKCS11_MODULE", ""),
    )
    extra = environment.get("PKCS11_SUN_CONFIG_EXTRA")
    if extra:
        text += extra + "\n"
    return text


def read_words(value: str) -> list[str]:
    """
    Split a variable into words on blanks.

    A backslash keeps the next character literal, a backslash before a
    newline joins the lines, and any other newline ends the input.

    Args:
        value: The variable's value.

    Returns:
        The words, in order.
    """
    words: list[str] = []
    word: list[str] = []
    in_word = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            index += 1
            if index < len(value) and value[index] != "\n":
                word.append(value[index])
                in_word = True
        elif char == "\n":
            break
        elif char in " \t":
            if in_word:
                words.append("".join(word))
                word = []
                in_word = False
        else:
            word.append(char)
            in_word = True
        index += 1
    if in_word:
        words.append("".join(word))
    return words


@dataclass
class _SessionArgs:
    """The extra release-tools, signing and OTA arguments."""

    releasetools: list[str] = field(default_factory=list[str])
    signing: list[str] = field(default_factory=list[str])
    ota: list[str] = field(default_factory=list[str])


def _signs_through_pkcs11(environment: Mapping[str, str]) -> bool:
    """Return whether a PKCS#11 module or vendor is configured."""
    return bool(
        environment.get("PKCS11_MODULE")
        or environment.get("PKCS11_VENDOR")
        or environment.get("PKCS11_VENDOR_FILE"),
    )


def prepare_signing_args(
    environment: MutableMapping[str, str],
    args: _SessionArgs,
    *,
    tmpdir: Path,
    dry_run: bool = False,
) -> None:
    """
    When a PKCS#11 module/vendor is configured, write a SunPKCS11
    provider config and extend the three argument lists with the
    signing/payload-signer helper tools, and (if set) add the
    signing-command interceptor and payload-signer
    maximum-signature-size overrides.

    Args:
        environment: Process environment to read PKCS11_MODULE/
            PKCS11_VENDOR/SIGNING_HELPER_TOOL/etc. from.
        args: Argument lists to extend in place.
        tmpdir: Directory the SunPKCS11 config file is written under.
        dry_run: Under DRY_RUN, render "generate_sunpkcs11_config"
            instead of writing the file. Later commands reference the
            config path either way.

    Returns:
        None.

    Raises:
        RuntimeError: If a helper tool variable names anything other
            than python or server.
    """
    if _signs_through_pkcs11(environment):
        config_path = tmpdir / "sunpkcs11.cfg"
        _show_step(["generate_sunpkcs11_config"], dry_run=dry_run)
        if not dry_run:
            config_path.write_text(generate_sunpkcs11_config(environment))
        tool = environment.get("SIGNING_HELPER_TOOL") or "python"
        avb_tool = environment.get("AVB_SIGNING_HELPER_TOOL") or tool
        payload_tool = environment.get("PAYLOAD_SIGNER_TOOL") or tool
        for chosen in (avb_tool, payload_tool):
            if chosen not in _HELPER_SUFFIXES:
                raise RuntimeError(
                    f"Unknown signing helper tool '{chosen}', use 'python' "
                    "or 'server'",
                )
        signing_helper_tool = (
            f"{_PKCS11_DIR}/signing_helper{_HELPER_SUFFIXES[avb_tool]}"
        )
        payload_signer_tool = (
            f"{_PKCS11_DIR}/payload_signer{_HELPER_SUFFIXES[payload_tool]}"
        )
        args.releasetools += [
            "--verbose",
            "--pkcs11_config",
            str(config_path),
            "--extra_avbtool_signing_args",
            f"--signing_helper {shlex.quote(signing_helper_tool)}",
        ]
        args.signing += ["--payload_signer", payload_signer_tool]
        args.ota += ["--payload_signer", payload_signer_tool]
        args.ota += ["--signapk_external_signer", payload_signer_tool]

    interceptor = environment.get("SIGNING_COMMAND_INTERCEPTOR")
    if interceptor:
        args.signing += ["--signing_command_interceptor", interceptor]
        args.ota += ["--signing_command_interceptor", interceptor]

    max_signature_size = environment.get(
        "PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE",
    )
    if max_signature_size:
        args.signing += [
            "--payload_signer_maximum_signature_size",
            max_signature_size,
        ]
        args.ota += [
            "--payload_signer_maximum_signature_size",
            max_signature_size,
        ]


@contextlib.contextmanager
def _pushd(path: Path) -> Generator[None, None, None]:
    """Run the body with path as the working directory."""
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _show_step(argv: list[str], *, dry_run: bool) -> None:
    """
    Print a step as a quoted command line under DRY_RUN, and as a
    "Running:" line otherwise.

    Args:
        argv: The step's command and arguments.
        dry_run: Whether the release runs under DRY_RUN.
    """
    if dry_run:
        sys.stderr.write(render_release_tool(argv))
    else:
        print("Running:", shlex.join(argv), file=sys.stderr)


_SOONG_RELEASETOOLS = Path(
    "out/soong/.intermediates/build/make/tools/releasetools",
)


def _releasetools_binary(directory: Path, tool: str) -> str:
    """
    Return the tool directly under directory, or else the first match of
    <tool>/*/<tool> under it (Soong's per-host-tag layout), or else an
    empty command after printing an error.
    """
    direct = directory / tool
    candidates = [direct, *sorted(direct.glob(f"*/{tool}"))]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    print(
        f"error: couldn't find releasetools binary '{tool}' under {directory}",
        file=sys.stderr,
    )
    return ""


class SigningSession:
    """
    One run of a signing script.
    """

    command = ""
    usage = ""
    keymapper: Keymapper

    def __init__(
        self,
        environment: MutableMapping[str, str],
        *,
        cwd: Path,
        metadata: SigningMetadata,
        device: str,
        signing_args: list[str],
    ) -> None:
        self.environment = environment
        self.cwd = cwd
        self.metadata = metadata
        self.device = device
        self.dry_run = environment.get("DRY_RUN") == "y"
        self.args = _SessionArgs(
            releasetools=read_words(
                environment.get("EXTRA_RELEASETOOLS_ARGS", ""),
            ),
            signing=signing_args,
            ota=read_words(environment.get("EXTRA_OTA_ARGS", "")),
        )
        self.program = f"{self.command}.sh"
        self.extra_devices = environment.get("EXTRA_DEVICES", "").split()
        self.tmpdir: Path | None = None
        self.vendor_release_initialized = False
        self.inherited_environment = dict(environment)
        self.transcript = Transcript()

    def _run_steps(self) -> None:
        raise NotImplementedError

    def run(self) -> int:
        with exit_on_signals():
            try:
                with contextlib.ExitStack() as self._resources:
                    self._run_steps()
            except ReleaseUsageError as error:
                print(
                    f"error: {error}, please try again",
                    file=sys.stderr,
                )
                print(f"Usage: {self.program} {self.usage}")
                return 1
            except ReleaseAbort as abort:
                return abort.code
            except KeyboardInterrupt:
                return 130
            finally:
                self.transcript.stop()
        return 0

    def _finalize_vendor_release(self) -> None:
        sign_environment.finalize_vendor_release(
            self.environment,
            device=self.device,
            build_number=self.environment.get("BUILD_NUMBER", ""),
            record_finish=self.vendor_release_initialized,
            inherited=self.inherited_environment,
            command=self.command,
        )

    def _resolve_keys(self, keymapper: Keymapper) -> None:
        """
        Resolve the keys the session signs with, before the vendor is set
        up.

        Args:
            keymapper: The keymapper the session loaded.

        Raises:
            ValueError: If the keymapper maps no such key for the device.
        """

    def prepare_for_signing_full(
        self,
        *,
        device: str,
        build_number: str,
        command_argv: list[str],
    ) -> None:
        try:
            sign_environment.load_vendor(self.environment)
            try:
                keymapper = load_keymapper(self.environment, self.metadata)
            except ValueError as error:
                print(error, file=sys.stderr)
                raise ReleaseAbort(1) from error
            self.keymapper = keymapper
            apply_keymapper_exports(self.environment, keymapper)
            try:
                self._resolve_keys(keymapper)
            except ValueError as error:
                print(error, file=sys.stderr)
                raise ReleaseAbort(1) from error
            parent = self.environment.get("TMPDIR") or "/dev/shm"
            tmpdir = Path(parent)
            if _signs_through_pkcs11(self.environment):
                tmpdir = Path(tempfile.mkdtemp(prefix="signing.", dir=parent))
                self.tmpdir = tmpdir
                self._resources.callback(
                    shutil.rmtree,
                    tmpdir,
                    ignore_errors=True,
                )
            self._resources.callback(self._finalize_vendor_release)
            sign_environment.maybe_initialize_vendor(
                self.environment,
                tmpdir=tmpdir,
            )
            release_initialized = self.environment.get(
                "PKCS11_VENDOR_INITIALIZED_RELEASE",
            )
            sign_environment.maybe_initialize_vendor_release(
                self.environment,
                device=device,
                build_number=build_number,
                keymapper=keymapper,
                command=self.command,
            )
            self.vendor_release_initialized = (
                release_initialized != "y"
                and self.environment.get("PKCS11_VENDOR_INITIALIZED_RELEASE")
                == "y"
            )
            self._maybe_start_signing_server()
            prepare_signing_args(
                self.environment,
                self.args,
                tmpdir=tmpdir,
                dry_run=self.dry_run,
            )
        except (RuntimeError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            raise ReleaseAbort(1) from error

        exec_log_path = self.environment.get("EXEC_LOG_PATH")
        if exec_log_path and not self.dry_run:
            try:
                self.transcript.start(Path(exec_log_path))
            except OSError as error:
                print(
                    f"error: cannot write EXEC_LOG_PATH {exec_log_path} "
                    f"({error}), going on without it",
                    file=sys.stderr,
                )
        sys.stderr.write("Command: " + render_release_tool(command_argv))

    def _maybe_start_signing_server(self) -> None:
        """
        Host a SigningServer for the rest of the release when the Python
        YubiHSM interceptor is in use.

        The server holds one YubiHSM session for AVB signatures and
        audit-log extraction, and, unless NEVER_START_APKSIGNER_BATCH=y, one
        "apksigner batch" process. avbtool's signing helper and the OTA
        payload signer default to signing_helper.server.py and
        payload_signer.server.py unless AVB_SIGNING_HELPER_TOOL,
        PAYLOAD_SIGNER_TOOL or SIGNING_HELPER_TOOL chooses them. apksigner
        signs through apksig's "external" KMS provider, whose helper signs
        through the server.
        """
        interceptor = self.environment.get("SIGNING_COMMAND_INTERCEPTOR", "")
        if self.dry_run:
            if Path(interceptor).name == "vendor.yubihsm.interceptor.py":
                self._use_server_helpers()
            return
        if Path(interceptor).name != "vendor.yubihsm.interceptor.py":
            return
        from .yubihsm_session_service import YubiHsmSessionService

        session_service = YubiHsmSessionService(
            sign_environment.yubihsm_config_from_environment(self.environment),
            audit_log_path=(
                Path(self.environment["AUDIT_LOG_PATH"])
                if self.environment.get("AUDIT_LOG_PATH")
                else None
            ),
        )
        handlers: dict[str, Handler] = {
            "yubihsm_sign_pkcs1": session_service,
            "yubihsm_extract_audit_log": session_service,
        }
        if self.environment.get("NEVER_START_APKSIGNER_BATCH") != "y":
            handlers["apksigner"] = ApksignerBatch(
                cwd=self.cwd,
                env=self.environment,
            )
        assert self.tmpdir is not None
        socket_path = self.tmpdir / "signing-server.sock"
        server = SigningServer(socket_path, handlers)
        try:
            self._resources.enter_context(server)
        except OSError as error:
            print(
                f"Warning: not starting the signing server ({error}).",
                file=sys.stderr,
            )
            return
        self.environment["SIGNING_SERVER_SOCKET"] = str(socket_path)
        self._use_server_helpers()

    def _use_server_helpers(self) -> None:
        """
        Point the release at the signing paths the signing server serves,
        unless the variables that choose them are set.
        """
        if not self.environment.get("SIGNING_HELPER_TOOL"):
            for variable in ("AVB_SIGNING_HELPER_TOOL", "PAYLOAD_SIGNER_TOOL"):
                if not self.environment.get(variable):
                    self.environment[variable] = "server"
        self.environment["APKSIGNER_EXTERNAL_SIGNER"] = str(
            _PKCS11_DIR / "apksigner_signing_helper.py",
        )
        self.args.signing += ["--apksigner_kms_type", "external"]

    def _invoke(self, argv: list[str]) -> int:
        if self.dry_run:
            sys.stderr.write(render_release_tool(argv))
            return 0
        return run_release_tool(argv)

    def _write_checksum(self, out_dir: Path, filename: str) -> None:
        """
        Print the commands of filename's checksum and write it to
        filename.sha256sum in out_dir, or under DRY_RUN leave an empty
        file in the working directory.
        """
        _show_step(["pushd", str(out_dir)], dry_run=self.dry_run)
        _show_step(["sha256sum", filename], dry_run=self.dry_run)
        _show_step(["popd"], dry_run=self.dry_run)
        if self.dry_run:
            (self.cwd / f"{filename}.sha256sum").write_text("")
            return
        with _pushd(out_dir):
            text = format_sha256sum(filename)
        (out_dir / f"{filename}.sha256sum").write_text(text)


class ReleaseOrchestrator(SigningSession):
    """
    Owns one release.sh run.
    """

    command = "release"
    usage = "device [target-files.zip]"
    releasetools_binary_path: Path

    def __init__(
        self,
        environment: MutableMapping[str, str],
        *,
        cwd: Path,
        metadata: SigningMetadata,
        device: str,
        target_files_arg: str | None,
    ) -> None:
        super().__init__(
            environment,
            cwd=cwd,
            metadata=metadata,
            device=device,
            signing_args=[
                "--threads",
                "8",
                *read_words(environment.get("EXTRA_SIGNING_ARGS", "")),
            ],
        )
        self.target_files_arg = target_files_arg

    def _run_steps(self) -> None:
        if not self.environment.get("BUILD_NUMBER"):
            raise ReleaseUsageError(
                "BUILD_NUMBER not set, did you source envsetup.sh ?",
            )
        sourced = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"',
                "release.sh",
                _CLEAR_FACTORY_VARIABLES,
            ],
            cwd=self.cwd,
            check=False,
        )
        if sourced.returncode != 0:
            raise ReleaseAbort(sourced.returncode)

        rollback_raw = self.environment.get("AVB_ROLLBACK_INDEX_OVERRIDE")
        rollback = rollback_raw or None
        build = self.environment["BUILD_NUMBER"]
        if rollback is not None:
            if not (build.isascii() and build.isdigit()):
                print(
                    f"error: BUILD_NUMBER {build} is not a number",
                    file=sys.stderr,
                )
                raise ReleaseAbort(1)
            build = str(int(build) + 1)

        if not self.target_files_arg:
            self.releasetools_binary_path = _SOONG_RELEASETOOLS
            target_files = Path(
                "out/target/product",
                self.device,
                f"calyx_{self.device}-target_files-{build}.zip",
            )
            output_path = Path("out/release")
            releasetools_path = Path(".")
        else:
            target_files = Path(self.target_files_arg)
            releasetools_path = self.cwd
            self.args.releasetools += ["-p", str(releasetools_path)]
            self.releasetools_binary_path = releasetools_path / "bin"
            output_path = Path("out")
        out_dir = output_path / f"release-{self.device}-{build}"
        signed_target_files = (
            out_dir / f"{self.device}-target_files-{build}.zip"
        )

        skip_signing = self.environment.get("SKIP_SIGNING") == "y"
        if not skip_signing:
            self.prepare_for_signing_full(
                device=self.device,
                build_number=self.environment["BUILD_NUMBER"],
                command_argv=[
                    self.program,
                    self.device,
                    *([self.target_files_arg] if self.target_files_arg else []),
                ],
            )

        if not self.dry_run:
            version = self._extract_build_id(target_files)
            factory_env = resolve_device_family_environment(
                self.device,
                self.extra_devices,
                target_files,
            )
            if (
                (not self.environment.get("OTA_ONLY") or rollback is not None)
                and not factory_env.get("SKIP_AVB_CUSTOM_KEY")
                and self.environment.get("SKIP_SIGNING") != "y"
            ):
                avb_custom_key = self.cwd / (
                    f"{self.keymapper.key_dir(self.environment)}"
                    f"{self.keymapper.avb_custom_key(self.device)}"
                )
                if not avb_custom_key.is_file():
                    raise ReleaseUsageError(
                        f"AVB custom key {avb_custom_key} does not exist",
                    )
        else:
            version = "version_placeholder"
            factory_env = {}

        _show_step(["mkdir", "-p", str(out_dir)], dry_run=self.dry_run)
        if not self.dry_run:
            out_dir.mkdir(parents=True, exist_ok=True)

        keep_existing = self.environment.get("KEEP_EXISTING", "")

        def _keep(name: str, existing_substr: str) -> bool:
            if existing_substr in keep_existing or keep_existing == "all":
                return True
            return (self.environment.get(name) or "n") != "n"

        keep_target_files = _keep("KEEP_TARGET_FILES", "target")
        keep_ota = _keep("KEEP_OTA", "otaupdate")
        keep_factory = _keep("KEEP_FACTORY", "factory")

        release_args = None
        if skip_signing:
            self._abort_if_ota_only()
            print(
                "Skipping signing and OTA generation, creating factory image "
                "from unsigned target files",
            )
            if signed_target_files.exists():
                _show_step(
                    ["rm", str(signed_target_files)],
                    dry_run=self.dry_run,
                )
            _show_step(
                ["cp", str(target_files), str(signed_target_files)],
                dry_run=self.dry_run,
            )
            if not self.dry_run:
                signed_target_files.unlink(missing_ok=True)
                try:
                    shutil.copyfile(target_files, signed_target_files)
                except OSError as error:
                    print(f"cp: {error}", file=sys.stderr)
                    raise ReleaseAbort(1) from error
        else:
            release_args = self._build_release_arguments(rollback)

            if not keep_target_files or not signed_target_files.exists():
                print("Creating signed targetfiles zip")
                code = self._invoke(
                    [
                        _releasetools_binary(
                            self.releasetools_binary_path,
                            "sign_target_files_apks",
                        ),
                        *self.args.releasetools,
                        "-o",
                        *release_args.signing_args,
                        str(target_files),
                        str(signed_target_files),
                    ],
                )
                if code != 0:
                    raise ReleaseAbort(1)

            if rollback is not None:
                print(
                    "Skipping OTA update zip for AVB Rollback Index "
                    "override build",
                )
            else:
                ota_zip = out_dir / f"{self.device}-ota_update-{build}.zip"
                if not keep_ota or not ota_zip.exists():
                    print("Creating OTA update zip")
                    code = self._invoke(
                        [
                            _releasetools_binary(
                                self.releasetools_binary_path,
                                "ota_from_target_files",
                            ),
                            *self.args.releasetools,
                            *release_args.ota_args,
                            str(signed_target_files),
                            str(ota_zip),
                        ],
                    )
                    if code != 0:
                        raise ReleaseAbort(1)

                    print("Calculating sha256sum for OTA update zip")
                    self._write_checksum(out_dir, ota_zip.name)

                self._abort_if_ota_only()

        img_zip = out_dir / f"{self.device}-img-{build}.zip"
        if not keep_factory or not img_zip.exists():
            print("Creating factory image")
            code = self._invoke(
                [
                    _releasetools_binary(
                        self.releasetools_binary_path,
                        "img_from_target_files",
                    ),
                    *self.args.releasetools,
                    str(signed_target_files),
                    str(img_zip),
                ],
            )
            if code != 0:
                raise ReleaseAbort(1)

        self._assemble_factory_image(
            out_dir=out_dir,
            releasetools_path=releasetools_path,
            version=version,
            build=build,
            factory_env=factory_env,
        )

        otatest = self.environment.get("OTATEST")
        if otatest and release_args is not None:
            otatest_target_files = (
                out_dir / f"{self.device}-target_files-{otatest}.zip"
            )
            print("Creating OTA test update zip")
            code = self._invoke(
                [
                    _releasetools_binary(
                        self.releasetools_binary_path,
                        "sign_target_files_apks",
                    ),
                    *self.args.releasetools,
                    "--otatest",
                    "-o",
                    *release_args.signing_args,
                    str(target_files),
                    str(otatest_target_files),
                ],
            )
            if code != 0:
                raise ReleaseAbort(1)

            otatest_ota_zip = (
                out_dir / f"{self.device}-ota_update-{otatest}.zip"
            )
            code = self._invoke(
                [
                    _releasetools_binary(
                        self.releasetools_binary_path,
                        "ota_from_target_files",
                    ),
                    *self.args.releasetools,
                    *release_args.ota_args,
                    str(otatest_target_files),
                    str(otatest_ota_zip),
                ],
            )
            if code != 0:
                raise ReleaseAbort(1)

            print("Calculating sha256sum for OTA test update zip")
            self._write_checksum(out_dir, otatest_ota_zip.name)

    def _abort_if_ota_only(self) -> None:
        if self.environment.get("OTA_ONLY"):
            print(
                "Not creating factory image due to OTA_ONLY="
                f"{self.environment['OTA_ONLY']}",
            )
            raise ReleaseAbort(0)

    def _build_release_arguments(
        self,
        rollback: str | None,
    ) -> ReleaseArguments:
        avb_algorithm = avb_algorithm_for(self.environment, self.keymapper)
        get_key = make_get_key(
            self.keymapper,
            self.environment,
            device=self.device,
        )
        try:
            return build_release_arguments(
                self.metadata,
                get_key,
                device=self.device,
                avb_rollback_index_override=rollback,
                avb_algorithm=avb_algorithm,
                extra_signing_args=self.args.signing,
                extra_ota_args=self.args.ota,
            )
        except UnsupportedRollbackDeviceError as error:
            print(str(error))
            raise ReleaseAbort(1) from error

    def _extract_build_id(self, target_files: Path) -> str:
        try:
            with zipfile.ZipFile(target_files) as archive:
                text = archive.read("SYSTEM/build.prop").decode()
        except (OSError, KeyError, zipfile.BadZipFile) as error:
            print(
                f"error: cannot read SYSTEM/build.prop from {target_files} "
                f"({error})",
                file=sys.stderr,
            )
            raise ReleaseAbort(1) from error
        for line in text.splitlines():
            name, sep, value = line.partition("=")
            if sep and name == "ro.build.id":
                return value.lower()
        return ""

    def _assemble_factory_image(
        self,
        *,
        out_dir: Path,
        releasetools_path: Path,
        version: str,
        build: str,
        factory_env: dict[str, str],
    ) -> None:
        android_build_top = self.environment.get("ANDROID_BUILD_TOP")
        if android_build_top:
            source_path = (
                Path(android_build_top)
                / "device/common/generate-factory-images-common.sh"
            )
        else:
            source_path = (
                self.cwd
                / releasetools_path
                / "device/common/generate-factory-images-common.sh"
            )

        _show_step(["pushd", str(out_dir)], dry_run=self.dry_run)

        _show_step(["source", str(source_path)], dry_run=self.dry_run)
        if not self.dry_run:
            assignments = {
                **factory_env,
                "DEVICE": self.device,
                "VERSION": version,
                "BUILD": build,
                "PRODUCT": self.device,
            }
            if self.environment.get("SKIP_SIGNING") != "y":
                key_dir = self.keymapper.key_dir(self.environment)
                assignments["AVB_CUSTOM_KEY"] = str(
                    self.cwd
                    / f"{key_dir}{self.keymapper.avb_custom_key(self.device)}",
                )
            assembled = subprocess.run(
                [
                    "bash",
                    "-c",
                    _FACTORY_IMAGE_SCRIPT,
                    "factory-image-assembly",
                    str(out_dir),
                    str(source_path),
                    str(self.cwd / _CLEAR_FACTORY_VARIABLES),
                    *(f"{name}={value}" for name, value in assignments.items()),
                ],
                check=False,
                env={**os.environ, **self.environment},
            )
            if assembled.returncode != 0:
                raise ReleaseAbort(assembled.returncode)

        pattern = f"{self.device}-{version}-factory-*.zip"
        matches = sorted(p.name for p in out_dir.glob(pattern))
        final_name = f"{self.device}-factory-{build}.zip"
        if self.dry_run:
            sources = matches if matches else [pattern]
            sys.stderr.write(render_release_tool(["mv", *sources, final_name]))
        else:
            if len(matches) != 1:
                print(
                    f"error: expected one file matching {pattern!r} in "
                    f"{out_dir}, found {matches!r}",
                    file=sys.stderr,
                )
                raise ReleaseAbort(1)
            _show_step(["mv", matches[0], final_name], dry_run=False)
            (out_dir / matches[0]).rename(out_dir / final_name)

        print("Calculating sha256sum for factory image")
        _show_step(["sha256sum", final_name], dry_run=self.dry_run)
        if self.dry_run:
            (self.cwd / f"{final_name}.sha256sum").write_text("")
        else:
            with _pushd(out_dir):
                text = format_sha256sum(final_name)
            (out_dir / f"{final_name}.sha256sum").write_text(text)

        _show_step(["popd"], dry_run=self.dry_run)

        print(
            "Removing intermediate file after factory image generation: "
            f"{self.device}-img-{build}.zip",
        )
        img_zip = out_dir / f"{self.device}-img-{build}.zip"
        _show_step(["rm", str(img_zip)], dry_run=self.dry_run)
        if not self.dry_run:
            img_zip.unlink()


def _vendor_release_reads_build_number(
    environment: MutableMapping[str, str],
) -> bool:
    """
    Return whether initializing the vendor for a release names its logs
    after BUILD_NUMBER, which the SoftHSM vendor always does and the
    YubiHSM vendor does outside DRY_RUN, unless the release is initialized
    already.
    """
    if environment.get("PKCS11_VENDOR_INITIALIZED_RELEASE") == "y":
        return False
    if environment.get("PKCS11_VENDOR") == "yubihsm":
        return environment.get("DRY_RUN") != "y"
    return environment.get("PKCS11_VENDOR") == "softhsm"


class DeltaOrchestrator(SigningSession):
    """
    Owns one generate_delta.sh run, which builds the incremental OTA
    between two signed releases in archive/.
    """

    command = "generate_delta"
    usage = "device oldversion newversion"

    def __init__(
        self,
        environment: MutableMapping[str, str],
        *,
        cwd: Path,
        metadata: SigningMetadata,
        device: str,
        old: str,
        new: str,
    ) -> None:
        super().__init__(
            environment,
            cwd=cwd,
            metadata=metadata,
            device=device,
            signing_args=[],
        )
        self.old = old
        self.new = new
        self.ota_key = ""

    def _resolve_keys(self, keymapper: Keymapper) -> None:
        self.ota_key = make_get_key(
            keymapper,
            self.environment,
            device=self.device,
        )("other", "ota")

    def _run_steps(self) -> None:
        if (self.cwd / "build/tools/releasetools").is_dir():
            ota_from_target_files = _releasetools_binary(
                _SOONG_RELEASETOOLS,
                "ota_from_target_files",
            )
            if not ota_from_target_files:
                raise ReleaseAbort(1)
        else:
            ota_from_target_files = "./bin/ota_from_target_files"
            self.args.releasetools += ["-p", "."]
        if "BUILD_NUMBER" not in self.environment and (
            _vendor_release_reads_build_number(self.environment)
        ):
            print(
                "BUILD_NUMBER not set, did you source envsetup.sh ?",
                file=sys.stderr,
            )
            raise ReleaseAbort(1)
        try:
            self.prepare_for_signing_full(
                device=self.device,
                build_number=self.environment.get("BUILD_NUMBER", ""),
                command_argv=[
                    self.program,
                    self.device,
                    self.old,
                    self.new,
                ],
            )
        except ReleaseAbort as abort:
            raise ReleaseUsageError("failed to prepare for signing") from abort

        old_dir = f"archive/release-{self.device}-{self.old}"
        new_dir = f"archive/release-{self.device}-{self.new}"
        incremental = f"{self.device}-incremental-{self.old}-{self.new}.zip"
        code = self._invoke(
            [
                ota_from_target_files,
                *self.args.releasetools,
                *self.args.ota,
                "-k",
                self.ota_key,
                "-i",
                f"{old_dir}/{self.device}-target_files-{self.old}.zip",
                f"{new_dir}/{self.device}-target_files-{self.new}.zip",
                f"{new_dir}/{incremental}",
            ],
        )
        if code != 0:
            raise ReleaseAbort(code)

        print("Calculating sha256sum for incremental")
        self._write_checksum(Path(new_dir), incremental)
