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
from collections.abc import Mapping, MutableMapping, Sequence
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
    Abort,
    Transcript,
    defer_signals,
    exit_on_signals,
    format_sha256sum,
    render_release_tool,
    run_release_tool,
)
from .sign_planning import is_build_number
from .signing_server import SigningServer

_PKCS11_DIR = Path(__file__).resolve().parents[1] / "pkcs11"

_CLEAR_FACTORY_VARIABLES = "device/common/clear-factory-images-variables.sh"

# generate-factory-images-common.sh extracts the signed target-files with
# Info-ZIP unzip. Its distro-patched zip-bomb check reads a 32-bit data
# descriptor after an entry past 4 GiB as 64-bit and refuses soong_zip
# archives that large, as AOSP notes where it sets the same variable for the
# build (build/soong/ui/build/config.go).
_FACTORY_IMAGE_SCRIPT = """
set -uo pipefail
export UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE
out_dir=$1 common_script=$2 clear_script=$3
shift 3
source "$clear_script" || exit
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
    elif _signs_through_pkcs11(environment):
        size = environment.get("RSA_KEY_SIZE") or "4096"
    else:
        size = (
            environment.get("AVB_RSA_KEY_SIZE")
            or environment.get("RSA_KEY_SIZE")
            or "4096"
        )
    return f"SHA256_RSA{size}"


def _read_target_files_entry(target_files: Path, name: str) -> str:
    """
    Read one text entry of a target-files zip.

    Args:
        target_files: The target-files zip.
        name: The entry, such as "SYSTEM/build.prop".

    Returns:
        The entry's text.

    Raises:
        Abort: If the zip or the entry cannot be read.
    """
    try:
        with zipfile.ZipFile(target_files) as archive:
            return archive.read(name).decode()
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        print(
            f"error: cannot read {name} from {target_files} ({error})",
            file=sys.stderr,
        )
        raise Abort(1) from error


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
        Abort: If the zip or its android-info.txt cannot be read.
    """
    text = _read_target_files_entry(target_files, "OTA/android-info.txt")
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
        environment.get("PKCS11_MODULE") or environment.get("PKCS11_VENDOR"),
    )


def prepare_signing_args(
    environment: MutableMapping[str, str],
    args: _SessionArgs,
) -> None:
    """
    When a PKCS#11 module/vendor is configured, extend the three argument
    lists with the signing/payload-signer helper tools and apksigner's
    calyx KMS type, and (if set) add the signing-command interceptor and
    payload-signer maximum-signature-size overrides.

    releasetools takes --pkcs11_config as the switch to PKCS#11 signing
    and reads the file only for a SunPKCS11 KeyStore, which the KMS type
    and the external signer replace, so it is given /dev/null.

    Args:
        environment: Process environment to read PKCS11_MODULE/
            PKCS11_VENDOR and the overrides from, and to point
            CALYX_APKSIGNER_SIGNING_HELPER at the apksigner helper in.
        args: Argument lists to extend in place.

    Returns:
        None.
    """
    if _signs_through_pkcs11(environment):
        signing_helper_tool = f"{_PKCS11_DIR}/signing_helper.py"
        payload_signer_tool = f"{_PKCS11_DIR}/payload_signer.py"
        args.releasetools += [
            "--verbose",
            "--pkcs11_config",
            "/dev/null",
            "--extra_avbtool_signing_args",
            f"--signing_helper {shlex.quote(signing_helper_tool)}",
        ]
        args.signing += [
            "--payload_signer",
            payload_signer_tool,
            "--apksigner_kms_type",
            "calyx",
        ]
        args.ota += [
            "--payload_signer",
            payload_signer_tool,
            "--signapk_external_signer",
            payload_signer_tool,
        ]
        environment["CALYX_APKSIGNER_SIGNING_HELPER"] = str(
            _PKCS11_DIR / "apksigner_signing_helper.py",
        )

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
        program: str,
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
        self.program = program
        self.extra_devices = environment.get("EXTRA_DEVICES", "").split()
        self.tmpdir: Path | None = None
        self.vendor_release_initialized = False
        self.inherited_environment = dict(environment)
        self.transcript = Transcript()

    def _run_steps(self) -> None:
        raise NotImplementedError

    def run(self) -> int:
        """
        Run the steps, then release what they acquired with SIGTERM and
        SIGHUP held back, and SIGINT as well, so that a repeated signal
        cannot cut the cleanup short.

        Returns:
            0 on success, or the exit status of the failure.
        """
        with defer_signals():
            try:
                self._resources = contextlib.ExitStack()
                try:
                    with exit_on_signals():
                        self._run_steps()
                except BaseException as error:
                    with defer_signals(interrupt=True):
                        if not self._resources.__exit__(
                            type(error),
                            error,
                            error.__traceback__,
                        ):
                            raise
                else:
                    with defer_signals(interrupt=True):
                        self._resources.__exit__(None, None, None)
            except ReleaseUsageError as error:
                print(
                    f"error: {error}, please try again",
                    file=sys.stderr,
                )
                print(f"Usage: {self.program} {self.usage}")
                return 1
            except Abort as abort:
                return abort.code
            except KeyboardInterrupt:
                return 130
            finally:
                self.transcript.stop()
        return 0

    def _finalize_vendor_release(
        self,
        vendor: sign_environment.Vendor,
        build_number: str,
    ) -> None:
        vendor.finalize_release(
            self.environment,
            device=self.device,
            build_number=build_number,
            record_finish=self.vendor_release_initialized,
            command=self.command,
        )
        vendor.cleanup(self.environment, inherited=self.inherited_environment)

    def _resolve_keys(self, keymapper: Keymapper) -> None:
        """
        Resolve the keys the session signs with, before the vendor is set
        up.

        Args:
            keymapper: The keymapper the session loaded.

        Raises:
            ValueError: If the keymapper maps no such key for the device.
        """

    def prepare_signing(
        self,
        *,
        command_argv: list[str],
    ) -> None:
        """
        Load the keymapper, set up the vendor and the signing arguments,
        start the EXEC_LOG_PATH transcript and print the command line.

        Args:
            command_argv: The command line to print.

        Raises:
            Abort: With exit status 1, if the keymapper, the keys or the
                vendor cannot be set up.
        """
        try:
            vendor = sign_environment.load_vendor(self.environment)
            try:
                keymapper = load_keymapper(self.environment, self.metadata)
            except ValueError as error:
                print(error, file=sys.stderr)
                raise Abort(1) from error
            self.keymapper = keymapper
            apply_keymapper_exports(self.environment, keymapper)
            try:
                self._resolve_keys(keymapper)
            except ValueError as error:
                print(error, file=sys.stderr)
                raise Abort(1) from error
            if vendor is not None:
                parent = self.environment.get("TMPDIR") or "/dev/shm"
                tmpdir = Path(tempfile.mkdtemp(prefix="signing.", dir=parent))
                self.tmpdir = tmpdir
                self._resources.callback(
                    shutil.rmtree,
                    tmpdir,
                    ignore_errors=True,
                )
                build_number = self.environment.get("BUILD_NUMBER", "")
                self._resources.callback(
                    self._finalize_vendor_release,
                    vendor,
                    build_number,
                )
                sign_environment.maybe_initialize_vendor(
                    self.environment,
                    tmpdir=tmpdir,
                )
                if (
                    self.environment.get("PKCS11_VENDOR_INITIALIZED_RELEASE")
                    != "y"
                ):
                    vendor.initialize_release(
                        self.environment,
                        device=self.device,
                        build_number=build_number,
                        keymapper=keymapper,
                        command=self.command,
                    )
                    self.environment["PKCS11_VENDOR_INITIALIZED_RELEASE"] = "y"
                    self.vendor_release_initialized = True
            self._maybe_start_signing_server()
            prepare_signing_args(self.environment, self.args)
        except (RuntimeError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            raise Abort(1) from error

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

        The server holds one YubiHSM session for signatures and audit-log
        extraction and, unless NEVER_START_APKSIGNER_BATCH=y, one
        "apksigner batch" process.
        """
        interceptor = self.environment.get("SIGNING_COMMAND_INTERCEPTOR", "")
        if (
            self.dry_run
            or Path(interceptor).name != "vendor.yubihsm.interceptor.py"
        ):
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
        assert self.tmpdir is not None
        socket_path = self.tmpdir / "signing-server.sock"
        server = SigningServer(socket_path)
        server.add_service(
            {
                "yubihsm_sign_pkcs1": session_service.sign,
                "yubihsm_extract_audit_log": session_service.extract_audit_log,
            },
            session_service.close,
        )
        if self.environment.get("NEVER_START_APKSIGNER_BATCH") != "y":
            batch = ApksignerBatch(cwd=self.cwd, env=self.environment)
            server.add_service({"apksigner": batch.handle}, batch.close)
        try:
            self._resources.enter_context(server)
        except OSError as error:
            print(
                f"Warning: not starting the signing server ({error}).",
                file=sys.stderr,
            )
            return
        self.environment["SIGNING_SERVER_SOCKET"] = str(socket_path)

    def _invoke(self, argv: list[str]) -> int:
        if self.dry_run:
            sys.stderr.write(render_release_tool(argv))
            return 0
        return run_release_tool(argv)

    def _run_tool(self, argv: list[str]) -> None:
        """
        Run or under DRY_RUN=y print one release tool invocation.

        Raises:
            Abort: With exit status 1, if the tool fails.
        """
        if self._invoke(argv) != 0:
            raise Abort(1)

    def _write_checksum(self, out_dir: Path, filename: str) -> None:
        """
        Write filename's checksum to filename.sha256sum in out_dir,
        unless DRY_RUN=y.
        """
        if self.dry_run:
            return
        (out_dir / f"{filename}.sha256sum").write_text(
            format_sha256sum(out_dir, filename),
        )


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
        program: str,
        device: str,
        target_files_arg: str | None,
    ) -> None:
        super().__init__(
            environment,
            cwd=cwd,
            metadata=metadata,
            program=program,
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
        rollback_raw = self.environment.get("AVB_ROLLBACK_INDEX_OVERRIDE")
        rollback = rollback_raw or None
        factory_image = not self.environment.get("OTA_ONLY") or (
            rollback is not None
        )
        if factory_image:
            self._check_factory_variables()
        build = self.environment["BUILD_NUMBER"]
        if rollback is not None:
            if not is_build_number(build):
                print(
                    f"error: BUILD_NUMBER {build} is not a number",
                    file=sys.stderr,
                )
                raise Abort(1)
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
            self.prepare_signing(
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
            avb_custom_key = self._avb_custom_key()
            if (
                factory_image
                and not factory_env.get("SKIP_AVB_CUSTOM_KEY")
                and avb_custom_key is not None
                and not avb_custom_key.is_file()
            ):
                raise ReleaseUsageError(
                    f"AVB custom key {avb_custom_key} does not exist",
                )
        else:
            version = "version_placeholder"
            factory_env = {}

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
            if not self.dry_run:
                signed_target_files.unlink(missing_ok=True)
                try:
                    shutil.copyfile(target_files, signed_target_files)
                except OSError as error:
                    print(f"cp: {error}", file=sys.stderr)
                    raise Abort(1) from error
        else:
            release_args = self._build_release_arguments(rollback)

            if not keep_target_files or not signed_target_files.exists():
                print("Creating signed targetfiles zip")
                self._sign_target_files(
                    release_args,
                    target_files,
                    signed_target_files,
                )

            if rollback is not None:
                print(
                    "Skipping OTA update zip for AVB Rollback Index "
                    "override build",
                )
            else:
                ota_zip = out_dir / f"{self.device}-ota_update-{build}.zip"
                if not keep_ota or not ota_zip.exists():
                    print("Creating OTA update zip")
                    self._make_ota(release_args, signed_target_files, ota_zip)

                    print("Calculating sha256sum for OTA update zip")
                    self._write_checksum(out_dir, ota_zip.name)

                self._abort_if_ota_only()

        img_zip = out_dir / f"{self.device}-img-{build}.zip"
        if not keep_factory or not img_zip.exists():
            print("Creating factory image")
            self._run_tool(
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
            self._sign_target_files(
                release_args,
                target_files,
                otatest_target_files,
                "--otatest",
            )

            otatest_ota_zip = (
                out_dir / f"{self.device}-ota_update-{otatest}.zip"
            )
            self._make_ota(release_args, otatest_target_files, otatest_ota_zip)

            print("Calculating sha256sum for OTA test update zip")
            self._write_checksum(out_dir, otatest_ota_zip.name)

    def _check_factory_variables(self) -> None:
        """
        Stop the release unless the factory image variables can be sourced.

        Raises:
            Abort: If sourcing them fails, with bash's status.
        """
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
            raise Abort(sourced.returncode)

    def _sign_target_files(
        self,
        release_args: ReleaseArguments,
        target_files: Path,
        signed_target_files: Path,
        *options: str,
    ) -> None:
        self._run_tool(
            [
                _releasetools_binary(
                    self.releasetools_binary_path,
                    "sign_target_files_apks",
                ),
                *self.args.releasetools,
                *options,
                "-o",
                *release_args.signing_args,
                str(target_files),
                str(signed_target_files),
            ],
        )

    def _make_ota(
        self,
        release_args: ReleaseArguments,
        target_files: Path,
        ota_zip: Path,
    ) -> None:
        self._run_tool(
            [
                _releasetools_binary(
                    self.releasetools_binary_path,
                    "ota_from_target_files",
                ),
                *self.args.releasetools,
                *release_args.ota_args,
                str(target_files),
                str(ota_zip),
            ],
        )

    def _abort_if_ota_only(self) -> None:
        if self.environment.get("OTA_ONLY"):
            print(
                "Not creating factory image due to OTA_ONLY="
                f"{self.environment['OTA_ONLY']}",
            )
            raise Abort(0)

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
            raise Abort(1) from error

    def _extract_build_id(self, target_files: Path) -> str:
        text = _read_target_files_entry(target_files, "SYSTEM/build.prop")
        for line in text.splitlines():
            name, sep, value = line.partition("=")
            if sep and name == "ro.build.id":
                return value.lower()
        return ""

    def _avb_custom_key(self) -> Path | None:
        """
        Return the AVB custom key file the factory image carries, or None
        for a release that does not sign.
        """
        if self.environment.get("SKIP_SIGNING") == "y":
            return None
        key_dir = self.keymapper.key_dir(self.environment)
        return (
            self.cwd / f"{key_dir}{self.keymapper.avb_custom_key(self.device)}"
        )

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

        assignments = {
            **factory_env,
            "DEVICE": self.device,
            "VERSION": version,
            "BUILD": build,
            "PRODUCT": self.device,
        }
        avb_custom_key = self._avb_custom_key()
        if avb_custom_key is not None:
            assignments["AVB_CUSTOM_KEY"] = str(avb_custom_key)
        argv = [
            "bash",
            "-c",
            _FACTORY_IMAGE_SCRIPT,
            "factory-image-assembly",
            str(out_dir),
            str(source_path),
            str(self.cwd / _CLEAR_FACTORY_VARIABLES),
            *(f"{name}={value}" for name, value in assignments.items()),
        ]
        final_name = f"{self.device}-factory-{build}.zip"
        img_zip = out_dir / f"{self.device}-img-{build}.zip"
        if self.dry_run:
            sys.stderr.write(render_release_tool(argv))
            print("Calculating sha256sum for factory image")
            print(
                "Removing intermediate file after factory image generation: "
                f"{img_zip.name}",
            )
            return

        print("Running:", shlex.join(argv), file=sys.stderr)
        assembled = subprocess.run(
            argv,
            check=False,
            env={**os.environ, **self.environment},
        )
        if assembled.returncode != 0:
            raise Abort(assembled.returncode)

        pattern = f"{self.device}-{version}-factory-*.zip"
        matches = sorted(p.name for p in out_dir.glob(pattern))
        if len(matches) != 1:
            print(
                f"error: expected one file matching {pattern!r} in "
                f"{out_dir}, found {matches!r}",
                file=sys.stderr,
            )
            raise Abort(1)
        (out_dir / matches[0]).rename(out_dir / final_name)

        print("Calculating sha256sum for factory image")
        self._write_checksum(out_dir, final_name)

        print(
            "Removing intermediate file after factory image generation: "
            f"{img_zip.name}",
        )
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
        program: str,
        device: str,
        old: str,
        new: str,
    ) -> None:
        super().__init__(
            environment,
            cwd=cwd,
            metadata=metadata,
            program=program,
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
                raise Abort(1)
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
            raise Abort(1)
        self.prepare_signing(
            command_argv=[self.program, self.device, self.old, self.new],
        )

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
            raise Abort(code)

        print("Calculating sha256sum for incremental")
        self._write_checksum(Path(new_dir), incremental)
