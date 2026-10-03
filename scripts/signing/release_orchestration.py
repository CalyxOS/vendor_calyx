#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Run the release command.
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
from collections.abc import Generator, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path

from . import sign_environment
from .keymap import Keymapper, apply_keymapper_exports, load_keymapper
from .metadata import SigningMetadata
from .release_arguments import (
    GetKey,
    ReleaseArguments,
    UnsupportedRollbackDeviceError,
    build_release_arguments,
    make_get_key,
)
from .release_execution import (
    exit_on_signals,
    format_sha256sum,
    render_release_tool,
    run_release_tool,
)

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


def avb_algorithm_for(environment: Mapping[str, str]) -> str:
    """
    Pick the AVB algorithm for the keymapper in use.

    The legacy keymapper takes AVB_RSA_KEY_SIZE. With PKCS#11 signing,
    the other keymappers take the keys' RSA_KEY_SIZE, and without it
    AVB_RSA_KEY_SIZE, then RSA_KEY_SIZE. Each defaults to 4096.

    Args:
        environment: Process environment to read KEYMAPPER,
            PKCS11_MODULE/PKCS11_VENDOR and the key sizes from.

    Returns:
        The AVB algorithm, such as "SHA256_RSA4096".
    """
    if (environment.get("KEYMAPPER") or "legacy") == "legacy":
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
    target_files: Path,
) -> dict[str, str]:
    """
    Resolve the device family's BOOTLOADER/RADIO versions and the vendor
    flags the factory-image assembly script reads.

    Args:
        device: The device being released.
        target_files: Path to the target-files zip, read for
            BOOTLOADER/RADIO only when needed.

    Returns:
        Environment variables to add for the factory-image step, with
        no key for a flag the device leaves unset.

    Raises:
        ReleaseUsageError: If the device is not recognized.
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


def make_release_get_key(
    keymapper: Keymapper,
    environment: MutableMapping[str, str],
    *,
    device: str,
) -> GetKey:
    """
    Build a key resolver over the release's keymapper, with KEY_SUFFIX
    defaulting to .pem only when unset.

    Args:
        keymapper: The keymapper the release loaded.
        environment: Process environment to read KEY_DIR and KEY_SUFFIX
            from.
        device: Device being released.

    Returns:
        A callable taking key_type and key_name, see make_get_key().
    """
    return make_get_key(
        keymapper,
        device=device,
        key_dir=keymapper.key_dir(environment),
        key_suffix=environment.get("KEY_SUFFIX", ".pem"),
    )


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
        RuntimeError: If the configured signing/payload-signer helper
            tool is missing.
    """
    if _signs_through_pkcs11(environment):
        config_path = tmpdir / "sunpkcs11.cfg"
        _show_step(["generate_sunpkcs11_config"], dry_run=dry_run)
        if not dry_run:
            config_path.write_text(generate_sunpkcs11_config(environment))
        tool = environment.get("SIGNING_HELPER_TOOL") or "openssl"
        avb_tool = environment.get("AVB_SIGNING_HELPER_TOOL") or tool
        if avb_tool == "python":
            signing_helper_tool = f"{_PKCS11_DIR}/signing_helper.py"
        else:
            signing_helper_tool = f"{_PKCS11_DIR}/signing_helper.{avb_tool}.sh"
        payload_tool = environment.get("PAYLOAD_SIGNER_TOOL") or tool
        if payload_tool == "python":
            payload_signer_tool = f"{_PKCS11_DIR}/payload_signer.py"
        else:
            payload_signer_tool = (
                f"{_PKCS11_DIR}/payload_signer.{payload_tool}.sh"
            )
        if (
            not Path(signing_helper_tool).exists()
            or not Path(payload_signer_tool).exists()
        ):
            raise RuntimeError(
                f"Looking for signing helper tools '{avb_tool}' and "
                f"'{payload_tool}', missing '{signing_helper_tool}' and/or "
                f"'{payload_signer_tool}'",
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


class SigningSession:
    """
    One run of a signing script.
    """

    command = ""
    flag = ""
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
        self.tmpdir: Path | None = None
        self.vendor_release_initialized = False
        self.inherited_environment = dict(environment)

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
            prepare_signing_args(
                self.environment,
                self.args,
                tmpdir=tmpdir,
                dry_run=self.dry_run,
            )
        except (RuntimeError, OSError) as error:
            message = sign_environment.describe_vendor_error(error, self.flag)
            print(f"error: {message}", file=sys.stderr)
            raise ReleaseAbort(1) from error

        sys.stderr.write("Command: " + render_release_tool(command_argv))

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
    flag = "USE_PYTHON_RELEASE_ORCHESTRATION"
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
            signing_args=read_words(environment.get("EXTRA_SIGNING_ARGS", "")),
        )
        self.target_files_arg = target_files_arg

    def _run_steps(self) -> None:
        if self.environment.get("KEYMAPPER_FILE"):
            raise ReleaseUsageError(
                "USE_PYTHON_RELEASE_ORCHESTRATION does not support "
                "KEYMAPPER_FILE",
            )
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
            self.releasetools_binary_path = Path(
                "out/soong/.intermediates/build/make/tools/releasetools",
            )
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
                        self._releasetools_binary("sign_target_files_apks"),
                        *self.args.releasetools,
                        "-o",
                        *release_args.signing_args,
                        *release_args.avb_arguments,
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
                            self._releasetools_binary("ota_from_target_files"),
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
                    self._releasetools_binary("img_from_target_files"),
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
                    self._releasetools_binary("sign_target_files_apks"),
                    *self.args.releasetools,
                    "--otatest",
                    "-o",
                    *release_args.signing_args,
                    *release_args.avb_arguments,
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
                    self._releasetools_binary("ota_from_target_files"),
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
        avb_algorithm = avb_algorithm_for(self.environment)
        get_key = make_release_get_key(
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

    def _releasetools_binary(self, tool: str) -> str:
        """
        Return the tool directly under RELEASETOOLS_BINARY_PATH, or else
        the first match of <tool>/*/<tool> under it (Soong's per-host-tag
        layout), or else an empty command after printing an error.
        """
        direct = self.releasetools_binary_path / tool
        candidates = [direct, *sorted(direct.glob(f"*/{tool}"))]
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        print(
            f"error: couldn't find releasetools binary '{tool}' under "
            f"{self.releasetools_binary_path}",
            file=sys.stderr,
        )
        return ""

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
