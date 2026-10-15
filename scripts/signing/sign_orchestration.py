#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Top-level orchestration of sign.sh.
"""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from . import sign_environment
from .confirmation import ask_variable, confirm
from .keymap import Keymapper, apply_keymapper_exports, load_keymapper
from .metadata import SigningMetadata
from .release_execution import (
    Abort,
    defer_signals,
    exit_on_signals,
)
from .sign_execution import generate_incrementals as _run_generate_incrementals
from .sign_execution import sign_builds as _run_sign_builds
from .sign_planning import (
    IncrementalTriple,
    SigningPlan,
    SignPair,
    find_prev_signed_device_builds,
    gather_device_builds,
    gather_signable_devices,
    is_build_number,
    parse_build_numbers,
    partition_by_key_availability,
)

_DEVICES_BRIDGE = r"""
set -euo pipefail
source "$1"
for device in ${devices[@]+"${devices[@]}"}; do
  printf '%s\0' "$device"
done
"""


def load_devices_file(path: Path) -> tuple[str, ...]:
    """
    Read the site-specific `devices` Bash array from a DEVICES_FILE.

    The file is sourced by bash, and only the `devices` array is read
    back.

    Args:
        path: Path to a devices file (e.g. vars/devices).

    Returns:
        The device names it declares, in file order.

    Raises:
        subprocess.CalledProcessError: If Bash cannot source the file.
    """
    completed = subprocess.run(
        ["bash", "-c", _DEVICES_BRIDGE, "devices-bridge", str(path)],
        stdin=subprocess.DEVNULL,
        check=True,
        capture_output=True,
    )
    parts = completed.stdout.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return tuple(part.decode() for part in parts)


T = TypeVar("T")


class SignStepError(Exception):
    """
    One orchestration step failed with a non-zero exit code.
    """

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def _reported_step_error(message: str) -> SignStepError:
    print(f"\n{message}", file=sys.stderr)
    return SignStepError(message)


class SignDone(Exception):
    """
    Raised to end the run early with exit status 0, when there is nothing
    left to do or a dry run has shown its plan.
    """


@dataclass
class SignState:
    """Mutable state the orchestration steps read and update."""

    target_files: list[str] = field(default_factory=list[str])
    signable_devices: tuple[str, ...] = ()
    device_to_next_build: dict[str, int] = field(default_factory=dict[str, int])
    device_to_prev_build: dict[str, int] = field(default_factory=dict[str, int])
    device_to_preexisting_build: dict[str, int] = field(
        default_factory=dict[str, int],
    )
    devices_without_loaded_keys: tuple[str, ...] = ()
    no_incremental: bool = False


def _join_builds(device_to_build: Mapping[str, int]) -> str:
    return " ".join(
        str(build) for build in sorted(set(device_to_build.values()))
    )


class SignOrchestrator:
    """
    Owns one sign.sh run.
    """

    def __init__(
        self,
        environment: MutableMapping[str, str],
        *,
        cwd: Path,
        devices_file: Path,
        metadata: SigningMetadata,
        release_script: Path,
        generate_delta_script: Path,
    ) -> None:
        """
        Prepare a sign.sh run.

        Args:
            environment: Process environment, read and mutated in place.
            cwd: Directory sign.sh is run from, holding the target files,
                archive/ and logs/. It must be the working directory, in
                which the release jobs write out/.
            devices_file: Path to the site-specific DEVICES_FILE.
            metadata: Loaded signing metadata.
            release_script: release.sh each signing job runs.
            generate_delta_script: generate_delta.sh each incremental job
                runs.
        """
        self.environment = environment
        self.cwd = cwd
        self.devices_file = devices_file
        self.metadata = metadata
        self.release_script = release_script
        self.generate_delta_script = generate_delta_script
        self.state = SignState()
        self._loaded_keymapper: Keymapper | None = None
        self.assume_yes = environment.get("SIGN_ASSUME_YES") == "y"
        self.original_tmpdir = Path(environment.get("TMPDIR") or "/dev/shm")
        self.tmpdir: Path | None = None
        self.inherited_environment = dict(environment)

    def try_(self, description: str, step: Callable[[], T]) -> T:
        """
        Run step(), retrying on failure until it succeeds or the user
        declines to retry. SIGN_ASSUME_YES=y fails fast instead of
        retrying, so a persistent failure surfaces rather than looping
        forever.

        Args:
            description: Text identifying the step, for the retry prompt.
            step: A zero-argument callable raising SignStepError on
                failure.

        Returns:
            What step() returns.

        Raises:
            Abort: If the step fails and is not retried.
        """
        while True:
            try:
                return step()
            except SignStepError as error:
                if self.assume_yes:
                    print(
                        f"{description} failed (code {error.code}). "
                        "SIGN_ASSUME_YES=y is set, not retrying.",
                        file=sys.stderr,
                    )
                    raise Abort(error.code) from error
                if not confirm(
                    f"{description} failed (code {error.code}). Try again?",
                    assume_yes=False,
                ):
                    print(
                        f"{description} failed (code {error.code}). "
                        "Giving up...",
                        file=sys.stderr,
                    )
                    raise Abort(error.code) from error

    def run(self) -> int:
        """
        Run every step in order, then clean up.

        Returns:
            0 on success, or the exit code of the step that aborted.
        """
        try:
            with defer_signals():
                try:
                    with exit_on_signals():
                        try:
                            self._run_steps()
                        except Abort as abort:
                            return abort.code
                        except SignDone:
                            return 0
                        except KeyboardInterrupt:
                            return 130
                finally:
                    with defer_signals(interrupt=True):
                        self.cleanup()
        except KeyboardInterrupt:
            return 130
        return 0

    def _run_steps(self) -> None:
        self._find_target_files()
        self.try_("setup_log_dir", self._setup_log_dir)
        self.try_(
            "gather_signable_devices_from_metadata",
            self._gather_signable_devices_from_metadata,
        )
        self._gather_latest_device_builds()
        self.try_("prompt_missing_variables", self._prompt_missing_variables)
        self._gather_device_builds_to_sign()
        self._find_prev_signed_device_builds()
        self.try_(
            "maybe_ask_about_prev_signed_device_builds",
            self._maybe_ask_about_prev_signed_device_builds,
        )
        self.try_(
            "load_keymapper_and_maybe_pkcs11",
            self._load_keymapper_and_maybe_pkcs11,
        )
        self.try_(
            "maybe_handle_already_existing_builds",
            self._maybe_handle_already_existing_builds,
        )
        self.try_(
            "maybe_ask_about_missing_target_files",
            self._maybe_ask_about_missing_target_files,
        )
        self.try_("check_free_space", self.check_free_space)
        self.try_("initialize", self.initialize)
        plan = self.try_(
            "sort_and_separate_devices_by_key_availability",
            self._sort_and_separate_devices_by_key_availability,
        )
        self.try_("final_confirmation", lambda: self._final_confirmation(plan))

        for _, _, run in self._steps(plan):
            run()

        self._finish()

    def _find_target_files(self) -> None:
        self.state.target_files = sorted(
            entry.name
            for entry in self.cwd.iterdir()
            if entry.is_file()
            and not entry.is_symlink()
            and fnmatch.fnmatch(entry.name, "calyx_*-target_files-*.zip")
        )

    def _archive_dirs(self) -> list[str]:
        archive = self.cwd / "archive"
        if not archive.is_dir():
            return []
        return sorted(
            entry.name
            for entry in archive.iterdir()
            if entry.is_dir()
            and not entry.is_symlink()
            and entry.name.startswith("release-")
        )

    def _find_prev_signed_device_builds(self) -> None:
        archive_dirs = self._archive_dirs()
        build_numbers = parse_build_numbers(
            self.environment.get("BUILD_NUMBER", ""),
        )
        prev_build_number = self.environment.get("PREV_BUILD_NUMBER", "")
        prev_build_numbers = (
            parse_build_numbers(prev_build_number)
            if prev_build_number
            else None
        )
        rollback = bool(self.environment.get("AVB_ROLLBACK_INDEX_OVERRIDE"))

        def target_files_exists(
            archive_dir: str,
            device: str,
            build: int,
        ) -> bool:
            return (
                self.cwd
                / "archive"
                / archive_dir
                / f"{device}-target_files-{build}.zip"
            ).is_file()

        result = find_prev_signed_device_builds(
            archive_dirs,
            device_to_next_build=self.state.device_to_next_build,
            build_numbers=build_numbers,
            prev_build_numbers=prev_build_numbers,
            avb_rollback_index_override=rollback,
            target_files_exists=target_files_exists,
        )
        self.state.device_to_prev_build = dict(result.device_to_prev_build)
        self.state.device_to_preexisting_build = dict(
            result.device_to_preexisting_build,
        )

    def _setup_log_dir(self) -> None:
        if not self.environment.get("PKCS11_VENDOR"):
            return
        logs_dir = self.cwd / "logs"
        if not sign_environment.is_audit_log_repository(logs_dir):
            raise _reported_step_error(
                f"YUBIHSM_LOGS_DIR ({logs_dir}) is not the expected git "
                "repository.\n"
                "Are you sure you are calling this script from the right "
                "place?\n"
                "Did you clone the audit log git repository already?",
            )
        self.environment["YUBIHSM_LOGS_DIR"] = str(logs_dir)

    def _gather_signable_devices_from_metadata(self) -> None:
        try:
            devices = load_devices_file(self.devices_file)
        except subprocess.CalledProcessError as error:
            sys.stderr.write(error.stderr.decode(errors="replace"))
            raise SignStepError(f"cannot source {self.devices_file}") from error
        self.state.signable_devices = gather_signable_devices(
            devices,
            self.metadata.all_devices,
        )

    def _gather_latest_device_builds(self) -> None:
        self.state.device_to_next_build = gather_device_builds(
            self.state.target_files,
        )

    def _deduce_build_number(self) -> str:
        return _join_builds(self.state.device_to_next_build)

    def _deduce_prev_build_number(self) -> str:
        self._gather_device_builds_to_sign()
        self._find_prev_signed_device_builds()
        return _join_builds(self.state.device_to_prev_build)

    def _prompt_missing_variables(self) -> None:
        try:
            self._ask_missing_variables()
        except RuntimeError as error:
            raise _reported_step_error(str(error)) from error
        for name in ("NUM_SIGN_JOBS", "NUM_INCREMENTAL_JOBS"):
            value = self.environment[name]
            if not value.isdigit() or int(value) < 1:
                raise _reported_step_error(
                    f"{name} must be a positive number, not {value!r}",
                )

    def _ask_missing_variables(self) -> None:
        ask_variable(
            "PKCS11_VENDOR",
            self.environment,
            default="",
            needs_value=False,
        )
        deduced = self._deduce_build_number()
        ask_variable(
            "BUILD_NUMBER",
            self.environment,
            default=deduced,
            needs_value=True,
        )
        rollback = self.environment.get("AVB_ROLLBACK_INDEX_OVERRIDE")
        if rollback:
            self.state.no_incremental = True
            first = self.environment["BUILD_NUMBER"].split()[0]
            if not is_build_number(first):
                raise _reported_step_error(
                    f"BUILD_NUMBER {first} is not a number",
                )
            build = int(first)
            print(
                "Build number overriden to "
                f"{build + 1} for AVB Rollback Index override build",
            )
        else:
            deduced_prev = self._deduce_prev_build_number()
            ask_variable(
                "PREV_BUILD_NUMBER",
                self.environment,
                default=deduced_prev,
                needs_value=False,
            )
            if not self.environment.get("PREV_BUILD_NUMBER"):
                self.state.no_incremental = True
        ask_variable(
            "NUM_SIGN_JOBS",
            self.environment,
            default="3",
            needs_value=True,
        )
        ask_variable(
            "NUM_INCREMENTAL_JOBS",
            self.environment,
            default="3",
            needs_value=True,
        )

    def _gather_device_builds_to_sign(self) -> None:
        build_numbers = parse_build_numbers(self.environment["BUILD_NUMBER"])
        self.state.device_to_next_build = gather_device_builds(
            self.state.target_files,
            build_numbers,
        )

    def _maybe_ask_about_prev_signed_device_builds(self) -> None:
        if self.state.no_incremental:
            return
        if not (self.cwd / "archive").is_dir():
            print()
            print("Could not find an archive/ directory.")
            print(
                "If you proceed, we will create it, but we will not be "
                "able to generate incrementals.",
            )
            print(
                "If this is a mistake, please ensure you are running this "
                "script from the proper",
            )
            print("directory, which should contain an archive/ subdirectory.")
            print()
            if not confirm(
                "WARNING: Create archive/ and continue without incrementals?",
                assume_yes=self.assume_yes,
            ):
                raise SignStepError("declined to create archive/")
            self.state.no_incremental = True
            (self.cwd / "archive").mkdir()
            return

        print()
        print("Found the following previous builds:")
        any_found = False
        for build in sorted(set(self.state.device_to_prev_build.values())):
            if str(build) == self.environment["BUILD_NUMBER"]:
                continue
            any_found = True
            prev_builds = self.state.device_to_prev_build
            devices = ",".join(
                device
                for device, prev_build in prev_builds.items()
                if prev_build == build
            )
            print(f"  {build}: {devices}")
        if not any_found:
            print("  None.")
            print()
            if not confirm(
                "WARNING: Proceed without generating any incremental builds?",
                assume_yes=self.assume_yes,
            ):
                raise SignStepError("declined to proceed without incrementals")
            self.state.no_incremental = True
            return

        missing_prior_builds = sorted(
            device
            for device in self.state.device_to_next_build
            if device not in self.state.device_to_prev_build
        )
        if missing_prior_builds:
            print()
            print(
                f"Found no prior builds for {len(missing_prior_builds)} "
                "devices we plan to sign:",
            )
            print(f"  {' '.join(missing_prior_builds)}")
            print()
            if not confirm(
                "WARNING: Continue without incremental builds for these "
                "devices?",
                assume_yes=self.assume_yes,
            ):
                raise SignStepError(
                    "declined to continue without incrementals for "
                    "some devices",
                )

    def _load_keymapper_and_maybe_pkcs11(self) -> None:
        try:
            sign_environment.load_vendor(self.environment)
        except RuntimeError as error:
            raise _reported_step_error(str(error)) from error
        try:
            self.keymapper()
        except (ValueError, OSError) as error:
            raise _reported_step_error(str(error)) from error

    def _maybe_handle_already_existing_builds(self) -> None:
        build_numbers = parse_build_numbers(self.environment["BUILD_NUMBER"])
        any_already_signed = any(
            build in self.state.device_to_preexisting_build.values()
            for build in build_numbers
        )
        if any_already_signed:
            print()
            print(
                "The following devices appear to already be signed (in "
                "archive/):",
            )
            for build in build_numbers:
                devices = ",".join(
                    device
                    for device, preexisting in (
                        self.state.device_to_preexisting_build.items()
                    )
                    if preexisting == build
                )
                if devices:
                    print(f" {build}: {devices}")
            print()
            print(
                "If you continue, these device/build pairs will not be "
                "signed again.",
            )
            print(
                "(If you want them to be signed again, remove them from "
                "archive/ first.)",
            )
            print()
            if not confirm("Continue?", assume_yes=self.assume_yes):
                raise SignStepError(
                    "declined to continue past preexisting builds",
                )

        if not self.state.device_to_next_build:
            print()
            print("There is nothing left to sign.")
            if not self.state.no_incremental:
                if not confirm(
                    "Continue anyway for incremental build generation?",
                    assume_yes=self.assume_yes,
                ):
                    raise SignStepError(
                        "declined to continue with nothing to sign",
                    )
            else:
                print(
                    "There are also no incremental builds to generate, so "
                    "there is nothing to do.",
                )
                print("Bye!")
                raise SignDone()

    def _maybe_ask_about_missing_target_files(self) -> None:
        missing = sorted(
            set(self.state.signable_devices)
            - set(self.state.device_to_next_build),
        )
        if missing:
            print()
            print(
                f"Out of {len(self.state.signable_devices)} signable "
                f"devices, only found {len(self.state.device_to_next_build)}"
                " target files to sign:",
            )
            print(f"  {' '.join(sorted(self.state.device_to_next_build))}")
            print(
                "These target files are missing for the selected build "
                "number(s):",
            )
            print(f"  {' '.join(missing)}")
            print()
            if not confirm("Continue?", assume_yes=self.assume_yes):
                raise SignStepError(
                    "declined to continue past missing target files",
                )

    def check_free_space(self) -> None:
        print()
        devices = len(self.state.device_to_next_build)
        estimated_required = 20 * devices
        try:
            completed = subprocess.run(
                ["df", "--output=avail", "-B1", str(self.cwd)],
                check=True,
                capture_output=True,
                text=True,
            )
            available_bytes = int(completed.stdout.splitlines()[-1].strip())
        except subprocess.CalledProcessError as error:
            sys.stderr.write(error.stderr or "")
            raise _reported_step_error("df failed") from error
        except (OSError, ValueError, IndexError) as error:
            raise _reported_step_error(
                f"Could not read the free space ({error})",
            ) from error
        available = available_bytes >> 30
        subprocess.run(["df", "-h", str(self.cwd)], check=False)
        print()
        if available_bytes < estimated_required << 30:
            print(
                f"ERROR: Only {available}GB free, but an estimated "
                f"{estimated_required}GB is needed "
                f"(20GB x {devices} device(s)).",
                file=sys.stderr,
            )
            raise SignStepError("insufficient free space")
        print(
            f"Free space check passed, {available}GB available, "
            f"{estimated_required}GB estimated required.",
        )

    def initialize(self) -> None:
        if self.tmpdir is None:
            self.tmpdir = Path(
                tempfile.mkdtemp(
                    prefix="signing_tmp.",
                    dir=str(self.original_tmpdir),
                ),
            )
        self.environment["TMPDIR"] = str(self.tmpdir)
        print()
        if not self.environment.get("PKCS11_VENDOR"):
            print("Initializing...")
        else:
            print("Initializing PKCS#11 and related components...")
            try:
                sign_environment.maybe_initialize_vendor_interactive(
                    self.environment,
                    assume_yes=self.assume_yes,
                )
                sign_environment.maybe_initialize_vendor(
                    self.environment,
                    tmpdir=self.tmpdir,
                )
            except (RuntimeError, OSError) as error:
                raise _reported_step_error(str(error)) from error
        (self.cwd / "archive").mkdir(exist_ok=True)

    def _sort_and_separate_devices_by_key_availability(self) -> SigningPlan:
        ordered = [
            device
            for device in self.metadata.all_devices
            if device in self.state.device_to_next_build
        ]
        vendor = sign_environment.load_vendor(self.environment)
        if vendor is not None:
            try:
                with_loaded, without_loaded = (
                    vendor.split_devices_by_loaded_keys(
                        self.environment,
                        self.keymapper(),
                        ordered,
                    )
                )
            except Exception as error:
                print(error, file=sys.stderr)
                raise _reported_step_error(
                    "Could not determine which devices have keys loaded.",
                ) from error
        else:
            with_loaded, without_loaded = tuple(ordered), ()
        rollback = bool(self.environment.get("AVB_ROLLBACK_INDEX_OVERRIDE"))
        plan = partition_by_key_availability(
            with_loaded,
            without_loaded,
            device_to_next_build=self.state.device_to_next_build,
            device_to_prev_build=(
                {}
                if self.state.no_incremental
                else self.state.device_to_prev_build
            ),
            device_to_preexisting_build=self.state.device_to_preexisting_build,
            avb_rollback_index_override=rollback,
        )
        work = [
            *(pair.device for pair in plan.sign_pairs_without_loaded_keys),
            *(
                triple.device
                for triple in plan.incremental_triples_without_loaded_keys
            ),
        ]
        self.state.devices_without_loaded_keys = tuple(
            device for device in without_loaded if device in work
        )
        return plan

    def _steps(
        self,
        plan: SigningPlan,
    ) -> list[tuple[str, list[str], Callable[[], None]]]:
        """
        List the steps of plan that have work, in the order they run.

        Args:
            plan: The signing plan.

        Returns:
            For each step, the description and the items that the plan
            shows, and a callable that runs the step and then uploads
            the audit logs.
        """

        def sign(
            pairs: Sequence[SignPair],
        ) -> tuple[str, list[str], Callable[[], None]]:
            def run() -> None:
                self._sign_builds(pairs)
                self._upload_logs_best_effort()

            return (
                "sign release for",
                [pair.tag for pair in pairs],
                run,
            )

        def generate(
            triples: Sequence[IncrementalTriple],
        ) -> tuple[str, list[str], Callable[[], None]]:
            def run() -> None:
                self._generate_incrementals(triples)
                self._upload_logs_best_effort()

            return (
                "generate incremental updates for",
                [triple.tag for triple in triples],
                run,
            )

        steps = [
            sign(plan.sign_pairs_with_loaded_keys),
            generate(plan.incremental_triples_with_loaded_keys),
            (
                "ensure keys available for devices",
                list(self.state.devices_without_loaded_keys),
                self._ensure_keys,
            ),
            sign(plan.sign_pairs_without_loaded_keys),
            generate(plan.incremental_triples_without_loaded_keys),
        ]
        return [step for step in steps if step[1]]

    def _render_plan(self, plan: SigningPlan) -> None:
        for description, items, _ in self._steps(plan):
            print(f"Would {description}: " + " ".join(items))

    def _final_confirmation(self, plan: SigningPlan) -> None:
        print()
        print("Here's the plan:")
        self._render_plan(plan)
        print()
        if self.dry_run:
            raise SignDone()
        if not confirm("Ready?", assume_yes=self.assume_yes):
            raise SignStepError("declined final confirmation")

    def _upload_logs(self) -> None:
        """
        Upload new audit logs with the log repository's upload.py, unless
        DRY_RUN=y.

        Raises:
            SignStepError: If the upload fails.
        """
        if self.dry_run:
            return
        if self.environment.get("SKIP_LOG_UPLOAD") == "true":
            return
        if not self.environment.get("PKCS11_VENDOR"):
            return
        logs_dir = self.environment.get("YUBIHSM_LOGS_DIR")
        if not logs_dir:
            return
        try:
            completed = subprocess.run(
                [str(Path(logs_dir) / "upload.py"), "--upload-all-new"],
                check=False,
                env=dict(self.environment),
            )
        except OSError as error:
            print(error, file=sys.stderr)
            raise SignStepError("upload_logs failed", code=126) from error
        if completed.returncode != 0:
            raise SignStepError("upload_logs failed", code=completed.returncode)

    def _upload_logs_best_effort(self) -> None:
        """Upload logs once, silently ignoring any failure."""
        try:
            self._upload_logs()
        except SignStepError:
            pass

    def _upload_logs_retry_best_effort(self) -> None:
        """
        Upload new audit logs, offering a retry on failure, and go on
        when the user declines one.
        """
        try:
            self.try_("upload_logs", self._upload_logs)
        except Abort:
            pass

    def _ensure_keys(self) -> None:
        self.try_(
            "ensure_all_keys_available_for_devices",
            self._ensure_all_keys_available_for_devices,
        )
        self._upload_logs_retry_best_effort()

    @property
    def dry_run(self) -> bool:
        return self.environment.get("DRY_RUN") == "y"

    def _sign_builds(self, pairs: Sequence[SignPair]) -> None:
        code = _run_sign_builds(
            pairs,
            release_script=self.release_script,
            archive_dir=self.cwd / "archive",
            jobs=int(self.environment["NUM_SIGN_JOBS"]),
            original_tmpdir=self.original_tmpdir,
            environment=self.environment,
        )
        if code != 0:
            raise Abort(code)

    def _generate_incrementals(
        self,
        triples: Sequence[IncrementalTriple],
    ) -> None:
        code = _run_generate_incrementals(
            triples,
            generate_delta_script=self.generate_delta_script,
            jobs=int(self.environment["NUM_INCREMENTAL_JOBS"]),
            original_tmpdir=self.original_tmpdir,
            environment=self.environment,
        )
        if code != 0:
            raise Abort(code)

    def keymapper(self) -> Keymapper:
        """Load the keymapper once and apply its exports."""
        if self._loaded_keymapper is None:
            keymapper = load_keymapper(self.environment, self.metadata)
            apply_keymapper_exports(self.environment, keymapper)
            self._loaded_keymapper = keymapper
        return self._loaded_keymapper

    def _ensure_all_keys_available_for_devices(self) -> None:
        try:
            vendor = sign_environment.load_vendor(self.environment)
            assert vendor is not None
            vendor.ensure_keys_for_devices(
                self.environment,
                self.keymapper(),
                self.state.devices_without_loaded_keys,
            )
        except Exception as error:
            raise _reported_step_error(str(error)) from error

    def _finish(self) -> None:
        print()
        print(
            "Done signing and/or generating incrementals for: "
            f"{self.environment.get('BUILD_NUMBER', '')}",
        )

    def cleanup(self) -> None:
        try:
            vendor = sign_environment.load_vendor(self.environment)
        except RuntimeError:
            vendor = None
        if vendor is not None:
            vendor.cleanup(
                self.environment,
                inherited=self.inherited_environment,
            )
        self._upload_logs_best_effort()
        if self.tmpdir is not None:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
