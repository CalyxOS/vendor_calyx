#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
The YubiHSM provisioning wizard behind vendor.yubihsm.provision.sh.
"""

from __future__ import annotations

import base64
import getpass
import subprocess
import sys
from collections.abc import Callable, MutableMapping, Sequence
from pathlib import Path

from . import sign_environment
from .confirmation import confirm
from .files import write_file_atomically
from .keymap import Keymapper, apply_keymapper_exports, load_keymapper
from .metadata import default_metadata_path, load_metadata
from .release_execution import render_release_tool
from .vendor_yubihsm import (
    YubiHsmConfig,
    export_wrapped_key,
    extract_and_save_audit_log,
    get_device_identity,
    list_restorable_objects,
    restore_all_keys_and_certs,
)

SCRIPTS_DIR = Path(__file__).resolve().parents[1]

_START = ("load_configuration", "maybe_start_yubihsm_connector_service")
_END = ("finish",)
_MODES = {
    "keygen": (
        *_START,
        "ask_signing_authkey_password_if_needed",
        "use_signing_authkey",
        "connect_hsm",
        "keygen",
        "check_exports",
        *_END,
    ),
    "backup": (
        *_START,
        "ask_signing_authkey_password_if_needed",
        "use_signing_authkey",
        "connect_hsm",
        "backup_primary",
        "check_exports",
        *_END,
    ),
    "load-keys": (
        "load_configuration",
        "ask_signing_authkey_password_if_needed",
        "use_signing_authkey",
        "maybe_start_yubihsm_connector_service",
        "connect_hsm",
        "load_keys",
        *_END,
    ),
}


class StepFailed(Exception):
    """A wizard step failed with an exit status."""

    def __init__(self, code: int = 1) -> None:
        super().__init__(code)
        self.code = code


def _read_secret(prompt: str) -> str:
    """
    Prompt for a secret, without echo on a terminal, and print a newline
    after reading it from anything else.

    Args:
        prompt: Text to prompt with.

    Returns:
        The line read, without its newline.
    """
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    print()
    return line.removesuffix("\n")


class ProvisionWizard:
    """The provisioning wizard."""

    def __init__(
        self,
        environment: MutableMapping[str, str],
        *,
        cwd: Path,
    ) -> None:
        self.environment = environment
        self.cwd = cwd
        environment["NEVER_START_YUBIHSM_CONNECTOR"] = "y"
        for name, default in (
            ("YUBIHSM_AUTHKEY", "1"),
            ("YUBIHSM_PASSWORD", "password"),
        ):
            if not environment.get(name):
                environment[name] = default
        self.is_provisioning_mode = False
        self.keymapper: Keymapper | None = None
        self.signing_authkey_id = ""
        self.signing_authkey_password = environment.get(
            "YUBIHSM_SIGNING_AUTHKEY_PASSWORD",
            "",
        )
        self.audit_log_path: Path | None = None
        self.keep_path = environment.get("KEEP_PATH", "")
        self.basepath = Path(
            environment.get("SOURCE_DIRECTORY") or SCRIPTS_DIR.parents[2],
        )

    def run(self, arguments: Sequence[str]) -> int:
        """
        Run the stages of the mode the arguments name, then clean up.

        Args:
            arguments: The wizard's arguments, its mode first.

        Returns:
            0 once every stage succeeds, 1 for an unknown mode, or the
            status of the stage that failed.
        """
        try:
            steps = self._set_mode(arguments[0] if arguments else "")
            if steps is None:
                return 1
            for step in steps:
                print(f"Now performing: {step}")
                code = self.try_(step, getattr(self, f"_{step}"))
                if code:
                    return code
            return 0
        finally:
            self._cleanup()

    def try_(self, name: str, step: Callable[[], None]) -> int:
        """
        Run a stage until it succeeds or the operator stops retrying it,
        giving up at once under SIGN_ASSUME_YES=y.

        Args:
            name: The stage's name in the retry question.
            step: The stage.

        Returns:
            0 once the stage succeeds, or the status it last failed with.
        """
        while True:
            try:
                step()
                return 0
            except StepFailed as failure:
                code = failure.code
            except Exception as error:
                print(f"error: {error}", file=sys.stderr)
                code = 1
            if self.environment.get("SIGN_ASSUME_YES") == "y":
                print(
                    f"{name} failed (code {code}). SIGN_ASSUME_YES=y is set, "
                    "not retrying.",
                    file=sys.stderr,
                )
                return code
            if not confirm(
                f"{name} failed (code {code}). Try again?",
                assume_yes=False,
            ):
                print(
                    f"{name} failed (code {code}). Giving up...",
                    file=sys.stderr,
                )
                return code

    def _set_mode(self, mode: str) -> tuple[str, ...] | None:
        if mode not in _MODES:
            print(f"Unrecognized mode: {mode}", file=sys.stderr)
            return None
        default_key_dir = f"{self.cwd}/keys"
        if mode == "backup":
            self.is_provisioning_mode = True
            self.keep_path = self.keep_path or "/dev/shm/keep"
            default_key_dir = f"{self.keep_path}/keys"
        elif mode == "keygen":
            self.is_provisioning_mode = True
            self.keep_path = self.keep_path or str(self.cwd)
        if not self.environment.get("KEY_DIR"):
            self.environment["KEY_DIR"] = default_key_dir
        print(f"Mode: {mode}")
        return _MODES[mode]

    @property
    def key_dir(self) -> str:
        """Directory holding the wizard's key backups."""
        return self.environment["KEY_DIR"]

    def _config(self) -> YubiHsmConfig:
        return sign_environment.yubihsm_config_from_environment(
            self.environment,
        )

    def _load_configuration(self) -> None:
        environment = self.environment
        metadata = load_metadata(default_metadata_path())
        sign_environment.YubiHsmVendor().apply_source_exports(environment)
        self.signing_authkey_id = (
            environment.get("YUBIHSM_SIGNING_AUTHKEY_ID") or "0x0001"
        )

        def load() -> None:
            try:
                self.keymapper = load_keymapper(environment, metadata)
            except ValueError as error:
                print(error, file=sys.stderr)
                raise StepFailed(1) from error
            apply_keymapper_exports(environment, self.keymapper)

        code = self.try_("load_keymapper", load)
        if code:
            raise StepFailed(code)

    def _maybe_start_yubihsm_connector_service(self) -> None:
        print()
        print(
            "This step uses administrator privileges via sudo to start the "
            "YubiHSM connector.",
        )
        print("You may be required to enter your administrator password.")
        if not confirm(
            "Would you like to start the yubihsm connector?",
            assume_yes=self.environment.get("SIGN_ASSUME_YES") == "y",
        ):
            return
        sys.stdout.flush()
        code = subprocess.run(
            ["sudo", "systemctl", "start", "yubihsm-connector"],
        ).returncode
        if code:
            raise StepFailed(code)

    def _ask_signing_authkey_password_if_needed(self) -> None:
        if self.signing_authkey_password:
            return
        self.signing_authkey_password = _read_secret(
            "Enter signing authkey password: ",
        )

    def _use_signing_authkey(self) -> None:
        self.environment["YUBIHSM_AUTHKEY"] = self.signing_authkey_id
        self.environment["YUBIHSM_PASSWORD"] = self.signing_authkey_password

    def _connect_hsm(self) -> None:
        print()
        print("Please connect the YubiHSM 2.")
        if not confirm(
            "Enter Y when the HSM is connected, or N to quit.",
            assume_yes=self.environment.get("SIGN_ASSUME_YES") == "y",
        ):
            raise StepFailed(1)
        identity = get_device_identity(self._config())
        name = identity.name
        logs_dir = Path(f"{self.keep_path or self.cwd}/logs")
        self.environment["YUBIHSM_LOGS_DIR"] = str(logs_dir)
        (logs_dir / name).mkdir(parents=True, exist_ok=True)
        self.audit_log_path = (
            logs_dir
            / name
            / f"{sign_environment.formatted_date()}-provision.log"
        )
        self.environment["AUDIT_LOG_PATH"] = str(self.audit_log_path)

    def _keygen(self) -> None:
        Path(self.key_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        sys.stdout.flush()
        code = subprocess.run(
            [
                str(SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.keygen.sh"),
                self.key_dir,
            ],
            cwd=self.basepath,
            env=self.environment,
        ).returncode
        if code:
            raise StepFailed(code)

    def _extract_logs(self, comment: str) -> None:
        config = self._config()
        assert self.audit_log_path is not None
        extract_and_save_audit_log(
            config,
            self.audit_log_path,
            comment,
        )

    def export_wrapped_key(self, key_id: str) -> None:
        """
        Export a key wrapped into its backup file under key_dir, and record
        the export in the audit log, or under DRY_RUN=y print the command
        line instead.

        Args:
            key_id: The key's ID, e.g. "0x2000".

        Raises:
            StepFailed: If the export or, unless NO_LOG_FAIL=y, the audit
                log extraction fails.
        """
        environment = self.environment
        output = f"{self.key_dir}/{key_id}-asymmetric-key.yhw"
        command = [
            "export-wrapped-key",
            "--connector",
            environment["YUBIHSM_CONNECTOR"],
            "--authkey",
            environment["YUBIHSM_AUTHKEY"],
            "--wrap-id",
            environment["YUBIHSM_WRAP_KEY_ID"],
            "--key-id",
            key_id,
            "--output",
            output,
        ]
        if environment.get("DRY_RUN") == "y":
            print(
                render_release_tool(["python3", "-m", "signing", *command]),
                end="",
                file=sys.stderr,
            )
            return
        error: BaseException | None = None
        try:
            wrapped = export_wrapped_key(self._config(), key_id)
            write_file_atomically(
                Path(output),
                base64.b64encode(wrapped),
            )
        except Exception as caught:
            print(f"error: {caught}", file=sys.stderr)
            error = caught
        try:
            self._extract_logs(
                f"Operation: {' '.join(command)} "
                f"Result: {0 if error is None else 1}",
            )
        except Exception as log_error:
            print("Failed to extract logs", file=sys.stderr)
            if environment.get("NO_LOG_FAIL") == "y":
                if error is not None:
                    raise StepFailed(1) from error
                return
            raise StepFailed(1) from log_error
        if error is not None:
            raise StepFailed(1) from error

    def _backup_primary(self) -> None:
        from yubihsm.defs import OBJECT

        Path(self.key_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        keys = [
            obj
            for obj in list_restorable_objects(self._config(), None)
            if obj.object_type == OBJECT.ASYMMETRIC_KEY
        ]
        for key in keys:
            self.export_wrapped_key(f"0x{key.id:04x}")

    def _check_exports(self) -> None:
        if not any(Path(self.key_dir).glob("*.yhw")):
            print(
                "No exported keys found! Did they all fail to export?",
                file=sys.stderr,
            )
            raise StepFailed(1)

    def _load_keys(self) -> None:
        print()
        print("Restoring all keys and certs...")
        environment = self.environment
        assert self.keymapper is not None
        assert self.audit_log_path is not None
        keymapper = self.keymapper
        log_file = self.audit_log_path

        def restore() -> None:
            if environment.get("DRY_RUN") == "y":
                print(
                    render_release_tool(["restore_all_keys_and_certs"]),
                    end="",
                    file=sys.stderr,
                )
                return
            restore_all_keys_and_certs(
                self._config(),
                Path(self.key_dir),
                log_file,
                is_ondemand=sign_environment.key_id_is_ondemand(keymapper),
                exportable_domain=environment["YUBIHSM_EXPORTABLE_DOMAIN"],
                ondemand_domain=environment["YUBIHSM_ONDEMAND_DOMAIN"],
                opaque_capabilities=environment["YUBIHSM_OPAQUE_CAPABILITIES"],
            )

        code = self.try_("restore_all_keys_and_certs", restore)
        if code:
            raise StepFailed(code)

    def _finish(self) -> None:
        if self.is_provisioning_mode:
            print("Provisioning completed successfully!")
            print("Do not forget to save the contents of:")
            print(self.keep_path)
        else:
            print("Done!")

    def _cleanup(self) -> None:
        if self.keep_path and Path(self.keep_path).is_dir():
            print(
                f"IMPORTANT: You must save the contents of '{self.keep_path}'! "
                "Copy it somewhere safe!",
                file=sys.stderr,
            )


def provision_main(
    environment: MutableMapping[str, str],
    arguments: Sequence[str],
) -> int:
    """
    Run the provisioning wizard in the mode arguments[0] names.

    Args:
        environment: Process environment, mutated in place.
        arguments: The provisioning script's arguments.

    Returns:
        The wizard's exit status.
    """
    return ProvisionWizard(environment, cwd=Path.cwd()).run(arguments)
