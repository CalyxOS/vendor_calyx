#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Sign one app with its key on the YubiHSM, for sign-app.sh.
"""

from __future__ import annotations

import sys
from collections.abc import MutableMapping, Sequence
from pathlib import Path
from typing import TextIO

from . import sign_environment
from .keymap import StaticKeymapper
from .metadata import SigningMetadata
from .release_execution import defer_signals, exit_on_signals, run_release_tool
from .release_orchestration import generate_sunpkcs11_config
from .vendor_yubihsm import get_device_identity

_SCRIPTS_DIR = Path(__file__).resolve().parents[1]


def _strip_extension(path: str) -> str:
    """Drop the shortest suffix starting with a dot."""
    dot = path.rfind(".")
    return path[:dot] if dot >= 0 else path


def sign_app(
    environment: MutableMapping[str, str],
    metadata: SigningMetadata,
    arguments: Sequence[str],
    *,
    program: str = "sign-app.sh",
) -> int:
    """
    Sign an app APK through the signing command interceptor, as
    sign-app.sh does, through apksigner's external KMS provider when
    PKCS11_PYTHON_INTERCEPTOR=y and USE_APKSIGNER_KMS=y, and through a
    SunPKCS11 KeyStore otherwise.

    Args:
        environment: Process environment, mutated in place. The signing
            command inherits it, so the caller passes os.environ.
        metadata: Validated signing metadata, whose app keys name the apps
            that can be signed.
        arguments: The app and the APK.
        program: The script path the usage line names.

    Returns:
        The signing command's exit status, or 1 for a usage error.
    """
    sign_environment.ask_yubihsm_credentials(environment)
    apps = metadata.keys_for_type("app")

    def error(message: str, usage: TextIO = sys.stdout) -> int:
        print(f"error: {message}, please try again", file=sys.stderr)
        print(f"Usage: {program} <app> file.apk", file=usage)
        print(f"Supported apps: {' '.join(apps)}", file=usage)
        return 1

    if len(arguments) != 2:
        return error("incorrect number of arguments")
    app, apk = arguments
    if not Path(apk).is_file():
        return error(
            f"{apk} is not an existing regular file or does not exist.",
            sys.stderr,
        )
    if app not in apps:
        return error(f"Unsupported app {app}")

    main_path = _SCRIPTS_DIR.parents[2]
    key_dir = environment.get("KEY_DIR") or f"{main_path}/keys"
    key_dir = f"{key_dir.removesuffix('/')}/"
    environment["KEY_DIR"] = key_dir
    environment["PKCS11_VENDOR"] = "yubihsm"
    vendor = sign_environment.YubiHsmVendor()
    sign_environment.load_vendor(environment)
    key_id = StaticKeymapper.from_file(
        Path(environment["KEYMAP_FILE"]),
    ).key_id("app", app)

    tmpdir = Path(environment.get("TMPDIR") or "/tmp")
    sun_config_path = tmpdir / "sunpkcs11.cfg"
    sun_config_path.write_text(generate_sunpkcs11_config(environment))

    environment["NEVER_START_APKSIGNER_BATCH"] = "y"
    inherited = dict(environment)
    with exit_on_signals():
        try:
            vendor.initialize(
                environment,
                tmpdir=Path(environment.get("TMPDIR") or "/dev/shm"),
            )
            from yubihsm.exceptions import YubiHsmError

            try:
                identity = get_device_identity(
                    sign_environment.yubihsm_config_from_environment(
                        environment,
                    ),
                )
            except YubiHsmError as failure:
                raise RuntimeError(f"YubiHSM failure: {failure}") from failure
            name = identity.name
            environment["AUDIT_LOG_PATH"] = (
                f"{environment['YUBIHSM_LOGS_DIR']}/{name}/"
                f"{sign_environment.formatted_date()}-{app}.log"
            )
            environment["SIGNING_COMMAND"] = "java"
            interceptor = environment["SIGNING_COMMAND_INTERCEPTOR"]
            output = f"{_strip_extension(apk)}-signed.apk"
            if (
                environment.get("PKCS11_PYTHON_INTERCEPTOR") == "y"
                and environment.get("USE_APKSIGNER_KMS") == "y"
            ):
                certificate = f"{key_dir}{key_id}.x509.pem"
                if not Path(certificate).is_file():
                    return error(
                        f"no certificate file found at {certificate} "
                        f"for key {key_id}",
                    )
                environment["APKSIGNER_EXTERNAL_SIGNER"] = str(
                    _SCRIPTS_DIR / "pkcs11/apksigner_signing_helper.py",
                )
                argv = [
                    interceptor,
                    "-jar",
                    f"{main_path}/framework/apksigner.jar",
                    "sign",
                    "--v4-signing-enabled=false",
                    "--min-sdk-version",
                    "30",
                    "--kms-type",
                    "external",
                    "--kms-key-alias",
                    key_id,
                    "--cert",
                    certificate,
                    "--out",
                    output,
                    apk,
                ]
            else:
                argv = [
                    interceptor,
                    "-Xmx4096m",
                    "--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
                    f"-Djava.library.path={main_path}/lib64",
                    "-jar",
                    f"{main_path}/framework/apksigner.jar",
                    "sign",
                    "--v4-signing-enabled=false",
                    "--min-sdk-version",
                    "30",
                    "--ks",
                    "NONE",
                    "--ks-type",
                    "PKCS11",
                    "--ks-pass",
                    "env:PKCS11_PIN",
                    "--provider-class",
                    "sun.security.pkcs11.SunPKCS11",
                    "--provider-arg",
                    str(sun_config_path),
                    "--ks-key-alias",
                    key_id,
                    "--out",
                    output,
                    apk,
                ]
            with defer_signals():
                code = run_release_tool(argv)
            if code == 0:
                print(f"Signed {apk} successfully")
            return code
        finally:
            vendor.cleanup(environment, inherited=inherited)
