#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
The plaintext key scripts and their command-line front ends.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, MutableMapping, Sequence
from pathlib import Path

from .keymap import Keymapper, apply_keymapper_exports, load_keymapper
from .metadata import SigningMetadata, default_metadata_path, load_metadata
from .plaintext import generate_certified_key, provision_certified_keys

SCRIPTS_DIR = Path(__file__).resolve().parents[1]

EXAMPLE_SUBJECT = (
    "'/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/"
    "emailAddress=android@android.com'"
)


class ScriptError(Exception):
    """The script stopped with exit status 1 after printing why."""


def _error(message: str, usage: Sequence[str]) -> ScriptError:
    """Print the message and the usage, and return the error to raise."""
    print(f"error: {message}, please try again", file=sys.stderr)
    for line in usage:
        print(line)
    return ScriptError()


def mkkey_main(program: str, arguments: Sequence[str]) -> int:
    """
    Generate a 2048-bit RSA key and its self-signed certificate as
    <key_name>.pk8 and <key_name>.x509.pem.

    Args:
        program: The script path to name in the usage text.
        arguments: The key name and the subject the script takes.

    Returns:
        0 on success, 1 on a usage error or an OpenSSL failure.

    Raises:
        OSError: If a key file cannot be written.
        ValueError: If the key name has no file name.
    """
    usage = (
        f"Usage: {program} key_name subject",
        "Example key_name: networkstack",
        f"Example subject: {EXAMPLE_SUBJECT}",
    )
    try:
        if len(arguments) != 2:
            raise _error("incorrect number of arguments", usage)
        key_name, subject = arguments
        if shutil.which("openssl") is None:
            raise _error("openssl not found in PATH.", usage)
        if os.path.exists(f"{key_name}.pk8") and not os.path.exists(
            f"{key_name}.x509.pem",
        ):
            print(
                f"error: key {key_name} exists without {key_name}.x509.pem.",
                file=sys.stderr,
            )
            print(
                "Restore the certificate from a backup, or delete "
                f"{key_name}.pk8 if the key was never used.",
                file=sys.stderr,
            )
            return 1
        for suffix in (".pk8", ".pem", ".x509.pem"):
            if os.path.exists(f"{key_name}{suffix}"):
                raise _error(f"key {key_name} already exists", usage)
    except ScriptError:
        return 1

    try:
        generate_certified_key(
            Path(key_name).parent,
            Path(key_name).name,
            subject,
        )
    except subprocess.CalledProcessError as error:
        sys.stderr.write(os.fsdecode(error.stderr or b""))
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def _key_script_arguments(
    arguments: Sequence[str],
    script: str,
) -> tuple[bool, str, list[str]]:
    """
    Split [--create-directory] PROGRAM ARGS... as the key script
    commands receive them.
    """
    arguments = list(arguments)
    create_directory = arguments[:1] == ["--create-directory"]
    if create_directory:
        arguments.pop(0)
    program = arguments.pop(0) if arguments else str(SCRIPTS_DIR / script)
    return create_directory, program, arguments


def _create_key_directory(arguments: Sequence[str]) -> None:
    """Create the key directory, refusing one that already exists."""
    if not arguments:
        return
    if os.path.isdir(arguments[0]):
        print("key directory already exists", file=sys.stderr)
        raise ScriptError()
    os.makedirs(arguments[0], exist_ok=True)


def _provision(provision: Callable[[], None]) -> int:
    """Run a key provisioning step, reporting its failure as an error."""
    try:
        provision()
    except subprocess.CalledProcessError as error:
        sys.stderr.write(os.fsdecode(error.stderr or b""))
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def _load_script_keymapper(
    environment: MutableMapping[str, str],
    metadata: SigningMetadata,
) -> Keymapper:
    """Load and apply the keymapper, KEYMAPPER defaulting to legacy."""
    environment["KEYMAPPER"] = environment.get("KEYMAPPER") or "legacy"
    try:
        keymapper = load_keymapper(environment, metadata)
    except ValueError as error:
        print(error, file=sys.stderr)
        raise ScriptError() from error
    apply_keymapper_exports(environment, keymapper)
    return keymapper


def updatekeys_main(
    environment: MutableMapping[str, str],
    arguments: Sequence[str],
) -> int:
    """
    Create or update a device's keys under a key directory, after
    creating the directory when --create-directory leads the arguments.

    Args:
        environment: Process environment, mutated in place.
        arguments: [--create-directory] PROGRAM KEY_DIR SUBJECT.

    Returns:
        0 on success, 1 on a usage or setup error.

    Raises:
        OSError: If the key directory cannot be created, or the metadata
            or a key file cannot be read or written.
        RuntimeError: If a key and its certificate are not both present.
        ValueError: If the metadata or the subject is invalid.
    """
    create_directory, program, arguments = _key_script_arguments(
        arguments,
        "updatekeys.sh",
    )
    usage = (
        f"Usage: {program} key_dir subject",
        f"Example subject: {EXAMPLE_SUBJECT}",
    )
    try:
        if len(arguments) != 2:
            if create_directory:
                _create_key_directory(arguments)
            raise _error("incorrect number of arguments", usage)
        key_path, subject = arguments
        scripts = Path(program).parent.resolve()
        top = f"{scripts}/../../.."
        metadata = load_metadata(default_metadata_path())
        device = Path(key_path).name
        environment["KEY_DIR"] = f"{Path(key_path).parent}/"
        avbtool = environment.get("AVBTOOL_BIN") or f"{top}/bin/avbtool"
        keymapper = _load_script_keymapper(environment, metadata)
        expected = Path(environment["KEY_DIR"]) / device
        if expected.resolve() != Path(key_path).resolve():
            keymapper_name = (
                f"the keymapper from {environment['KEYMAPPER_FILE']}"
                if environment.get("KEYMAPPER_FILE")
                else f"the {environment['KEYMAPPER']} keymapper"
            )
            raise _error(
                f"{keymapper_name} keeps the keys of {device} in "
                f"{expected}, not {key_path}",
                usage,
            )
        if create_directory:
            _create_key_directory(arguments)
        if not os.path.exists(avbtool):
            raise _error(f"{avbtool} not found.", usage)
        if shutil.which("openssl") is None:
            raise _error("openssl not found in PATH.", usage)
        if not os.path.isdir(key_path):
            raise _error("key directory does not exist", usage)
    except ScriptError:
        return 1
    return _provision(
        lambda: update_keys(
            keymapper,
            Path(environment["KEY_DIR"]),
            device,
            subject,
            avbtool,
            key_suffix=environment.get("KEY_SUFFIX", ".pem"),
        ),
    )


def updatecommonkeys_main(
    environment: MutableMapping[str, str],
    arguments: Sequence[str],
) -> int:
    """
    Convert the Chromium keystore and create the missing app keys under a
    key directory, after creating the directory when --create-directory
    leads the arguments.

    Args:
        environment: Process environment, mutated in place.
        arguments: [--create-directory] PROGRAM KEY_DIR SUBJECT.

    Returns:
        0 on success, 1 on a usage or setup error.

    Raises:
        OSError: If the key directory cannot be created, or the metadata
            or a key file cannot be read or written.
        RuntimeError: If a key and its certificate are not both present.
        ValueError: If the metadata or the subject is invalid.
    """
    create_directory, program, arguments = _key_script_arguments(
        arguments,
        "updatecommonkeys.sh",
    )
    usage = (
        f"Usage: {program} key_dir subject",
        f"Example subject: {EXAMPLE_SUBJECT}",
    )
    try:
        if create_directory:
            _create_key_directory(arguments)
        if len(arguments) != 2:
            raise _error("incorrect number of arguments", usage)
        key_dir, subject = arguments
        metadata = load_metadata(default_metadata_path())
        keymapper = _load_script_keymapper(environment, metadata)
        for tool in ("openssl", "keytool"):
            if shutil.which(tool) is None:
                raise _error(f"{tool} not found in PATH.", usage)
        if not os.path.isdir(key_dir):
            raise _error("key directory does not exist", usage)
    except ScriptError:
        return 1
    return _provision(
        lambda: update_common_keys(
            metadata,
            keymapper,
            Path(key_dir),
            subject,
        ),
    )


def update_keys(
    keymapper: Keymapper,
    key_directory: Path,
    device: str,
    subject: str,
    avbtool: str,
    key_suffix: str = ".pem",
) -> None:
    """
    Provision a device's plaintext keys and certificates, the core and
    APEX APK keys first, then the AVB keys, the APEX container keys and
    the APEX payload keys.

    Args:
        keymapper: Physical-key mapper.
        key_directory: Root directory containing generated key artifacts.
        device: Device whose per-device keys should be provisioned.
        subject: Distinguished name for self-signed certificates.
        avbtool: Executable used to derive AVB public keys.
        key_suffix: Suffix of the vbmeta and vbmeta_system private keys,
            from KEY_SUFFIX.

    Raises:
        FileExistsError: If key state collides.
        InconsistentKeyStateError: If a private key exists without its
            certificate, or a certificate without its private key.
        OSError: If artifact discovery or an external command fails.
        ValueError: If the subject is empty, or a key ID escapes the key
            directory.
    """
    if not subject:
        raise ValueError("certificate subject must not be empty")
    _provision_certificates(
        keymapper,
        key_directory,
        device,
        ("core", "apex_apk"),
        subject,
    )
    vbmeta_private = key_directory / keymapper.key(
        "avb",
        "vbmeta",
        device,
        suffix=key_suffix,
        key_suffix=key_suffix,
    )
    vbmeta_public = key_directory / keymapper.avb_custom_key(device)
    _provision_avb_key(avbtool, vbmeta_private, vbmeta_public)

    vbmeta_system_private = key_directory / keymapper.key(
        "avb",
        "vbmeta_system",
        device,
        suffix=key_suffix,
        key_suffix=key_suffix,
    )
    _generate_rsa_key(vbmeta_system_private)

    custom_public_key = key_directory / "avb_pkmd.bin"
    if custom_public_key.exists():
        custom_public_key.replace(vbmeta_public)

    legacy = key_directory / "com.android.runtime.release"
    current = key_directory / "com.android.runtime"
    for suffix in (".pk8", ".x509.pem"):
        if Path(f"{legacy}{suffix}").exists():
            Path(f"{legacy}{suffix}").replace(f"{current}{suffix}")
    _provision_certificates(
        keymapper,
        key_directory,
        device,
        ("apex_container",),
        subject,
    )

    seen_payloads: set[Path] = set()
    for row in keymapper.rows((device,)):
        if row.key_type != "apex_payload":
            continue
        base = key_directory / keymapper.key(
            "apex_payload",
            row.key_name,
            device,
            suffix="",
            key_suffix="",
        )
        private_key = Path(f"{base}.pem")
        if private_key in seen_payloads:
            continue
        seen_payloads.add(private_key)
        _provision_avb_key(avbtool, private_key, Path(f"{base}.avbpubkey"))


def _provision_certificates(
    keymapper: Keymapper,
    key_directory: Path,
    device: str,
    key_types: tuple[str, ...],
    subject: str,
) -> None:
    """
    Provision the certificate-bearing keys of some key types.

    Raises:
        FileExistsError: If a key to generate has a .pem file.
        InconsistentKeyStateError: If a private key exists without its
            certificate, or a certificate without its private key.
        OSError: If backend discovery or generation fails.
        ValueError: If a key ID escapes the key directory.
    """
    labels = sorted(
        {
            row.key_id
            for row in keymapper.rows((device,))
            if row.key_type in key_types
        },
    )
    for label in labels:
        path = key_directory / label
        if not Path(f"{path}.pk8").exists() and Path(f"{path}.pem").exists():
            raise FileExistsError(f"key {path} already exists")
    provision_certified_keys(key_directory, dict.fromkeys(labels, subject))


def _generate_rsa_key(private_key: Path) -> None:
    """
    Generate an RSA 4096 PEM private key unless one is there.

    Raises:
        subprocess.CalledProcessError: If OpenSSL fails.
    """
    if private_key.exists():
        return
    subprocess.run(
        ("openssl", "genrsa", "-out", str(private_key), "4096"),
        check=True,
    )


def _provision_avb_key(
    avbtool: str,
    private_key: Path,
    public_key: Path,
) -> None:
    """
    Generate a missing private key and derive its AVB public key.

    The public key is derived again on every call and replaced only when
    it differs, so an empty, stale or orphaned one is corrected.

    Raises:
        subprocess.CalledProcessError: If OpenSSL or avbtool fails.
    """
    _generate_rsa_key(private_key)
    derived = public_key.with_name(f"{public_key.name}.tmp")
    try:
        subprocess.run(
            (
                avbtool,
                "extract_public_key",
                "--key",
                str(private_key),
                "--output",
                str(derived),
            ),
            check=True,
        )
        if public_key.is_file() and (
            public_key.read_bytes() == derived.read_bytes()
        ):
            return
        os.replace(derived, public_key)
    finally:
        derived.unlink(missing_ok=True)


def update_common_keys(
    metadata: SigningMetadata,
    keymapper: Keymapper,
    key_directory: Path,
    subject: str,
) -> None:
    """
    Convert the Chromium keystore if present, then generate every app key
    that lacks its private key and certificate.

    Args:
        metadata: Validated signing-key metadata.
        keymapper: Keymapper naming the app keys.
        key_directory: Directory holding the common keys.
        subject: Distinguished name for self-signed certificates.

    Raises:
        ValueError: If the subject is empty.
        InconsistentKeyStateError: If an app's private key exists without
            its certificate, or a certificate without its key.
        subprocess.CalledProcessError: If keytool or openssl fails.
    """
    if not subject:
        raise ValueError("certificate subject must not be empty")
    _convert_chromium_keystore(key_directory)
    subjects: dict[str, str] = {}
    for key_name in metadata.keys_for_type("app"):
        label = Path(keymapper.key("app", key_name)).name
        if label:
            subjects[label] = subject.replace("_KEY_LABEL_", label)
    provision_certified_keys(key_directory, subjects)


def _convert_chromium_keystore(key_directory: Path) -> None:
    """
    Convert calyxos.keystore into chromium.pk8 and chromium.x509.pem,
    with keytool and openssl prompting for passwords on the terminal.

    The intermediate PKCS#12 file and the unencrypted PEM key stay in a
    private temporary directory, which is removed whether or not the
    conversion succeeds.
    """
    keystore = key_directory / "calyxos.keystore"
    if not keystore.exists():
        return
    with tempfile.TemporaryDirectory(prefix="chromium-key.") as directory:
        p12 = Path(directory) / "calyxos.p12"
        pem = Path(directory) / "calyxos.pem"
        for argv in (
            [
                "keytool",
                "-importkeystore",
                "-srckeystore",
                str(keystore),
                "-destkeystore",
                str(p12),
                "-srcstoretype",
                "jks",
                "-deststoretype",
                "pkcs12",
            ],
            ["openssl", "pkcs12", "-in", str(p12), "-out", str(pem), "-nodes"],
            [
                "openssl",
                "x509",
                "-in",
                str(pem),
                "-out",
                str(key_directory / "chromium.x509.pem"),
            ],
            [
                "openssl",
                "pkcs8",
                "-in",
                str(pem),
                "-out",
                str(key_directory / "chromium.pk8"),
                "-outform",
                "DER",
                "-topk8",
                "-nocrypt",
            ],
        ):
            subprocess.run(argv, check=True)
