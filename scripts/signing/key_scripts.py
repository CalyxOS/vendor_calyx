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
from collections.abc import Sequence
from pathlib import Path

from .keymap import Keymapper
from .models import KeyReference, KeySpec
from .plaintext import PlaintextBackend, provision_certified_keys

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
        0 on success, 1 for any failure.
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

    spec = KeySpec(KeyReference(label=Path(key_name).name), 2048)
    backend = PlaintextBackend(Path(key_name).parent)
    try:
        backend.generate_key(spec)
        backend.generate_certificate(spec, subject)
    except subprocess.CalledProcessError as error:
        sys.stderr.write(os.fsdecode(error.stderr or b""))
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


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
    provision_avb_key(avbtool, vbmeta_private, vbmeta_public)

    vbmeta_system_private = key_directory / keymapper.key(
        "avb",
        "vbmeta_system",
        device,
        suffix=key_suffix,
        key_suffix=key_suffix,
    )
    generate_rsa_key(vbmeta_system_private)

    custom_public_key = key_directory / "avb_pkmd.bin"
    if custom_public_key.exists():
        custom_public_key.replace(vbmeta_public)

    migrate_runtime_key(key_directory)
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
        provision_avb_key(avbtool, private_key, Path(f"{base}.avbpubkey"))


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
    provision_certified_keys(
        PlaintextBackend(key_directory),
        dict.fromkeys(labels, subject),
    )


def generate_rsa_key(private_key: Path) -> None:
    """
    Generate an RSA 4096 PEM private key unless one is there.

    Args:
        private_key: PEM destination for the RSA private key.

    Raises:
        subprocess.CalledProcessError: If OpenSSL fails.
    """
    if private_key.exists():
        return
    subprocess.run(
        ("openssl", "genrsa", "-out", str(private_key), "4096"),
        check=True,
    )


def provision_avb_key(
    avbtool: str,
    private_key: Path,
    public_key: Path,
) -> None:
    """
    Generate a missing private key and derive its AVB public key.

    The public key is derived again on every call and replaced only when
    it differs, so an empty, stale or orphaned one is corrected.

    Args:
        avbtool: Executable used to derive AVB public keys.
        private_key: PEM destination for the RSA private key.
        public_key: Destination for the AVB public key.

    Raises:
        subprocess.CalledProcessError: If OpenSSL or avbtool fails.
    """
    generate_rsa_key(private_key)
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


def migrate_runtime_key(key_directory: Path) -> None:
    """
    Rename the legacy runtime key and certificate to their current names.

    Args:
        key_directory: Directory containing plaintext signing artifacts.

    Raises:
        subprocess.CalledProcessError: If a move command fails.
    """
    legacy = key_directory / "com.android.runtime.release"
    current = key_directory / "com.android.runtime"
    for suffix in (".pk8", ".x509.pem"):
        if Path(f"{legacy}{suffix}").exists():
            subprocess.run(
                ("mv", f"{legacy}{suffix}", f"{current}{suffix}"),
                check=True,
            )
