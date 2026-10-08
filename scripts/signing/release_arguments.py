#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Build the AVB, sign_target_files_apks and ota_from_target_files
argument lists of a release.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass

from .keymap import Keymapper
from .metadata import SigningMetadata

_ROLLBACK_OVERRIDE_DEVICES = frozenset(
    {"devon", "hawao", "rhode", "fogos", "bangkk", "fogo"},
)

GetKey = Callable[[str, str], str]


class UnsupportedRollbackDeviceError(ValueError):
    """
    Raised when AVB_ROLLBACK_INDEX_OVERRIDE is set for a device that
    does not support a rollback index override.
    """


@dataclass(frozen=True, slots=True)
class ReleaseArguments:
    """
    The argument lists passed to sign_target_files_apks and
    ota_from_target_files.
    """

    signing_args: tuple[str, ...]
    ota_args: tuple[str, ...]


def make_get_key(
    keymapper: Keymapper,
    environment: MutableMapping[str, str],
    *,
    device: str,
) -> GetKey:
    """
    Bind a keymapper and device into a key resolver under the
    keymapper's KEY_DIR.

    AVB keys are requested with KEY_SUFFIX, which defaults to .pem only
    when unset, and APEX payload keys with .pem. Each keymapper decides
    which suffix it applies.

    Args:
        keymapper: Keymapper to resolve keys through.
        environment: Process environment to read KEY_DIR and KEY_SUFFIX
            from, with the keymapper's KEY_DIR export applied in place.
        device: Device to resolve per-device keys for.

    Returns:
        A callable taking key_type and key_name, which returns the key
        path, or an empty value for a key the keymapper does not map.
    """
    key_dir = keymapper.key_dir(environment)
    key_suffix = environment.get("KEY_SUFFIX", ".pem")

    def get_key(key_type: str, key_name: str) -> str:
        suffix = {"avb": key_suffix, "apex_payload": ".pem"}.get(key_type, "")
        value = keymapper.key(
            key_type,
            key_name,
            device,
            suffix=suffix,
            key_suffix=key_suffix,
        )
        return f"{key_dir}{value}" if value else ""

    return get_key


def build_release_arguments(
    metadata: SigningMetadata,
    get_key: GetKey,
    *,
    device: str,
    avb_rollback_index_override: str | None = None,
    avb_algorithm: str = "SHA256_RSA4096",
    extra_signing_args: Sequence[str] = (),
    extra_ota_args: Sequence[str] = (),
) -> ReleaseArguments:
    """
    Build the signing and OTA argument lists for one release, the AVB
    arguments last in the signing list.

    Args:
        metadata: Validated signing metadata (keys_avb/keys_apex/etc.).
        get_key: Bound key resolver, e.g. from make_get_key().
        device: Device being released.
        avb_rollback_index_override: Rollback index to bump to, or None for
            a normal release. Only a fixed set of device families
            support this.
        avb_algorithm: AVB signing algorithm string, e.g. "SHA256_RSA4096".
        extra_signing_args: Signing arguments to put before the ones
            built here, such as those from prepare_signing_args().
        extra_ota_args: Same, for EXTRA_OTA_ARGS.

    Returns:
        The two argument lists.

    Raises:
        UnsupportedRollbackDeviceError: If avb_rollback_index_override is
            set for a device that doesn't support it.
    """
    avb_arguments: list[str] = []
    for keyname in metadata.arrays["keys_avb"]:
        if not keyname:
            continue
        avb_arguments += [
            f"--avb_{keyname}_key",
            get_key("avb", keyname),
            f"--avb_{keyname}_algorithm",
            avb_algorithm,
        ]

    signing_args = list(extra_signing_args)
    ota_args = list(extra_ota_args)

    for key in metadata.arrays["keys_apex"]:
        if not key:
            continue
        signing_args += [
            "--extra_apks",
            f"{key}.apex={get_key('apex_container', key)}",
        ]
        signing_args += [
            "--extra_apex_payload_key",
            f"{key}.apex={get_key('apex_payload', key)}",
        ]

    already_remapped: set[str] = set()
    remap_loops = (
        (
            "core",
            (
                "build/make/target/product/security/devkey",
                *metadata.arrays["keys_core"],
            ),
        ),
        ("apex_apk", metadata.arrays["keys_apex_apk"]),
        ("app", metadata.arrays["keys_app"]),
    )
    for key_type, keys in remap_loops:
        for key in keys:
            if not key or key in already_remapped:
                continue
            value = get_key(key_type, key)
            if not value:
                continue
            signing_args += ["-k", f"{key}={value}"]
            already_remapped.add(key)

    if avb_rollback_index_override is not None:
        if device not in _ROLLBACK_OVERRIDE_DEVICES:
            raise UnsupportedRollbackDeviceError(
                f"Unsupported device for AVB Rollback Index override: {device}",
            )
        signing_args += [
            "--avb_rollback_index_override",
            avb_rollback_index_override,
            "--bump_date_and_version",
            "1",
        ]

    ota_key = get_key("other", "ota")
    signing_args += ["--package_key", ota_key]
    ota_args += ["--package_key", ota_key]

    return ReleaseArguments(
        signing_args=(*signing_args, *avb_arguments),
        ota_args=tuple(ota_args),
    )
