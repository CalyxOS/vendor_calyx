#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Device and build selection for sign.sh.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass


def parse_build_numbers(tokens: Sequence[str]) -> list[int]:
    """
    Read the words of BUILD_NUMBER or PREV_BUILD_NUMBER.

    A word that is not a decimal number names no target-files package, so
    it selects nothing.

    Args:
        tokens: The words, in order.

    Returns:
        The build numbers among them, in order.
    """
    return [
        int(token) for token in tokens if token.isascii() and token.isdigit()
    ]


_TARGET_FILES_RE = re.compile(
    r"^calyx_(?P<device>.+)-target_files-(?P<build>\d+)\.zip$",
)
_ARCHIVE_DIR_RE = re.compile(r"^release-(?P<device>.+)-(?P<build>\d+)$")


@dataclass(frozen=True, slots=True)
class SignPair:
    """
    One device/build/target_build to sign.
    """

    device: str
    build: int
    target_build: int

    @property
    def tag(self) -> str:
        """The "device,build,target_build" text naming the pair."""
        return f"{self.device},{self.build},{self.target_build}"


@dataclass(frozen=True, slots=True)
class IncrementalTriple:
    """
    One device/old_build/new_build incremental OTA to generate.
    """

    device: str
    old_build: int
    new_build: int

    @property
    def tag(self) -> str:
        """The "device,old_build,new_build" text naming the incremental."""
        return f"{self.device},{self.old_build},{self.new_build}"


@dataclass(frozen=True, slots=True)
class PrevBuildResult:
    """
    The previous builds find_prev_signed_device_builds() picks for each
    device, and the devices whose next build is already signed.
    """

    device_to_prev_build: Mapping[str, int]
    device_to_preexisting_build: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class SigningPlan:
    """
    The four bucketed work-item lists.
    """

    sign_pairs_with_loaded_keys: tuple[SignPair, ...]
    sign_pairs_without_loaded_keys: tuple[SignPair, ...]
    incremental_triples_with_loaded_keys: tuple[IncrementalTriple, ...]
    incremental_triples_without_loaded_keys: tuple[IncrementalTriple, ...]


def gather_signable_devices(
    devices: Sequence[str],
    all_devices: Sequence[str],
) -> tuple[str, ...]:
    """
    Intersect the site-specific device list with the exhaustive metadata list.

    Args:
        devices: Site-specific devices built here.
        all_devices: The exhaustive supported device list from metadata.

    Returns:
        Devices present in both, lexically sorted.
    """
    return tuple(sorted(set(devices) & set(all_devices)))


def gather_device_builds(
    target_files: Sequence[str],
    build_numbers: Sequence[int] | None = None,
) -> dict[str, int]:
    """
    Pick the numerically highest build per device.

    Args:
        target_files: calyx_<device>-target_files-<build>.zip filenames.
        build_numbers: If given, restricts the builds to these build
            numbers.

    Returns:
        Highest matching build number found per device.
    """
    result: dict[str, int] = {}
    for file in target_files:
        match = _TARGET_FILES_RE.match(file)
        if not match:
            continue
        device = match.group("device")
        build = int(match.group("build"))
        if build_numbers is not None and build not in build_numbers:
            continue
        if device not in result or build > result[device]:
            result[device] = build
    return result


def find_prev_signed_device_builds(
    archive_dirs: Sequence[str],
    *,
    device_to_next_build: Mapping[str, int],
    build_numbers: Sequence[int] = (),
    prev_build_numbers: Sequence[int] | None = None,
    avb_rollback_index_override: bool = False,
    target_files_exists: Callable[[str, str, int], bool],
) -> PrevBuildResult:
    """
    Find each device's best prior signed build to diff incrementals against.

    A device's prior build is the largest archived build strictly below
    its next build, or the largest archived build if it has no next build.

    Args:
        archive_dirs: release-<device>-<build> directory names under archive/.
        device_to_next_build: The build each device is being signed for, used
            to bound candidate prior builds from above.
        build_numbers: Requested build numbers, for detecting devices already
            signed under one of them (device_to_preexisting_build). Empty
            means BUILD_NUMBER is not yet known (skips this detection).
        prev_build_numbers: If given, restricts prior-build candidates to
            these build numbers, so that an empty sequence selects none.
        avb_rollback_index_override: Whether a rollback index override
            is in effect, which shifts the expected preexisting-build match
            by one.
        target_files_exists: Predicate telling whether
            archive/<archive_dir>/<device>-target_files-<build>.zip is a
            file, called as (archive_dir, device, build).

    Returns:
        The device_to_prev_build and device_to_preexisting_build
        bookkeeping.
    """
    device_to_preexisting_build: dict[str, int] = {}
    candidates: dict[str, list[int]] = {}

    for archive_dir in archive_dirs:
        match = _ARCHIVE_DIR_RE.match(archive_dir)
        if not match:
            continue
        device = match.group("device")
        build = int(match.group("build"))

        for build_number in build_numbers:
            expected_build = (
                build_number + 1
                if avb_rollback_index_override
                else build_number
            )
            if build == expected_build:
                device_to_preexisting_build[device] = build_number
                break

        if prev_build_numbers is not None and build not in prev_build_numbers:
            continue
        if not target_files_exists(archive_dir, device, build):
            continue
        candidates.setdefault(device, []).append(build)

    device_to_prev_build: dict[str, int] = {}
    for device, builds in candidates.items():
        next_build = device_to_next_build.get(device)
        eligible = [b for b in builds if next_build is None or b < next_build]
        if eligible:
            device_to_prev_build[device] = max(eligible)

    return PrevBuildResult(
        device_to_prev_build=device_to_prev_build,
        device_to_preexisting_build=device_to_preexisting_build,
    )


def partition_by_key_availability(
    devices_with_loaded_keys: Sequence[str],
    devices_without_loaded_keys: Sequence[str],
    *,
    device_to_next_build: Mapping[str, int],
    device_to_prev_build: Mapping[str, int],
    device_to_preexisting_build: Mapping[str, int],
    avb_rollback_index_override: bool = False,
) -> SigningPlan:
    """
    Build the four bucketed sign/incremental work-item lists.

    Args:
        devices_with_loaded_keys: Devices whose signing key is already
            resident on the HSM (or PKCS#11 is not in use at all).
        devices_without_loaded_keys: Devices whose signing key still needs
            loading.
        device_to_next_build: The build each device is being signed for.
        device_to_prev_build: Each device's prior build to diff against, if
            any (from find_prev_signed_device_builds()).
        device_to_preexisting_build: Devices already signed under the
            requested build, which are not signed again.
        avb_rollback_index_override: Whether a rollback index override
            is in effect, which bumps the signing target build by one.

    Returns:
        The four bucketed work-item lists.
    """

    def build_pairs(
        devices: Sequence[str],
        preexisting_builds: Mapping[str, int],
    ) -> tuple[tuple[SignPair, ...], tuple[IncrementalTriple, ...]]:
        sign_pairs: list[SignPair] = []
        incrementals: list[IncrementalTriple] = []
        for device in devices:
            next_build = device_to_next_build[device]
            next_target = (
                next_build + 1 if avb_rollback_index_override else next_build
            )
            if next_build != preexisting_builds.get(device):
                sign_pairs.append(SignPair(device, next_build, next_target))
            prev_build = device_to_prev_build.get(device)
            if prev_build is not None:
                incrementals.append(
                    IncrementalTriple(device, prev_build, next_build),
                )
        return tuple(sign_pairs), tuple(incrementals)

    sign_with, incremental_with = build_pairs(
        devices_with_loaded_keys,
        device_to_preexisting_build,
    )
    sign_without, incremental_without = build_pairs(
        devices_without_loaded_keys,
        device_to_preexisting_build,
    )
    return SigningPlan(
        sign_pairs_with_loaded_keys=sign_with,
        sign_pairs_without_loaded_keys=sign_without,
        incremental_triples_with_loaded_keys=incremental_with,
        incremental_triples_without_loaded_keys=incremental_without,
    )
