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
from typing import Self


class BuildNumber(int):
    """
    A build number that orders numerically and prints as it was written,
    so that a file name built from it names the file it came from.
    """

    text: str

    def __new__(cls, text: str) -> Self:
        number = super().__new__(cls, int(text))
        number.text = text
        return number

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"BuildNumber({self.text!r})"

    def __format__(self, format_spec: str) -> str:
        return self.text if not format_spec else super().__format__(format_spec)


def parse_build_numbers(tokens: Sequence[str]) -> list[BuildNumber]:
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
        BuildNumber(token)
        for token in tokens
        if token.isascii() and token.isdigit()
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


@dataclass(frozen=True, slots=True)
class IncrementalTriple:
    """
    One device/old_build/new_build incremental OTA to generate.

    new_build is None for a device with prior-build history but no build
    selected to sign this run.
    """

    device: str
    old_build: int
    new_build: int | None


@dataclass(frozen=True, slots=True)
class PrevBuildResult:
    """
    The previous builds find_prev_signed_device_builds() picks for each
    device, the devices whose next build is already signed, and the
    distinct previous builds in order.
    """

    device_to_prev_build: Mapping[str, int]
    device_to_preexisting_build: Mapping[str, int]
    prev_builds_sorted: tuple[int, ...]


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


def _parse_target_files(
    target_files: Sequence[str],
) -> list[tuple[str, int]]:
    parsed: list[tuple[str, int]] = []
    for file in target_files:
        match = _TARGET_FILES_RE.match(file)
        if match:
            parsed.append(
                (match.group("device"), BuildNumber(match.group("build"))),
            )
    return parsed


def gather_latest_device_builds(
    target_files: Sequence[str],
) -> dict[str, int]:
    """
    Pick the numerically highest build per device, ignoring BUILD_NUMBER.

    Args:
        target_files: calyx_<device>-target_files-<build>.zip filenames.

    Returns:
        Highest build number found per device.
    """
    result: dict[str, int] = {}
    for device, build in _parse_target_files(target_files):
        if device not in result or build > result[device]:
            result[device] = build
    return result


def gather_device_builds_to_sign(
    target_files: Sequence[str],
    build_numbers: Sequence[int],
) -> dict[str, int]:
    """
    Pick the highest matching build per device, restricted to build_numbers.

    Args:
        target_files: calyx_<device>-target_files-<build>.zip filenames.
        build_numbers: Build numbers the user selected.

    Returns:
        Highest matching build number found per device.
    """
    allowed = {str(build) for build in build_numbers}
    result: dict[str, int] = {}
    for device, build in _parse_target_files(target_files):
        if str(build) not in allowed:
            continue
        if device not in result or build > result[device]:
            result[device] = build
    return result


def sorted_build_numbers(device_to_build: Mapping[str, int]) -> tuple[int, ...]:
    """
    Return the distinct build numbers in a device-to-build mapping, sorted.

    Args:
        device_to_build: Per-device build numbers.

    Returns:
        Distinct build numbers, ascending.
    """
    by_text = {str(build): build for build in device_to_build.values()}
    return tuple(
        sorted(by_text.values(), key=lambda build: (build, str(build))),
    )


def find_prev_signed_device_builds(
    archive_dirs: Sequence[str],
    *,
    device_to_next_build: Mapping[str, int],
    build_numbers: Sequence[int] = (),
    prev_build_numbers: Sequence[int] | None = None,
    avb_rollback_index_override: str | None = None,
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
        avb_rollback_index_override: Rollback index in effect, if any,
            which shifts the expected preexisting-build match by one.
        target_files_exists: Predicate telling whether
            archive/<archive_dir>/<device>-target_files-<build>.zip is a
            file, called as (archive_dir, device, build).

    Returns:
        The device_to_prev_build, device_to_preexisting_build and
        prev_builds_sorted bookkeeping.
    """
    device_to_preexisting_build: dict[str, int] = {}
    candidates: dict[str, list[int]] = {}

    for archive_dir in archive_dirs:
        match = _ARCHIVE_DIR_RE.match(archive_dir)
        if not match:
            continue
        device = match.group("device")
        build = BuildNumber(match.group("build"))

        if build_numbers:
            for build_number in build_numbers:
                expected_build = (
                    build_number
                    if avb_rollback_index_override is None
                    else build_number + 1
                )
                if str(build) == str(expected_build):
                    device_to_preexisting_build[device] = build_number
                    break

        if prev_build_numbers is not None and str(build) not in {
            str(prev_build) for prev_build in prev_build_numbers
        }:
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
        prev_builds_sorted=sorted_build_numbers(device_to_prev_build),
    )


def partition_by_key_availability(
    devices_with_loaded_keys: Sequence[str],
    devices_without_loaded_keys: Sequence[str],
    *,
    device_to_next_build: Mapping[str, int],
    device_to_prev_build: Mapping[str, int],
    device_to_preexisting_build: Mapping[str, int],
    avb_rollback_index_override: str | None = None,
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
            requested build. Only devices with loaded keys skip re-signing.
        avb_rollback_index_override: Rollback index in effect, if any,
            which bumps the signing target build by one.

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
            next_build = device_to_next_build.get(device)
            if next_build is not None:
                next_target = (
                    next_build + 1
                    if avb_rollback_index_override is not None
                    else next_build
                )
                preexisting_build = preexisting_builds.get(device, "")
                if str(next_build) != str(preexisting_build):
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
        {},
    )
    return SigningPlan(
        sign_pairs_with_loaded_keys=sign_with,
        sign_pairs_without_loaded_keys=sign_without,
        incremental_triples_with_loaded_keys=incremental_with,
        incremental_triples_without_loaded_keys=incremental_without,
    )
