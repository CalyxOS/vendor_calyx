#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import pytest
from conftest import stub
from signing.sign_planning import (
    BuildNumber,
    find_prev_signed_device_builds,
    gather_device_builds_to_sign,
    gather_latest_device_builds,
    parse_build_numbers,
    partition_by_key_availability,
    sorted_build_numbers,
)


def test_gather_device_builds_to_sign_ignores_non_matching_files() -> None:
    result = gather_device_builds_to_sign(
        ["not_a_target_files_zip.txt", "calyx_bramble-target_files-x.zip"],
        [2026081500],
    )

    assert result == {}


def test_find_prev_signed_device_builds_detects_preexisting_build() -> None:
    result = find_prev_signed_device_builds(
        ["release-bramble-2026081500"],
        device_to_next_build={"bramble": 2026081500},
        build_numbers=[2026081500],
        target_files_exists=stub(True),
    )

    assert result.device_to_preexisting_build == {"bramble": 2026081500}
    assert result.device_to_prev_build == {}


def test_find_prev_signed_device_builds_applies_rollback_offset() -> None:
    result = find_prev_signed_device_builds(
        ["release-bramble-2026081501"],
        device_to_next_build={"bramble": 2026081501},
        build_numbers=[2026081500],
        avb_rollback_index_override="1",
        target_files_exists=stub(True),
    )

    assert result.device_to_preexisting_build == {"bramble": 2026081500}


@pytest.mark.parametrize(
    ("prev_build_numbers", "expected"),
    (
        ([2026081300], {"bramble": 2026081300}),
        ([], {}),
    ),
    ids=("some", "none"),
)
def test_find_prev_signed_device_builds_restricts_to_prev_build_numbers(
    prev_build_numbers: list[int],
    expected: dict[str, int],
) -> None:
    result = find_prev_signed_device_builds(
        ["release-bramble-2026081300", "release-bramble-2026081400"],
        device_to_next_build={"bramble": 2026081500},
        prev_build_numbers=prev_build_numbers,
        target_files_exists=stub(True),
    )

    assert result.device_to_prev_build == expected


def test_build_numbers_order_numerically_and_keep_their_text() -> None:
    builds = gather_latest_device_builds(
        [
            "calyx_bramble-target_files-0042.zip",
            "calyx_bramble-target_files-100.zip",
            "calyx_redfin-target_files-0042.zip",
        ],
    )

    assert builds == {"bramble": 100, "redfin": 42}
    assert f"calyx_redfin-target_files-{builds['redfin']}.zip" == (
        "calyx_redfin-target_files-0042.zip"
    )
    plan = partition_by_key_availability(
        ["redfin"],
        [],
        device_to_next_build=builds,
        device_to_prev_build={},
        device_to_preexisting_build={},
    )
    assert [
        (str(pair.build), str(pair.target_build))
        for pair in plan.sign_pairs_with_loaded_keys
    ] == [("0042", "0042")]


def test_build_numbers_match_by_their_text() -> None:
    files = ["calyx_bramble-target_files-0042.zip"]

    assert gather_device_builds_to_sign(files, [BuildNumber("42")]) == {}
    assert gather_device_builds_to_sign(files, [BuildNumber("0042")]) == {
        "bramble": 42,
    }
    result = find_prev_signed_device_builds(
        ["release-bramble-0042"],
        device_to_next_build={"bramble": BuildNumber("100")},
        build_numbers=[BuildNumber("42")],
        prev_build_numbers=[BuildNumber("42")],
        target_files_exists=stub(True),
    )
    assert result.device_to_preexisting_build == {}
    assert result.device_to_prev_build == {}


def test_a_preexisting_build_matches_the_next_build_by_its_text() -> None:
    plan = partition_by_key_availability(
        ["bramble"],
        [],
        device_to_next_build={"bramble": BuildNumber("0042")},
        device_to_prev_build={},
        device_to_preexisting_build={"bramble": BuildNumber("42")},
    )

    assert [
        (str(pair.build), str(pair.target_build))
        for pair in plan.sign_pairs_with_loaded_keys
    ] == [("0042", "0042")]


def test_parse_build_numbers_skips_words_that_are_not_numbers() -> None:
    assert parse_build_numbers(["2026081500", "2026081600,", "eng", "07"]) == [
        BuildNumber("2026081500"),
        BuildNumber("07"),
    ]


def test_sorted_build_numbers_keeps_builds_that_differ_in_padding() -> None:
    builds = sorted_build_numbers(
        {"bramble": BuildNumber("042"), "redfin": BuildNumber("42")},
    )

    assert [str(build) for build in builds] == ["042", "42"]
