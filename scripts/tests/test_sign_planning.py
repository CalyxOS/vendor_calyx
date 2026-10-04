#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import stub
from signing.sign_planning import (
    BuildNumber,
    IncrementalTriple,
    SignPair,
    find_prev_signed_device_builds,
    gather_device_builds_to_sign,
    gather_latest_device_builds,
    gather_signable_devices,
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


def test_gather_latest_device_builds_picks_the_highest_build() -> None:
    result = gather_latest_device_builds(
        [
            "calyx_bramble-target_files-2026081400.zip",
            "calyx_redfin-target_files-2026081300.zip",
            "calyx_bramble-target_files-2026081500.zip",
            "calyx_redfin-target_files-2026081600.zip",
        ],
    )

    assert result == {"bramble": 2026081500, "redfin": 2026081600}
    assert sorted_build_numbers(result) == (2026081500, 2026081600)


def test_gather_device_builds_to_sign_keeps_the_requested_builds() -> None:
    result = gather_device_builds_to_sign(
        [
            "calyx_bramble-target_files-2026081400.zip",
            "calyx_bramble-target_files-2026081500.zip",
            "calyx_redfin-target_files-2026081600.zip",
        ],
        [2026081400, 2026081600],
    )

    assert result == {"bramble": 2026081400, "redfin": 2026081600}


def test_planning_skips_names_without_a_numeric_build() -> None:
    target_files = [
        "calyx_bramble-target_files-latest.zip",
        "calyx_redfin-target_files-2026081500.zip",
    ]
    next_builds = gather_latest_device_builds(target_files)
    previous = find_prev_signed_device_builds(
        ["release-bramble-latest", "release-redfin-2026080100"],
        device_to_next_build=next_builds,
        target_files_exists=stub(True),
    )

    assert next_builds == {"redfin": 2026081500}
    assert previous.device_to_prev_build == {"redfin": 2026080100}


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


def test_gather_signable_devices_keeps_known_devices_in_metadata_order() -> (
    None
):
    assert gather_signable_devices(
        ("redfin", "bramble", "unknown_device"),
        ("bramble", "redfin", "barbet"),
    ) == ("bramble", "redfin")


def test_gather_builds_of_no_build_numbers_or_target_files_is_empty() -> None:
    assert (
        gather_device_builds_to_sign(
            (
                "calyx_bramble-target_files-2026081400.zip",
                "calyx_redfin-target_files-2026081600.zip",
            ),
            (),
        )
        == {}
    )
    assert gather_latest_device_builds(()) == {}


@pytest.mark.parametrize(
    ("avb_rollback_index_override", "target"),
    ((None, 2026081500), ("42", 2026081501)),
    ids=("no-rollback", "rollback"),
)
def test_partition_skips_a_preexisting_build_with_or_without_keys(
    avb_rollback_index_override: str | None,
    target: int,
) -> None:
    plan = partition_by_key_availability(
        ("bramble", "barbet"),
        ("redfin",),
        device_to_next_build={
            "bramble": 2026081500,
            "barbet": 2026081500,
            "redfin": 2026081500,
        },
        device_to_prev_build={"bramble": 2026081400, "redfin": 2026081300},
        device_to_preexisting_build={
            "barbet": 2026081500,
            "redfin": 2026081500,
        },
        avb_rollback_index_override=avb_rollback_index_override,
    )

    assert plan.sign_pairs_with_loaded_keys == (
        SignPair("bramble", 2026081500, target),
    )
    assert plan.sign_pairs_without_loaded_keys == ()
    assert plan.incremental_triples_with_loaded_keys == (
        IncrementalTriple("bramble", 2026081400, 2026081500),
    )
    assert plan.incremental_triples_without_loaded_keys == (
        IncrementalTriple("redfin", 2026081300, 2026081500),
    )


def test_find_prev_builds_ignores_an_archive_without_target_files(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    for name, target_files in (
        ("release-bramble-2026081300", "bramble-target_files-2026081300.zip"),
        ("release-bramble-2026081400", "bramble-target_files-2026081400.zip"),
        ("release-redfin-2026081200", "redfin-target_files-2026081200.zip"),
        ("release-redfin-2026081500", "redfin-target_files-2026081500.zip"),
        ("release-barbet-2026081100", None),
    ):
        (archive / name).mkdir(parents=True)
        if target_files:
            (archive / name / target_files).touch()

    result = find_prev_signed_device_builds(
        sorted(path.name for path in archive.iterdir()),
        device_to_next_build={
            "bramble": 2026081500,
            "redfin": 2026081500,
            "barbet": 2026081500,
        },
        build_numbers=(2026081500,),
        target_files_exists=lambda directory, device, build: (
            archive / directory / f"{device}-target_files-{build}.zip"
        ).is_file(),
    )

    assert result.device_to_prev_build == {
        "bramble": 2026081400,
        "redfin": 2026081200,
    }
    assert result.device_to_preexisting_build == {"redfin": 2026081500}


def test_sorted_build_numbers_keeps_builds_that_differ_in_padding() -> None:
    builds = sorted_build_numbers(
        {"bramble": BuildNumber("042"), "redfin": BuildNumber("42")},
    )

    assert [str(build) for build in builds] == ["042", "42"]
