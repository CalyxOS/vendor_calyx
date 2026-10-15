#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Load the signing metadata into backend-neutral Python objects.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

BASE_ARRAYS = (
    "keys_avb",
    "keys_other",
    "keys_core",
    "keys_apex",
    "keys_apex_apk",
    "keys_app",
    "keys_repo",
    "key_types",
    "all_devices",
)


@dataclass(frozen=True, slots=True)
class SigningMetadata:
    """
    Validated signing-key arrays and relationships from configuration.
    """

    arrays: Mapping[str, tuple[str, ...]]
    key_types: tuple[str, ...]
    key_type_to_array: Mapping[str, str]
    all_devices: tuple[str, ...]

    def keys_for_type(self, key_type: str) -> tuple[str, ...]:
        """
        Return ordered key names belonging to ``key_type``.

        Args:
            key_type: Declared metadata key category.

        Returns:
            Key names in metadata order, without "" placeholders.

        Raises:
            ValueError: If the key type is not declared by the metadata.
        """
        try:
            array_name = self.key_type_to_array[key_type]
        except KeyError as error:
            raise ValueError(f"unknown key type: {key_type}") from error
        return tuple(key for key in self.arrays[array_name] if key)

    def validate(self) -> None:
        """
        Validate uniqueness and references required by all keymappers.

        Returns:
            None.

        Raises:
            ValueError: If arrays contain duplicates, no key types or no
                devices are defined, or key-type mappings are incomplete.
        """
        for name, values in self.arrays.items():
            names = [value for value in values if value]
            if len(names) != len(set(names)):
                raise ValueError(f"duplicate entries in metadata array {name}")
        if not self.key_types:
            raise ValueError("metadata defines no key types")
        if not any(self.all_devices):
            raise ValueError("metadata defines no devices")
        if not set(self.key_types) <= set(self.key_type_to_array):
            raise ValueError("key_type_to_array does not cover key_types")


def default_metadata_path() -> Path:
    """
    Return the metadata module METADATA_FILE names, or scripts/metadata.py.

    Returns:
        Path of the metadata module to load.
    """
    return Path(
        os.environ.get("METADATA_FILE")
        or Path(__file__).resolve().parents[1] / "metadata.py",
    )


def load_metadata(path: Path) -> SigningMetadata:
    """
    Import a metadata module such as scripts/metadata.py.

    The module defines each array of BASE_ARRAYS as an upper-case tuple of
    strings (KEYS_AVB, ..., ALL_DEVICES) and KEY_TYPE_TO_ARRAY, mapping
    each key type to the lower-case name of one of those arrays.

    Args:
        path: Metadata module to import.

    Returns:
        Validated, immutable signing metadata.

    Raises:
        FileNotFoundError: If ``path`` is not a regular file.
        ValueError: If the module cannot be loaded, lacks an array or the
            mapping, an array is not a tuple of strings, the mapping names
            another array, or the metadata is invalid.
    """
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    spec = importlib.util.spec_from_file_location(
        "_signing_metadata",
        path,
        loader=importlib.machinery.SourceFileLoader(
            "_signing_metadata",
            str(path),
        ),
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import metadata module: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ValueError(
            f"cannot load metadata module {path} ({error})",
        ) from error

    arrays: dict[str, tuple[str, ...]] = {}
    for name in BASE_ARRAYS:
        try:
            values: object = getattr(module, name.upper())
        except AttributeError as error:
            raise ValueError(
                f"metadata module {path} defines no {name.upper()}",
            ) from error
        if not isinstance(values, tuple) or not all(
            isinstance(value, str) for value in cast(tuple[object, ...], values)
        ):
            raise ValueError(
                f"{name.upper()} in metadata module {path} is not a tuple of "
                "strings",
            )
        arrays[name] = cast(tuple[str, ...], values)
    try:
        mapping: object = module.KEY_TYPE_TO_ARRAY
    except AttributeError as error:
        raise ValueError(
            f"metadata module {path} defines no KEY_TYPE_TO_ARRAY",
        ) from error
    if not isinstance(mapping, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in cast(dict[object, object], mapping).items()
    ):
        raise ValueError(
            f"KEY_TYPE_TO_ARRAY in metadata module {path} does not map "
            "strings to strings",
        )
    mappings = cast(dict[str, str], mapping)
    for key_type, array_name in mappings.items():
        if array_name not in arrays:
            raise ValueError(
                f"KEY_TYPE_TO_ARRAY in metadata module {path} maps {key_type} "
                f"to {array_name}, which is not one of its arrays",
            )
    frozen_arrays = MappingProxyType(arrays)
    metadata = SigningMetadata(
        arrays=frozen_arrays,
        key_types=tuple(
            key_type for key_type in frozen_arrays["key_types"] if key_type
        ),
        key_type_to_array=MappingProxyType(mappings),
        all_devices=frozen_arrays["all_devices"],
    )
    metadata.validate()
    return metadata
