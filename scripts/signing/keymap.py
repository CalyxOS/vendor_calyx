#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Resolve logical keys from signing metadata to physical key identities.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from .metadata import SigningMetadata


@dataclass(frozen=True, order=True, slots=True)
class KeymapRow:
    """
    One stable ID-to-key association emitted in a keymap.
    """

    key_id: str
    device: str
    key_type: str
    key_name: str

    def to_tsv(self) -> str:
        """
        Serialize the row without a trailing newline.

        Returns:
            The row encoded as tab-separated fields.
        """
        return "\t".join(
            (self.key_id, self.device, self.key_type, self.key_name),
        )


class Keymapper(abc.ABC):
    """
    Resolve logical metadata keys to physical key identities.
    """

    @abc.abstractmethod
    def rows(self, devices: Sequence[str]) -> tuple[KeymapRow, ...]:
        """
        Build physical mappings for selected devices.

        Args:
            devices: Device names to map.

        Returns:
            Deterministically ordered logical-to-physical mappings.

        Raises:
            ValueError: If devices or mapper configuration are invalid.
        """

    def to_tsv(self, devices: Sequence[str]) -> str:
        """
        Serialize a complete keymap, including its header and final newline.

        Args:
            devices: Device names for which per-device rows should be emitted.

        Returns:
            The complete keymap in tab-separated format.

        Raises:
            ValueError: If no devices are supplied or a device is unknown.
        """
        lines = ["ID\tDevice\tKey Type\tKey"]
        lines.extend(row.to_tsv() for row in self.rows(devices))
        return "\n".join(lines) + "\n"


class _BaseKeymapper(Keymapper):
    """
    Keymapper whose rows come from the metadata arrays.
    """

    metadata: SigningMetadata

    def rows(self, devices: Sequence[str]) -> tuple[KeymapRow, ...]:
        """
        Build sorted keymap rows for selected devices.

        Args:
            devices: Non-empty device names.

        Returns:
            Deterministically sorted keymap rows.

        Raises:
            ValueError: If no devices are supplied, or the keymapper does
                not know a device.
        """
        self._validate_devices(devices)
        rows: list[KeymapRow] = []
        for key_type in self.metadata.key_types:
            for key_name in self.metadata.keys_for_type(key_type):
                row_devices = (
                    devices
                    if self._is_per_device_row(key_type, key_name)
                    else ("",)
                )
                for device in row_devices:
                    value = self._row_value(key_type, key_name, device)
                    if value:
                        rows.append(
                            KeymapRow(value, device, key_type, key_name),
                        )
        return tuple(sorted(rows))

    def _validate_devices(self, devices: Sequence[str]) -> None:
        """
        Validate a non-empty collection of device names.

        The base accepts any device name.

        Args:
            devices: Device names to validate.

        Returns:
            None.

        Raises:
            ValueError: If no devices are supplied.
        """
        if not devices:
            raise ValueError("at least one device is required")

    @abc.abstractmethod
    def _is_per_device_row(self, key_type: str, key_name: str) -> bool:
        """
        Resolve whether a logical key receives one row per device.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.

        Returns:
            Whether ``rows()`` should emit one row per device rather than a
            single shared row.
        """

    @abc.abstractmethod
    def _row_value(self, key_type: str, key_name: str, device: str) -> str:
        """
        Resolve the identity value for one row.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.
            device: Device name, or the empty string for a shared row.

        Returns:
            The row's identity value, or an empty string to omit the row.
        """


@dataclass(frozen=True, slots=True)
class Id2bConfig:
    """
    Configurable policies and ID ranges for the two-byte keymapper.
    """

    device_prefix_start: int = 0x20
    device_prefix_end: int = 0xFE
    key_type_to_prefix: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(
            {
                "avb": 0x10,
                "core": 0x11,
                "apex_container": 0x12,
                "apex_payload": 0x13,
                "apex_apk": 0x14,
                "app": 0x15,
                "repo": 0x16,
            },
        ),
    )
    per_device_offsets: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(
            {
                "avb": 0x00,
                "core": 0x10,
                "apex_container": 0x30,
                "apex_payload": 0x80,
                "apex_apk": 0xD0,
            },
        ),
    )
    key_is_per_device: Mapping[str, bool] = field(
        default_factory=lambda: MappingProxyType(
            {
                "avb": True,
                "ota": True,
                "releasekey": False,
                "core": False,
                "app": False,
                "repo": False,
                "apex_container": False,
                "apex_payload": False,
                "apex_apk": False,
            },
        ),
    )
    avb_consolidation: str = "all"
    apex_consolidation: str = "dual"
    ota_key_type: str = "avb"
    ota_key_name: str = "vbmeta"
    release_key_type: str = "core"
    release_key_name: str = "build/make/target/product/security/testkey"


class Id2bKeymapper(_BaseKeymapper):
    """
    Assign deterministic two-byte IDs to configured Android signing keys.
    """

    def __init__(self, metadata: SigningMetadata):
        """
        Create a mapper for a set of metadata.

        Args:
            metadata: Validated key and device configuration.

        Returns:
            None.

        Raises:
            ValueError: If the mapping configuration is invalid.
        """
        self.metadata = metadata
        self.config = Id2bConfig()
        self._indices = {
            name: {value: index for index, value in enumerate(values) if value}
            for name, values in metadata.arrays.items()
        }
        self._validate_config()

    def _validate_config(self) -> None:
        """
        Reject ID-range exhaustion and unsupported consolidation strategies.

        Returns:
            None.

        Raises:
            ValueError: If an ID range is exhausted or a strategy is
                unsupported.
        """
        device_count = len(self.metadata.all_devices)
        available = (
            self.config.device_prefix_end - self.config.device_prefix_start + 1
        )
        if device_count > available:
            raise ValueError(
                "all_devices exceeds the configured two-byte ID range",
            )
        if self.config.avb_consolidation not in {"all", "delegated", "none"}:
            raise ValueError("invalid AVB consolidation strategy")
        if self.config.apex_consolidation not in {
            "single",
            "dual",
            "triple",
            "combined",
            "none",
        }:
            raise ValueError("invalid APEX consolidation strategy")

    def _is_per_device(self, key_type: str, key_name: str) -> bool:
        """
        Resolve whether a logical key receives a distinct ID per device.

        OTA and the historical release key have policies separate from the key
        type to which they eventually alias.

        Args:
            key_type: Metadata category containing the key.
            key_name: Logical key name within the category.

        Returns:
            Whether the key receives a separate ID for each device.

        Raises:
            ValueError: If no per-device policy exists for the key category.
        """
        lookup = key_type
        if key_type == "other" and key_name == "ota":
            lookup = "ota"
        elif key_type == "core" and key_name in {
            "build/make/target/product/security/testkey",
            "build/make/target/product/security/devkey",
        }:
            lookup = "releasekey"
        try:
            return self.config.key_is_per_device[lookup]
        except KeyError as error:
            raise ValueError(
                f"no per-device policy for key type {lookup}",
            ) from error

    def _canonical_key(self, key_type: str, key_name: str) -> tuple[str, str]:
        """
        Apply AVB, APEX, OTA, and release-key consolidation aliases.

        Args:
            key_type: Original metadata key category.
            key_name: Original logical key name.

        Returns:
            The canonical key category and name.
        """
        if key_type == "avb":
            if self.config.avb_consolidation == "all":
                key_name = "vbmeta"
            elif (
                self.config.avb_consolidation == "delegated"
                and key_name != "vbmeta"
            ):
                key_name = self.metadata.arrays["keys_avb"][1]
        elif key_type in {"apex_container", "apex_payload", "apex_apk"}:
            strategy = self.config.apex_consolidation
            if strategy == "combined":
                key_type = "apex_container"
            elif strategy == "single":
                key_type = "apex_container"
                key_name = self.metadata.arrays["keys_apex"][0]
            elif strategy == "dual":
                if key_type in {"apex_container", "apex_apk"}:
                    key_type = "apex_container"
                key_name = self.metadata.arrays["keys_apex"][0]
            elif strategy == "triple":
                key_name = self.metadata.arrays["keys_apex"][0]
        elif key_type == "core" and key_name in {
            "build/make/target/product/security/testkey",
            "build/make/target/product/security/devkey",
        }:
            key_type = self.config.release_key_type
            key_name = self.config.release_key_name
        elif key_type == "other" and key_name == "ota":
            key_type = self.config.ota_key_type
            key_name = self.config.ota_key_name
        return key_type, key_name

    def key_id(self, key_type: str, key_name: str, device: str = "") -> str:
        """
        Return the four-digit hexadecimal ID for one logical key.

        Args:
            key_type: Metadata key category, such as ``avb`` or ``core``.
            key_name: Name as it appears in the category's metadata array.
            device: Required when the logical key is per-device.

        Returns:
            A two-byte key ID formatted as ``0xhhhh``.

        Raises:
            ValueError: If the key, device, prefix, offset, or resulting ID is
                invalid.
        """
        per_device = self._is_per_device(key_type, key_name)
        key_type, key_name = self._canonical_key(key_type, key_name)
        array_name = self.metadata.key_type_to_array[key_type]
        try:
            index = self._indices[array_name][key_name]
        except KeyError as error:
            raise ValueError(f"unknown {key_type} key: {key_name}") from error

        if per_device:
            if device not in self._indices["all_devices"]:
                raise ValueError(f"device {device!r} not found in all_devices")
            try:
                offset = self.config.per_device_offsets[key_type]
            except KeyError as error:
                raise ValueError(
                    f"no per-device offset for {key_type}",
                ) from error
            prefix = (
                self.config.device_prefix_start
                + self._indices["all_devices"][device]
            )
        else:
            try:
                prefix = self.config.key_type_to_prefix[key_type]
            except KeyError as error:
                raise ValueError(f"no shared prefix for {key_type}") from error
            offset = 0
        low_byte = offset + index
        if low_byte > 0xFF:
            raise ValueError(f"key IDs overflow for key type {key_type}")
        return f"0x{(prefix << 8) | low_byte:04x}"

    def _is_per_device_row(self, key_type: str, key_name: str) -> bool:
        return self._is_per_device(key_type, key_name)

    def _row_value(self, key_type: str, key_name: str, device: str) -> str:
        return self.key_id(key_type, key_name, device)

    def _validate_devices(self, devices: Sequence[str]) -> None:
        super()._validate_devices(devices)
        unknown = set(devices) - set(self.metadata.all_devices)
        if unknown:
            raise ValueError(
                f"devices missing from all_devices: {sorted(unknown)}",
            )
