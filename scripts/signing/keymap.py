#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Resolve logical keys from signing metadata to physical key identities.
"""

from __future__ import annotations

import abc
import importlib.util
import sys
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from .metadata import SigningMetadata

_LEGACY_CORE_ALIASES = {
    "bluetooth": "com.android.bluetooth",
    "nfc": "com.android.nfcservices",
}
_LEGACY_APEX_CONTAINER_ALIASES = {
    "com.android.tethering": "releasekey",
    "com.android.support.apexer": "releasekey",
    "com.android.hardware.biometrics.face.virtual": "com.android.hardware",
    "com.android.resolv": "testcert",
    "com.android.bluetooth": "com.android.btservices",
    "com.android.hardware.biometrics.fingerprint.virtual": (
        "com.android.hardware"
    ),
    "com.android.ondevicepersonalization": "releasekey",
    "com.android.vndk.current.on_vendor": "com.android.vndk.current",
    "com.android.scheduling": "releasekey",
    "com.android.hardware.cas": "com.android.hardware",
}
_LEGACY_APEX_PAYLOAD_ALIASES = {
    "com.android.hardware.biometrics.face.virtual": "com.android.hardware",
    "com.android.bluetooth": "com.android.btservices",
    "com.android.hardware.biometrics.fingerprint.virtual": (
        "com.android.hardware"
    ),
    "com.android.vndk.current.on_vendor": "com.android.vndk.current",
    "com.android.hardware.cas": "com.android.hardware",
}
_LEGACY_APEX_APK_ALIASES = {
    "packages/modules/Connectivity/service/"
    "ServiceConnectivityResources/resources-certs/"
    "com.android.connectivity.resources": "com.android.connectivity.resources",
    "packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin": (
        "com.android.hotspot2.osulogin"
    ),
    "packages/modules/Wifi/service/ServiceWifiResources/resources-certs/"
    "com.android.wifi.resources": "com.android.wifi.resources",
    "packages/modules/AdServices/adservices/apk/com.android.adservices.api": (
        "com.android.adservices.api"
    ),
    "packages/modules/Bluetooth/android/app/certs/com.android.bluetooth": (
        "com.android.bluetooth"
    ),
    "packages/modules/Permission/SafetyCenter/Resources/"
    "com.android.safetycenter.resources": "com.android.safetycenter.resources",
    "packages/modules/Wifi/WifiDialog/certs/com.android.wifi.dialog": (
        "com.android.wifi.dialog"
    ),
    "packages/modules/Uwb/service/ServiceUwbResources/resources-certs/"
    "com.android.uwb.resources": "com.android.uwb.resources",
    "packages/modules/Connectivity/nearby/halfsheet/apk-certs/"
    "com.android.nearby.halfsheet": "com.android.nearby.halfsheet",
    "packages/providers/MediaProvider/pdf/apk/com.android.graphics.pdf": (
        "com.android.graphics.pdf"
    ),
    "packages/modules/AppSearch/apk/com.android.appsearch.apk": (
        "com.android.appsearch.apk"
    ),
    "packages/modules/HealthFitness/apk/com.android.healthconnect.controller": (
        "com.android.healthconnect.controller"
    ),
    "packages/modules/HealthFitness/backuprestore/"
    "com.android.health.connect.backuprestore": (
        "com.android.health.connect.backuprestore"
    ),
    "packages/modules/OnDevicePersonalization/federatedcompute/apk/"
    "com.android.federatedcompute": "com.android.federatedcompute",
    "device/google/gs-common/uwb-certs/com.qorvo.uwb": "com.qorvo.uwb",
}
_LEGACY_APP_ALIASES = {
    "prebuilts/calyx/microg/certs/microg": "microg",
    "external/calyx/chromium/certs/chromium": "chromium",
}
_LEGACY_SEPARATE_VBMETA_SYSTEM_DEVICES = frozenset(
    {
        "panther",
        "cheetah",
        "lynx",
        "tangorpro",
        "felix",
        "shiba",
        "husky",
        "akita",
        "tokay",
        "caiman",
        "komodo",
        "comet",
        "tegu",
        "stallion",
    },
)
_LEGACY_QORVO_DEVICES = frozenset({"raven", "cheetah", "tangorpro", "felix"})
_DEVKEY_NAME = "build/make/target/product/security/devkey"
_TESTKEY_NAME = "build/make/target/product/security/testkey"
_RELEASE_KEY_NAMES = frozenset({_TESTKEY_NAME, _DEVKEY_NAME})


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


def normalize_key_dir(environment: MutableMapping[str, str]) -> str:
    """
    Default KEY_DIR to keys/, end it in exactly one slash unless it is
    empty, and return it.

    Args:
        environment: Process environment to read KEY_DIR from and mutate
            in place.

    Returns:
        The normalized KEY_DIR value.
    """
    key_dir = environment.get("KEY_DIR", "keys")
    if key_dir:
        key_dir = key_dir.rstrip("/") + "/"
    environment["KEY_DIR"] = key_dir
    return key_dir


class Keymapper(abc.ABC):
    """
    Resolve logical metadata keys to physical key identities.
    """

    payload_signer_maximum_signature_size: int | None = None

    def key(
        self,
        key_type: str,
        key_name: str,
        device: str = "",
        *,
        suffix: str = "",
        key_suffix: str = ".pem",
    ) -> str:
        """
        Resolve one logical key to its path below KEY_DIR, by default its
        key_id(), followed for avb and apex_payload keys by the suffix
        asked for.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.
            device: Device for per-device keys.
            suffix: Suffix the caller asks for, which a keymapper keeps
                only for the key types whose files carry one.
            key_suffix: Value of KEY_SUFFIX.

        Returns:
            The key's path below KEY_DIR, or an empty string for a key the
            keymapper does not map.

        Raises:
            ValueError: If the keymapper knows no such key, or does not
                assign key IDs.
        """
        del key_suffix
        if key_type not in {"avb", "apex_payload"}:
            suffix = ""
        return f"{self.key_id(key_type, key_name, device)}{suffix}"

    @abc.abstractmethod
    def is_per_device(self, key_type: str, key_name: str) -> bool:
        """
        Return whether a logical key has one key per device.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.

        Returns:
            True for a per-device key, False for a shared one.
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

    def key_id(self, key_type: str, key_name: str, device: str = "") -> str:
        """
        Return the key ID an HSM stores one logical key under.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.
            device: Device for per-device keys.

        Returns:
            The key ID, formatted as ``0xhhhh``.

        Raises:
            ValueError: If the keymapper does not assign key IDs.
        """
        raise ValueError(f"{type(self).__name__} does not assign key IDs")

    def key_id_is_per_device(self, key_id: str) -> bool:
        """
        Return whether a key ID belongs to a per-device key. The YubiHSM
        vendor loads such keys on demand.

        Args:
            key_id: Key ID formatted as ``0xhhhh``.

        Returns:
            True for a per-device key ID.

        Raises:
            ValueError: If the keymapper does not assign key IDs.
        """
        raise ValueError(f"{type(self).__name__} does not assign key IDs")

    def device_key_ids(self, device: str) -> frozenset[str]:
        """
        Return the key IDs of a device's per-device keys, the entry
        device_specific_key_ids_map holds for it.

        Args:
            device: Device name.

        Returns:
            The device's per-device key IDs.

        Raises:
            ValueError: If the keymapper does not assign key IDs.
        """
        return frozenset(
            row.key_id for row in self.rows((device,)) if row.device == device
        )

    def avb_custom_key(self, device: str) -> str:
        """
        Return the AVB public key a factory image flashes as
        avb_custom_key, below KEY_DIR.

        Args:
            device: Device being released.

        Returns:
            The vbmeta key's .avbpubkey file.
        """
        return f"{self.key('avb', 'vbmeta', device)}.avbpubkey"

    def key_dir(self, environment: MutableMapping[str, str]) -> str:
        """
        Apply the keymapper's KEY_DIR export and return the value.

        KEY_DIR defaults to keys/ when unset, and otherwise ends in exactly
        one slash, or stays empty.

        Args:
            environment: Process environment to read KEY_DIR from and
                mutate in place.

        Returns:
            The normalized KEY_DIR value.
        """
        return normalize_key_dir(environment)

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
                    devices if self.is_per_device(key_type, key_name) else ("",)
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


class LegacyKeymapper(_BaseKeymapper):
    """
    Map metadata keys to the historical device/common directory layout.
    """

    def __init__(self, metadata: SigningMetadata) -> None:
        """
        Configure the validated signing metadata.

        Args:
            metadata: Key categories and supported devices to map.

        Returns:
            None.
        """
        self.metadata = metadata

    def is_per_device(self, key_type: str, key_name: str) -> bool:
        return key_type not in {"app", "repo"}

    def _row_value(self, key_type: str, key_name: str, device: str) -> str:
        return self.key_value(key_type, key_name, device)

    def key(
        self,
        key_type: str,
        key_name: str,
        device: str = "",
        *,
        suffix: str = "",
        key_suffix: str = ".pem",
    ) -> str:
        """
        Resolve a key to its path, ignoring the suffix asked for and giving
        avb and apex_payload keys KEY_SUFFIX.
        """
        del suffix
        return self.key_value(key_type, key_name, device, suffix=key_suffix)

    def key_id_is_per_device(self, key_id: str) -> bool:
        """
        Treat every key ID as per-device.
        """
        return True

    def device_key_ids(self, device: str) -> frozenset[str]:
        """
        Refuse, as legacy keys are paths rather than key IDs.
        """
        raise ValueError("LegacyKeymapper does not assign key IDs")

    def avb_custom_key(self, device: str) -> str:
        vbmeta = self.key_value("avb", "vbmeta", device)
        return str(Path(vbmeta).parent / "avb_custom_key.img")

    def key_dir(self, environment: MutableMapping[str, str]) -> str:
        """
        Set KEY_DIR to keys/ and return it.
        """
        environment["KEY_DIR"] = "keys/"
        return "keys/"

    def key_value(
        self,
        key_type: str,
        key_name: str,
        device: str = "",
        *,
        suffix: str = ".pem",
    ) -> str:
        """
        Resolve one logical key to its legacy relative path.

        Args:
            key_type: Metadata key category.
            key_name: Logical key name from that category.
            device: Device name for per-device categories.
            suffix: Suffix of avb and apex_payload keys, like KEY_SUFFIX.

        Returns:
            Relative key path, or an empty string for an inapplicable key.

        Raises:
            ValueError: If the key type is unsupported, or a per-device key
                type is resolved without a device. Any device name is
                accepted.
        """
        if key_type not in {"app", "repo"} and not device:
            raise ValueError(f"device is required for key type: {key_type}")
        if key_type == "other" and key_name == "ota":
            return f"{device}/releasekey"
        if key_type == "avb":
            basename = "avb"
            if (
                key_name == "vbmeta_system"
                and device in _LEGACY_SEPARATE_VBMETA_SYSTEM_DEVICES
            ):
                basename = "avb_vbmeta_system"
            return f"{device}/{basename}{suffix}"
        if key_type == "core":
            basename = Path(key_name).name
            if basename in {"testkey", "devkey"}:
                basename = "releasekey"
            basename = _LEGACY_CORE_ALIASES.get(basename, basename)
            return f"{device}/{basename}"
        if key_type == "apex_container":
            basename = Path(key_name).name
            basename = _LEGACY_APEX_CONTAINER_ALIASES.get(basename, basename)
            return f"{device}/{basename}"
        if key_type == "apex_payload":
            basename = Path(key_name).name
            basename = _LEGACY_APEX_PAYLOAD_ALIASES.get(basename, basename)
            return f"{device}/{basename}{suffix}"
        if key_type == "apex_apk":
            qorvo = "device/google/gs-common/uwb-certs/com.qorvo.uwb"
            if key_name == qorvo and device not in _LEGACY_QORVO_DEVICES:
                return ""
            basename = _LEGACY_APEX_APK_ALIASES.get(key_name, key_name)
            return f"{device}/{basename}"
        if key_type == "app":
            basename = _LEGACY_APP_ALIASES.get(key_name, Path(key_name).name)
            return f"common/{basename}"
        if key_type == "repo":
            return f"common/{Path(key_name).name}"
        raise ValueError(f"unsupported legacy key type: {key_type}")


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
    release_key_name: str = _TESTKEY_NAME


class Id2bKeymapper(_BaseKeymapper):
    """
    Assign deterministic two-byte IDs to configured Android signing keys.
    """

    def __init__(
        self,
        metadata: SigningMetadata,
        *,
        extra_devices: Sequence[str] = (),
    ):
        """
        Create a mapper for a set of metadata.

        Args:
            metadata: Validated key and device configuration.
            extra_devices: Devices outside metadata's all_devices that get
                a per-device key ID slot appended in order, as listed in
                EXTRA_DEVICES. A device already in all_devices
                keeps its index. The appended key IDs depend on the order of
                extra_devices.

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
        all_devices = list(metadata.arrays["all_devices"])
        for device in extra_devices:
            if device and device not in all_devices:
                all_devices.append(device)
        self._indices["all_devices"] = {
            value: index for index, value in enumerate(all_devices) if value
        }
        self._all_devices_count = len(all_devices)
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
        device_count = self._all_devices_count
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

    def is_per_device(self, key_type: str, key_name: str) -> bool:
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
        elif key_type == "core" and key_name in _RELEASE_KEY_NAMES:
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
        elif key_type == "core" and key_name in _RELEASE_KEY_NAMES:
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
        per_device = self.is_per_device(key_type, key_name)
        key_type, key_name = self._canonical_key(key_type, key_name)
        array_name = self.metadata.key_type_to_array[key_type]
        try:
            index = self._indices[array_name][key_name]
        except KeyError as error:
            raise ValueError(f"unknown {key_type} key: {key_name}") from error

        if per_device:
            if device not in self._indices["all_devices"]:
                raise ValueError(
                    f"device {device!r} not found in all_devices "
                    "or extra_devices",
                )
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

    payload_signer_maximum_signature_size = 512

    def _row_value(self, key_type: str, key_name: str, device: str) -> str:
        return self.key_id(key_type, key_name, device)

    def key_id_is_per_device(self, key_id: str) -> bool:
        """
        Return whether the ID falls in the per-device prefix range.
        """
        value = int(key_id, 16)
        return (
            self.config.device_prefix_start << 8
            <= value
            <= (self.config.device_prefix_end << 8 | 0xFF)
        )

    def _validate_devices(self, devices: Sequence[str]) -> None:
        super()._validate_devices(devices)
        unknown = set(devices) - set(self._indices["all_devices"])
        if unknown:
            raise ValueError(
                f"devices missing from all_devices: {sorted(unknown)}",
            )


class StaticKeymapper(Keymapper):
    """
    Map keys through the KEYMAP_FILE keymap generated by
    generate_keymap.sh.
    """

    payload_signer_maximum_signature_size = 512

    def __init__(self, rows: Sequence[KeymapRow]) -> None:
        """
        Configure the keymap rows.

        Args:
            rows: Keymap rows, in file order.

        Returns:
            None.
        """
        self.static_rows = tuple(rows)
        self._rows_by_key: dict[tuple[str, str], list[KeymapRow]] = {}
        for row in self.static_rows:
            self._rows_by_key.setdefault(
                (row.key_type, row.key_name),
                [],
            ).append(row)

    def _key_rows(
        self,
        key_type: str,
        key_name: str,
    ) -> tuple[str, list[KeymapRow]]:
        """
        Return the name the keymap lists a key under, devkey being listed
        as testkey, and the key's rows in file order.
        """
        if key_name == _DEVKEY_NAME:
            key_name = _TESTKEY_NAME
        return key_name, self._rows_by_key.get((key_type, key_name), [])

    @classmethod
    def from_file(cls, keymap_file: Path) -> StaticKeymapper:
        """
        Read a keymapper from a KEYMAP_FILE, skipping its header line and
        empty lines.

        Args:
            keymap_file: Keymap TSV file, header "ID\tDevice\tKey Type\tKey".

        Returns:
            The keymapper over the file's rows.

        Raises:
            ValueError: If a line does not have four tab-separated fields.
        """
        lines = keymap_file.read_text().splitlines()
        rows: list[KeymapRow] = []
        for number, line in enumerate(lines[1:], start=2):
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 4:
                raise ValueError(
                    f"{keymap_file}:{number}: expected four tab-separated "
                    "fields",
                )
            rows.append(KeymapRow(*fields))
        return cls(rows)

    def key_id(self, key_type: str, key_name: str, device: str = "") -> str:
        """
        Return the key ID of the first row whose key_type and key_name
        match and whose device is empty (a shared row) or this device. A
        generated KEYMAP_FILE has at most one such row.

        Raises:
            ValueError: If the keymap has no such row.
        """
        key_name, rows = self._key_rows(key_type, key_name)
        for row in rows:
            if row.device in ("", device):
                return row.key_id
        raise ValueError(
            f"Could not find key type '{key_type}' name '{key_name}' for "
            f"device '{device}' in KEYMAP_FILE",
        )

    def key_id_is_per_device(self, key_id: str) -> bool:
        """
        Return whether a row with this ID names a device.
        """
        return any(
            row.key_id == key_id and row.device for row in self.static_rows
        )

    def is_per_device(self, key_type: str, key_name: str) -> bool:
        """
        Return whether any of the key's rows names a device.

        Raises:
            ValueError: If the keymap has no row for the key.
        """
        key_name, matches = self._key_rows(key_type, key_name)
        if not matches:
            raise ValueError(
                f"Could not find key type '{key_type}' name '{key_name}' "
                "in KEYMAP_FILE",
            )
        return any(row.device for row in matches)

    def rows(self, devices: Sequence[str]) -> tuple[KeymapRow, ...]:
        """
        Return the keymap's shared rows and the rows of the given devices.
        """
        selected = set(devices)
        return tuple(
            sorted(
                row
                for row in self.static_rows
                if not row.device or row.device in selected
            ),
        )


def load_keymapper(
    environment: Mapping[str, str],
    metadata: SigningMetadata,
) -> Keymapper:
    """
    Select the keymapper KEYMAPPER_FILE or KEYMAPPER names.

    KEYMAPPER_FILE names a Python file, relative paths resolving against
    the scripts directory, whose create_keymapper(environment, metadata,
    *, extra_devices) returns an instance of a Keymapper subclass.

    Args:
        environment: Process environment to read KEYMAPPER_FILE, KEYMAPPER,
            KEYMAP_FILE and EXTRA_DEVICES from.
        metadata: Validated signing metadata.

    Returns:
        The KEYMAPPER_FILE keymapper, the legacy keymapper when neither is
        set, or the id2b or static keymapper.

    Raises:
        ValueError: If KEYMAPPER_FILE is not a Python keymapper, or
            KEYMAPPER names no keymapper, or KEYMAPPER=static comes without
            KEYMAP_FILE or with one that does not exist.
    """
    extra_devices = environment.get("EXTRA_DEVICES", "").split()
    keymapper_file = environment.get("KEYMAPPER_FILE", "")
    name = keymapper_file or environment.get("KEYMAPPER") or "legacy"
    keymapper: Keymapper
    if keymapper_file:
        keymapper = _load_keymapper_file(
            Path(keymapper_file),
            environment,
            metadata,
            extra_devices,
        )
    elif name == "legacy":
        keymapper = LegacyKeymapper(metadata)
    elif name == "id2b":
        keymapper = Id2bKeymapper(metadata, extra_devices=extra_devices)
    elif name == "static":
        keymap_file = environment.get("KEYMAP_FILE", "")
        if not keymap_file:
            raise ValueError(
                "Please set KEYMAP_FILE to a tab-separated values file "
                "generated by generate_keymap.sh",
            )
        if not Path(keymap_file).exists():
            raise ValueError(f"Cannot find KEYMAP_FILE {keymap_file}")
        keymapper = StaticKeymapper.from_file(Path(keymap_file))
    else:
        raise ValueError(f"Could not find keymapper '{name}'.")
    print(f"Using keymapper: {name}", file=sys.stderr)
    return keymapper


def _load_keymapper_file(
    path: Path,
    environment: Mapping[str, str],
    metadata: SigningMetadata,
    extra_devices: Sequence[str],
) -> Keymapper:
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    if path.suffix != ".py":
        raise ValueError(
            f"KEYMAPPER_FILE {path} is not a Python keymapper (*.py).",
        )
    if not path.is_file():
        raise ValueError(f"Could not find KEYMAPPER_FILE {path}.")
    spec = importlib.util.spec_from_file_location("_signing_keymapper", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot import KEYMAPPER_FILE {path}.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        del sys.modules[spec.name]
        raise ValueError(
            f"Cannot load KEYMAPPER_FILE {path} ({error}).",
        ) from error
    create = getattr(module, "create_keymapper", None)
    if create is None:
        raise ValueError(
            f"KEYMAPPER_FILE {path} does not define create_keymapper().",
        )
    try:
        keymapper = create(environment, metadata, extra_devices=extra_devices)
    except Exception as error:
        raise ValueError(
            f"create_keymapper() in KEYMAPPER_FILE {path} failed ({error}).",
        ) from error
    if not isinstance(keymapper, Keymapper):
        raise ValueError(
            f"create_keymapper() in KEYMAPPER_FILE {path} returned "
            f"{type(keymapper).__name__}, not a Keymapper.",
        )
    return keymapper


def apply_keymapper_exports(
    environment: MutableMapping[str, str],
    keymapper: Keymapper,
) -> None:
    """
    Set KEY_DIR, and PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE for a keymapper
    that sets one, before prepare_signing_args() runs.

    Args:
        environment: Process environment to mutate in place.
        keymapper: The release's keymapper.

    Returns:
        None.
    """
    keymapper.key_dir(environment)
    size = keymapper.payload_signer_maximum_signature_size
    if size is not None:
        environment["PAYLOAD_SIGNER_MAXIMUM_SIGNATURE_SIZE"] = str(size)
