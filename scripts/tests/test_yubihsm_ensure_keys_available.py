#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import (
    YUBIHSM_WRAP_ID,
    back_up_yubihsm_key,
    plug_yubihsm,
    yubihsm_config,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signing.keymap import StaticKeymapper
from signing.sign_environment import YubiHsmVendor
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    ensure_keys_are_available,
    restore_all_keys,
)
from yubihsm.defs import CAPABILITY, COMMAND, ERROR, OBJECT
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
    self_signed_certificate,
)

EXPORTABLE_DOMAIN = 0b001
UNEXPORTABLE_DOMAIN = 0b010
ONDEMAND_DOMAIN = 0b100
ONDEMAND_DOMAINS = EXPORTABLE_DOMAIN | ONDEMAND_DOMAIN
KEY_CAPABILITIES = CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP
OPAQUE_CAPABILITIES = CAPABILITY.GET_OPAQUE | CAPABILITY.EXPORTABLE_UNDER_WRAP


def _key(
    device: EmulatedYubiHsm,
    key_dir: Path,
    object_id: int,
    *,
    domains: int = ONDEMAND_DOMAINS,
    loaded: bool = True,
    backed_up: bool = True,
) -> rsa.RSAPrivateKey:
    key = device.put_asymmetric_key(
        object_id,
        domains=domains,
        capabilities=KEY_CAPABILITIES,
    )
    if backed_up:
        back_up_yubihsm_key(device, key_dir, object_id)
    if not loaded:
        del device.objects[(object_id, OBJECT.ASYMMETRIC_KEY)]
    return key


def _certificate(
    device: EmulatedYubiHsm,
    key_dir: Path,
    object_id: int,
    *,
    domains: int = ONDEMAND_DOMAINS,
    loaded: bool = True,
    backed_up: bool = True,
) -> x509.Certificate:
    certificate = self_signed_certificate()
    if loaded:
        device.put_certificate(
            object_id,
            certificate,
            domains=domains,
            capabilities=OPAQUE_CAPABILITIES,
        )
    if backed_up:
        (key_dir / f"{object_id:#06x}.x509.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM),
        )
    return certificate


def _backup_path(key_dir: Path, object_id: int) -> Path:
    return key_dir / f"{object_id:#06x}-asymmetric-key.yhw"


def _stored(device: EmulatedYubiHsm) -> set[tuple[int, OBJECT]]:
    return {
        (object_id, object_type)
        for object_id, object_type in device.objects
        if object_type in (OBJECT.ASYMMETRIC_KEY, OBJECT.OPAQUE)
    }


def _changes(device: EmulatedYubiHsm) -> list[tuple[COMMAND, int]]:
    """
    Return the device's successful deletes and imports, each with the ID
    of the object it deleted or created.
    """
    changes: list[tuple[COMMAND, int]] = []
    for command, (target, second) in device.history:
        if command in (COMMAND.DELETE_OBJECT, COMMAND.PUT_OPAQUE):
            changes.append((COMMAND(command), target))
        elif command == COMMAND.IMPORT_WRAPPED:
            changes.append((COMMAND.IMPORT_WRAPPED, second))
    return changes


def _assert_restored(
    device: EmulatedYubiHsm,
    object_id: int,
    key: rsa.RSAPrivateKey,
) -> None:
    restored = device.get(object_id, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    restored_key = serialization.load_der_private_key(restored.data, None)
    assert isinstance(restored_key, rsa.RSAPrivateKey)
    assert (
        restored_key.public_key().public_numbers()
        == key.public_key().public_numbers()
    )


def _ensure(
    yubihsm: Connector,
    key_dir: Path,
    *key_ids: str,
    is_ondemand: Callable[[int], bool] = lambda object_id: True,
    lookup_domains: str = "3",
    after_key: Callable[[str], None] | None = None,
) -> None:
    ensure_keys_are_available(
        yubihsm_config(yubihsm),
        key_dir,
        key_ids,
        is_ondemand=is_ondemand,
        lookup_domains=lookup_domains,
        after_key=after_key,
    )


@pytest.mark.parametrize(
    "certificate",
    ["loaded", "on disk", "absent"],
)
def test_already_loaded_key_is_a_noop_whatever_its_certificate(
    yubihsm: Connector,
    tmp_path: Path,
    certificate: str,
) -> None:
    device = plug_yubihsm(yubihsm)
    _key(device, tmp_path, 0x2000, backed_up=False)
    if certificate != "absent":
        _certificate(device, tmp_path, 0x2000, loaded=certificate == "loaded")

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []
    assert (0x2000, OBJECT.ASYMMETRIC_KEY) in _stored(device)


def test_loaded_key_needs_no_room_for_its_certificate(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=1 + 1)
    _key(device, tmp_path, 0x2000)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []
    assert _stored(device) == {(0x2000, OBJECT.ASYMMETRIC_KEY)}


def test_imports_missing_key_but_not_its_certificate(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    key = _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == [(COMMAND.IMPORT_WRAPPED, 0x2000)]
    assert _stored(device) == {(0x2000, OBJECT.ASYMMETRIC_KEY)}
    _assert_restored(device, 0x2000, key)
    restored = device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    assert restored.domains == ONDEMAND_DOMAINS
    assert restored.capabilities == KEY_CAPABILITIES


def test_evicts_candidate_with_its_certificate_when_space_is_needed(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x2000 lies below the middle of the on-demand objects, so the
    candidate moves on to the last eligible key, 0x2002. Its certificate
    goes with it once 0x2000 has loaded. The certificate of 0x2003, whose
    key is not loaded, is not evicted, and 0x2000's is not imported.
    """
    device = plug_yubihsm(yubihsm, free_records=4 + 1)
    key = _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2003)
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x2002),
    ]
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2001, OBJECT.ASYMMETRIC_KEY),
        (0x2003, OBJECT.OPAQUE),
    }
    _assert_restored(device, 0x2000, key)


def test_a_failed_certificate_delete_leaves_the_new_key_loaded(
    yubihsm: Connector,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import signing.vendor_yubihsm as vendor_yubihsm

    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    delete_object = vendor_yubihsm.delete_object

    def fail_on_certificates(
        config: YubiHsmConfig,
        object_id: int,
        object_type: OBJECT,
    ) -> None:
        if object_type == OBJECT.OPAQUE:
            raise YubiHsmDeviceError(ERROR.INVALID_DATA)
        delete_object(config, object_id, object_type)

    monkeypatch.setattr(vendor_yubihsm, "delete_object", fail_on_certificates)
    loaded: list[str] = []

    _ensure(yubihsm, tmp_path, "0x2000", after_key=loaded.append)

    assert loaded == ["0x2000"]
    assert (0x2002, OBJECT.OPAQUE) in _stored(device)
    assert "could not delete the certificate of evicted key 0x2002" in (
        capsys.readouterr().err
    )


def test_evicted_key_keeps_a_certificate_without_a_backup(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002, backed_up=False)
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
    ]
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }


@pytest.mark.parametrize("spoil", ["not-base64", "truncated"])
def test_undecodable_backup_fails_before_evicting(
    yubihsm: Connector,
    tmp_path: Path,
    spoil: str,
) -> None:
    """
    A backup of the key being loaded that does not decode fails before
    an on-demand object is evicted to make room for it.
    """
    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    backup = _backup_path(tmp_path, 0x2000)
    backup.write_bytes(
        b"\xf3raw" if spoil == "not-base64" else backup.read_bytes()[:-3],
    )
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(ValueError, match="not a base64 wrapped-key backup"):
        _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []
    assert _stored(device) == {
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }


def test_candidate_with_unreadable_backup_is_not_evicted(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x3000 lies above the middle of the on-demand objects, so the first
    eligible key is evicted. The key backup of 0x2001 is not base64, so
    its key cannot be loaded again later and stays with its certificate,
    and the key of 0x2002 goes in its place.
    """
    device = plug_yubihsm(yubihsm, free_records=4 + 1)
    _key(device, tmp_path, 0x3000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _certificate(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    _backup_path(tmp_path, 0x2001).write_bytes(b"\xf3raw")
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x3000")

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x3000),
        (COMMAND.DELETE_OBJECT, 0x2002),
    ]
    assert _stored(device) == {
        (0x2001, OBJECT.ASYMMETRIC_KEY),
        (0x2001, OBJECT.OPAQUE),
        (0x3000, OBJECT.ASYMMETRIC_KEY),
    }


def test_raises_when_space_needed_and_no_eviction_candidate(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A certificate whose key is not loaded is no candidate either.
    """
    device = plug_yubihsm(yubihsm, free_records=1 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2001)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand key"):
        _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []
    assert _stored(device) == {(0x2001, OBJECT.OPAQUE)}


def test_raises_when_key_backup_missing(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _certificate(device, tmp_path, 0x2000, loaded=False)

    with pytest.raises(RuntimeError, match="could not find a wrapped copy"):
        _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []


def test_evicts_lowest_id_candidate_when_own_id_is_above_middle(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x2000 lies above the middle of the on-demand objects, so the first
    eligible key is evicted, the mirror image of
    test_evicts_candidate_with_its_certificate_when_space_is_needed().
    """
    device = plug_yubihsm(yubihsm, free_records=3 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x1000)
    _key(device, tmp_path, 0x1001)
    _certificate(device, tmp_path, 0x1000)
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x1000),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x1000),
    ]
    assert _stored(device) == {
        (0x1001, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.ASYMMETRIC_KEY),
    }


def test_restores_a_non_ondemand_key_in_the_exportable_domain(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    key = _key(
        device,
        tmp_path,
        0x2000,
        domains=EXPORTABLE_DOMAIN,
        loaded=False,
    )
    _certificate(device, tmp_path, 0x2000, loaded=False)

    _ensure(
        yubihsm,
        tmp_path,
        "0x2000",
        is_ondemand=lambda object_id: False,
        lookup_domains="1,3",
    )

    assert _changes(device) == [(COMMAND.IMPORT_WRAPPED, 0x2000)]
    _assert_restored(device, 0x2000, key)
    restored = device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    assert restored.domains == EXPORTABLE_DOMAIN


def test_object_outside_the_ondemand_domain_is_not_counted_as_loaded(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A key stored in a domain outside lookup_domains is loaded again,
    which the device refuses since the ID is taken.
    """
    device = plug_yubihsm(yubihsm)
    _key(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)

    with pytest.raises(YubiHsmDeviceError) as raised:
        _ensure(yubihsm, tmp_path, "0x2000")

    assert raised.value.code == ERROR.OBJECT_EXISTS
    assert _changes(device) == []


def test_counts_objects_in_every_lookup_domain(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _key(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)

    _ensure(yubihsm, tmp_path, "0x2000", lookup_domains="1,3")

    assert _changes(device) == []


def test_object_outside_the_ondemand_domain_is_not_evicted(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001, domains=UNEXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2001, domains=UNEXPORTABLE_DOMAIN)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand key"):
        _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == []
    assert _stored(device) == {
        (0x2001, OBJECT.ASYMMETRIC_KEY),
        (0x2001, OBJECT.OPAQUE),
    }


def test_eviction_skips_objects_outside_the_ondemand_domain(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x2003 would be the highest eligible ID, but it sits in the
    unexportable domain alone, so the only on-demand key, 0x2001, is
    evicted with its certificate instead.
    """
    device = plug_yubihsm(yubihsm, free_records=4 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _certificate(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2003, domains=UNEXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2003, domains=UNEXPORTABLE_DOMAIN)
    assert device.storage()[0] == 1

    _ensure(yubihsm, tmp_path, "0x2000")

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2001),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x2001),
    ]
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2003, OBJECT.ASYMMETRIC_KEY),
        (0x2003, OBJECT.OPAQUE),
    }


def test_load_is_refused_when_the_device_rejects_the_import(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _key(device, tmp_path, 0x2000, loaded=False)
    device.fail_next(COMMAND.IMPORT_WRAPPED, ERROR.INVALID_DATA)

    with pytest.raises(YubiHsmDeviceError) as raised:
        _ensure(yubihsm, tmp_path, "0x2000")

    assert raised.value.code == ERROR.INVALID_DATA
    assert _changes(device) == []
    assert _stored(device) == set()


def test_failed_import_loads_the_evicted_key_again(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A backup cut short that still decodes is evicted for, and the device
    then refuses to unwrap it. The evicted key is loaded again from its
    backup before the error is raised, and its certificate stays.
    """
    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    backup = _backup_path(tmp_path, 0x2000)
    backup.write_bytes(
        base64.b64encode(base64.b64decode(backup.read_bytes())[:-16]),
    )
    evicted = _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(YubiHsmDeviceError) as raised:
        _ensure(yubihsm, tmp_path, "0x2000")

    assert raised.value.code == ERROR.INVALID_DATA
    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x2002),
    ]
    assert _stored(device) == {
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }
    _assert_restored(device, 0x2002, evicted)


def test_backup_of_another_key_leaves_no_object_behind(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A backup holding another key's blob imports that key, which is
    deleted again, and the key evicted to make room is loaded again.
    """
    device = plug_yubihsm(yubihsm, free_records=2 + 1)
    _key(device, tmp_path, 0x2004, loaded=False)
    _backup_path(tmp_path, 0x2000).write_bytes(
        _backup_path(tmp_path, 0x2004).read_bytes(),
    )
    evicted = _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(ValueError, match="does not match expected key id"):
        _ensure(yubihsm, tmp_path, "0x2000")

    assert _stored(device) == {
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }
    _assert_restored(device, 0x2002, evicted)


def _write_keymap(path: Path, rows: list[tuple[str, str, str, str]]) -> None:
    lines = ["ID\tDevice\tKey Type\tKey"]
    lines.extend("\t".join(row) for row in rows)
    path.write_text("\n".join(lines) + "\n")


def _audit_loads(device: EmulatedYubiHsm) -> None:
    """
    Log every key and certificate import, with the log read up to now.
    """
    device.audit(COMMAND.IMPORT_WRAPPED, COMMAND.PUT_OPAQUE)
    device.log_index = device.log[-1][0]


def _restore(yubihsm: Connector, key_dir: Path, log_file: Path) -> None:
    restore_all_keys(
        yubihsm_config(yubihsm),
        key_dir,
        log_file,
        is_ondemand=lambda object_id: True,
        exportable_domain="1",
        ondemand_domain="3",
    )


def _audit_log_sections(log_file: Path) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    for line in log_file.read_text().splitlines():
        if line.startswith("# "):
            sections.append((line.split(" ", 2)[2], []))
        else:
            sections[-1][1].append(line)
    return sections


def _assert_load_entry(entries: list[str], object_id: int) -> None:
    (import_entry,) = entries
    assert f"cmd: {COMMAND.IMPORT_WRAPPED:#04x}" in import_entry
    assert f"tKey: {YUBIHSM_WRAP_ID:#06x}" in import_entry
    assert f"2Key: {object_id:#06x}" in import_entry


def _vendor_environment(yubihsm: Connector, key_dir: Path) -> dict[str, str]:
    return {
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": f"{DEFAULT_AUTHKEY_ID:#06x}",
        "YUBIHSM_PASSWORD": DEFAULT_PASSWORD,
        "YUBIHSM_WRAP_KEY_ID": f"{YUBIHSM_WRAP_ID:#06x}",
        "YUBIHSM_ONDEMAND_DOMAIN": "3",
        "KEY_DIR": str(key_dir),
        "DRY_RUN": "y",
    }


def test_split_devices_partitions_by_key_availability(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _key(device, tmp_path, 0x1000, backed_up=False)
    _certificate(device, tmp_path, 0x1000, backed_up=False)
    _key(device, tmp_path, 0x1001, backed_up=False)
    _certificate(device, tmp_path, 0x1002, backed_up=False)
    keymap_file = tmp_path / "keymap.tsv"
    _write_keymap(
        keymap_file,
        [
            ("0x1000", "bramble", "avb", "vbmeta"),
            ("0x1001", "uncertified", "avb", "vbmeta"),
            ("0x1002", "certified-only", "avb", "vbmeta"),
            ("0x1003", "missing", "avb", "vbmeta"),
        ],
    )

    with_loaded, without_loaded = YubiHsmVendor().split_devices_by_loaded_keys(
        _vendor_environment(yubihsm, tmp_path),
        StaticKeymapper.from_file(keymap_file),
        ["bramble", "uncertified", "certified-only", "missing"],
    )

    assert with_loaded == ("bramble", "uncertified")
    assert without_loaded == ("certified-only", "missing")


def test_split_devices_rejects_a_device_without_keymap_rows(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    plug_yubihsm(yubihsm)
    keymap_file = tmp_path / "keymap.tsv"
    _write_keymap(keymap_file, [])

    with pytest.raises(RuntimeError, match="has no keys for unknown-device"):
        YubiHsmVendor().split_devices_by_loaded_keys(
            _vendor_environment(yubihsm, tmp_path),
            StaticKeymapper.from_file(keymap_file),
            ["unknown-device"],
        )


def test_ensure_keys_for_devices_unions_multiple_devices(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    keys = {
        object_id: _key(device, tmp_path, object_id, loaded=False)
        for object_id in (0x2000, 0x2001)
    }
    for object_id in keys:
        _certificate(device, tmp_path, object_id, loaded=False)
    keymap_file = tmp_path / "keymap.tsv"
    _write_keymap(
        keymap_file,
        [
            ("0x2000", "bramble", "avb", "vbmeta"),
            ("0x2001", "redfin", "avb", "vbmeta"),
        ],
    )

    YubiHsmVendor().ensure_keys_for_devices(
        _vendor_environment(yubihsm, tmp_path),
        StaticKeymapper.from_file(keymap_file),
        ["bramble", "redfin"],
    )

    assert _stored(device) == {
        (object_id, OBJECT.ASYMMETRIC_KEY) for object_id in keys
    }
    for object_id, key in keys.items():
        _assert_restored(device, object_id, key)


def test_restore_all_keys_logs_each_key_as_it_is_restored(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _audit_loads(device)
    audit_log = tmp_path / "audit.log"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    for object_id in (0x3000, 0x3001):
        _key(device, key_dir, object_id, loaded=False)
        _certificate(device, key_dir, object_id, loaded=False)

    _restore(yubihsm, key_dir, audit_log)

    assert _stored(device) == {
        (object_id, OBJECT.ASYMMETRIC_KEY) for object_id in (0x3000, 0x3001)
    }
    sections = _audit_log_sections(audit_log)
    assert [comment for comment, _ in sections] == [
        "Function: ensure_key_is_available Result: 0",
        "Function: ensure_key_is_available Result: 0",
        "Function: restore_all_keys Result: 0",
    ]
    _assert_load_entry(sections[0][1], 0x3000)
    _assert_load_entry(sections[1][1], 0x3001)
    assert sections[2][1] == []
    assert device.unread_log() == []


def test_restore_all_keys_skips_a_certificate_without_a_key_backup(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    _certificate(device, key_dir, 0x3002, loaded=False)

    _restore(yubihsm, key_dir, tmp_path / "audit.log")

    assert _changes(device) == []
    assert _stored(device) == set()


def test_restore_all_keys_restores_keys_in_id_order(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    for object_id in (0x3002, 0x3000):
        _key(device, key_dir, object_id, loaded=False)
        _certificate(device, key_dir, object_id, loaded=False)
    _key(device, key_dir, 0x3001, loaded=False)

    _restore(yubihsm, key_dir, tmp_path / "audit.log")

    assert _changes(device) == [
        (COMMAND.IMPORT_WRAPPED, 0x3000),
        (COMMAND.IMPORT_WRAPPED, 0x3001),
        (COMMAND.IMPORT_WRAPPED, 0x3002),
    ]


def test_restore_all_keys_extracts_log_even_on_failure(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm, free_records=1)
    _audit_loads(device)
    audit_log = tmp_path / "audit.log"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    _key(device, key_dir, 0x3003, loaded=False)
    _certificate(device, key_dir, 0x3003, loaded=False)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand key"):
        _restore(yubihsm, key_dir, audit_log)

    assert _audit_log_sections(audit_log) == [
        ("Function: ensure_key_is_available Result: 1", []),
        ("Function: restore_all_keys Result: 1", []),
    ]
    assert _changes(device) == []


def test_restore_all_keys_reports_failure_when_logging_a_key_fails(
    monkeypatch: pytest.MonkeyPatch,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    The device cannot make writing the log file fail, so the per-key
    extraction raises in its place. The entries it left unread are
    written with the closing comment, which reports the failure.
    """
    import signing.vendor_yubihsm as vendor_yubihsm

    device = plug_yubihsm(yubihsm)
    _audit_loads(device)
    audit_log = tmp_path / "audit.log"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    _key(device, key_dir, 0x3000, loaded=False)
    _certificate(device, key_dir, 0x3000, loaded=False)
    comments: list[str] = []
    extract_and_save = vendor_yubihsm.extract_and_save_audit_log

    def extract(
        hsm_config: YubiHsmConfig,
        log_file: Path,
        comment: str,
    ) -> None:
        comments.append(comment)
        if comment.startswith("Function: ensure_key_is_available"):
            raise OSError("audit log unavailable")
        extract_and_save(hsm_config, log_file, comment)

    monkeypatch.setattr(vendor_yubihsm, "extract_and_save_audit_log", extract)

    with pytest.raises(OSError, match="audit log unavailable"):
        _restore(yubihsm, key_dir, audit_log)

    assert comments == [
        "Function: ensure_key_is_available Result: 0",
        "Function: restore_all_keys Result: 1",
    ]
    sections = _audit_log_sections(audit_log)
    assert [comment for comment, _ in sections] == [
        "Function: restore_all_keys Result: 1",
    ]
    _assert_load_entry(sections[0][1], 0x3000)
    assert device.unread_log() == []


def test_restore_all_keys_reports_failure_when_reading_the_log_fails(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = plug_yubihsm(yubihsm)
    _audit_loads(device)
    audit_log = tmp_path / "audit.log"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    _key(device, key_dir, 0x3000, loaded=False)
    _certificate(device, key_dir, 0x3000, loaded=False)
    device.fail_next(COMMAND.GET_LOG_ENTRIES, ERROR.INVALID_DATA)

    with pytest.raises(YubiHsmDeviceError) as raised:
        _restore(yubihsm, key_dir, audit_log)

    assert raised.value.code == ERROR.INVALID_DATA
    sections = _audit_log_sections(audit_log)
    assert [comment for comment, _ in sections] == [
        "Function: restore_all_keys Result: 1",
    ]
    _assert_load_entry(sections[0][1], 0x3000)
    assert device.unread_log() == []
