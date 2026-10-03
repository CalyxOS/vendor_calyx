#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
from collections.abc import Callable
from pathlib import Path
from typing import NotRequired, TypedDict, Unpack

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from signing.vendor_yubihsm import (
    YubiHsmConfig,
    ensure_keys_are_available,
)
from yubihsm.defs import CAPABILITY, COMMAND, ERROR, OBJECT
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm_emulator import (
    DEFAULT_AUTHKEY_ID,
    DEFAULT_PASSWORD,
    Connector,
    EmulatedYubiHsm,
)

WRAP_ID = 0x0010
EXPORTABLE_DOMAIN = 0b001
UNEXPORTABLE_DOMAIN = 0b010
ONDEMAND_DOMAIN = 0b100
ONDEMAND_DOMAINS = EXPORTABLE_DOMAIN | ONDEMAND_DOMAIN
KEY_CAPABILITIES = CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORTABLE_UNDER_WRAP
OPAQUE_CAPABILITIES = CAPABILITY.GET_OPAQUE | CAPABILITY.EXPORTABLE_UNDER_WRAP
FIXED_RECORDS = 2


def _self_signed_certificate() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def config(yubihsm: Connector) -> YubiHsmConfig:
    return YubiHsmConfig(
        connector_url=yubihsm.url,
        auth_key=f"{DEFAULT_AUTHKEY_ID:#06x}",
        password=DEFAULT_PASSWORD,
        wrap_id=f"{WRAP_ID:#06x}",
    )


def _plug(yubihsm: Connector, *, total_records: int = 256) -> EmulatedYubiHsm:
    """
    Plug in a fresh device holding the default authentication key and
    the wrap key, FIXED_RECORDS objects in all.
    """
    device = EmulatedYubiHsm(total_records=total_records)
    device.put_wrap_key(WRAP_ID)
    yubihsm.plug(device)
    return device


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
        wrapped = device.wrapped(object_id, OBJECT.ASYMMETRIC_KEY, WRAP_ID)
        _backup_path(key_dir, object_id).write_bytes(base64.b64encode(wrapped))
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
    certificate = _self_signed_certificate()
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
    for _, command, (target, second) in device.history:
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


def _assert_certificate(
    device: EmulatedYubiHsm,
    object_id: int,
    certificate: x509.Certificate,
    *,
    domains: int,
    capabilities: int,
) -> None:
    stored = device.get(object_id, OBJECT.OPAQUE)
    assert stored is not None
    assert stored.data == certificate.public_bytes(serialization.Encoding.DER)
    assert stored.domains == domains
    assert stored.capabilities == capabilities


class _EnsureKwargs(TypedDict):
    restore_mode: bool
    is_ondemand: Callable[[int], bool]
    verify_key_ids: NotRequired[bool]
    exportable_domain: str
    ondemand_domain: str
    opaque_capabilities: str


class _EnsureOverrides(TypedDict, total=False):
    restore_mode: bool
    is_ondemand: Callable[[int], bool]
    verify_key_ids: bool
    exportable_domain: str
    ondemand_domain: str
    opaque_capabilities: str


def _kwargs(**overrides: Unpack[_EnsureOverrides]) -> _EnsureKwargs:
    base = _EnsureKwargs(
        restore_mode=False,
        is_ondemand=lambda object_id: True,
        exportable_domain="1",
        ondemand_domain="3",
        opaque_capabilities="get-opaque",
    )
    base.update(overrides)
    return base


def test_already_loaded_key_and_cert_is_a_noop(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000)
    _certificate(device, tmp_path, 0x2000)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == []
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.OPAQUE),
    }


def test_imports_missing_key_when_space_is_sufficient(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    key = _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == [(COMMAND.IMPORT_WRAPPED, 0x2000)]
    _assert_restored(device, 0x2000, key)
    restored = device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert restored is not None
    assert restored.domains == ONDEMAND_DOMAINS
    assert restored.capabilities == KEY_CAPABILITIES


def test_evicts_candidate_when_space_is_needed(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x2000 lies below the middle of the on-demand objects, so each
    candidate moves on to the next eligible ID of its type until both a
    key and a certificate are found. The key of 0x2002 replaces that of
    0x2001 before the certificate of 0x2003 ends the search.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 3 + 1)
    key = _key(device, tmp_path, 0x2000, loaded=False)
    certificate = _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2003)
    assert device.storage()[0] == 1

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x2003),
        (COMMAND.PUT_OPAQUE, 0x2000),
    ]
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.OPAQUE),
        (0x2001, OBJECT.ASYMMETRIC_KEY),
    }
    _assert_restored(device, 0x2000, key)
    _assert_certificate(
        device,
        0x2000,
        certificate,
        domains=ONDEMAND_DOMAINS,
        capabilities=OPAQUE_CAPABILITIES,
    )


def test_unreadable_backup_fails_before_evicting(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A malformed backup of the key being loaded fails before an
    on-demand object is evicted to make room for it.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    _backup_path(tmp_path, 0x2000).write_bytes(b"\xf3raw")
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(ValueError, match="not a base64 wrapped-key backup"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert _changes(device) == []
    assert _stored(device) == {
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }


def test_truncated_backup_fails_before_evicting(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    A backup cut short partway through its base64 text is refused while
    decoding, before the on-demand object is evicted to make room.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    backup = _backup_path(tmp_path, 0x2000)
    backup.write_bytes(backup.read_bytes()[:-3])
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(ValueError, match="not a base64 wrapped-key backup"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

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
    eligible candidate of each type is evicted. The key backup of 0x2001
    is not base64, so its key cannot be loaded again later and stays,
    and the key of 0x2002 goes in its place.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 4 + 1)
    _key(device, tmp_path, 0x3000, loaded=False)
    _certificate(device, tmp_path, 0x3000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _certificate(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    _backup_path(tmp_path, 0x2001).write_bytes(b"\xf3raw")
    assert device.storage()[0] == 1

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x3000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2002),
        (COMMAND.IMPORT_WRAPPED, 0x3000),
        (COMMAND.DELETE_OBJECT, 0x2001),
        (COMMAND.PUT_OPAQUE, 0x3000),
    ]
    assert _stored(device) == {
        (0x2001, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
        (0x3000, OBJECT.ASYMMETRIC_KEY),
        (0x3000, OBJECT.OPAQUE),
    }


def test_raises_when_space_needed_and_no_eviction_candidate(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand key"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert _changes(device) == []
    assert _stored(device) == set()


def test_raises_when_backup_missing_outside_restore_mode(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)

    with pytest.raises(RuntimeError, match="could not find a wrapped copy"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False, restore_mode=False),
        )

    assert _changes(device) == []


def test_restore_mode_skips_missing_key_but_still_imports_cert(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    certificate = _certificate(device, tmp_path, 0x2000, loaded=False)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False, restore_mode=True),
    )

    assert _changes(device) == [(COMMAND.PUT_OPAQUE, 0x2000)]
    _assert_certificate(
        device,
        0x2000,
        certificate,
        domains=ONDEMAND_DOMAINS,
        capabilities=OPAQUE_CAPABILITIES,
    )


def test_restore_mode_raises_when_neither_piece_is_on_disk(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)

    with pytest.raises(RuntimeError, match="Failed to find any on-disk"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False, restore_mode=True),
        )

    assert _changes(device) == []


def test_restore_mode_raises_when_only_a_loaded_key_has_no_cert_backup(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, backed_up=False)

    with pytest.raises(RuntimeError, match="Failed to find any on-disk"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False, restore_mode=True),
        )

    assert _changes(device) == []


def test_raises_when_cert_backup_missing_outside_restore_mode(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    With the key already loaded, the key checks pass and the missing
    certificate backup is what fails.
    """
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, backed_up=False)

    with pytest.raises(RuntimeError, match="could not find it on disk"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False, restore_mode=False),
        )

    assert _changes(device) == []


def test_raises_when_space_needed_and_no_cert_eviction_candidate(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    With the key already loaded, no key needs evicting, which isolates
    the search for a certificate to evict.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 1 + 1)
    _key(device, tmp_path, 0x2000)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand cert"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert _changes(device) == []
    assert _stored(device) == {(0x2000, OBJECT.ASYMMETRIC_KEY)}


def test_evicts_lowest_id_candidate_when_own_id_is_above_middle(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    0x2000 lies above the middle of the on-demand objects, so the first
    eligible candidate of each type is evicted, the mirror image of
    test_evicts_candidate_when_space_is_needed().
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 3 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x1000)
    _key(device, tmp_path, 0x1001)
    _certificate(device, tmp_path, 0x1000)
    assert device.storage()[0] == 1

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x1000),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x1000),
        (COMMAND.PUT_OPAQUE, 0x2000),
    ]
    assert _stored(device) == {
        (0x1001, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.OPAQUE),
    }


def test_verify_key_ids_filters_out_non_ondemand_outside_restore_mode(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(is_ondemand=lambda object_id: False, restore_mode=False),
    )

    assert _changes(device) == []
    assert _stored(device) == set()


def test_verify_key_ids_keeps_exportable_non_ondemand_in_restore_mode(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    key = _key(
        device,
        tmp_path,
        0x2000,
        domains=EXPORTABLE_DOMAIN,
        loaded=False,
    )
    certificate = _certificate(device, tmp_path, 0x2000, loaded=False)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(
            is_ondemand=lambda object_id: False,
            restore_mode=True,
        ),
    )

    assert _changes(device) == [
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.PUT_OPAQUE, 0x2000),
    ]
    _assert_restored(device, 0x2000, key)
    _assert_certificate(
        device,
        0x2000,
        certificate,
        domains=EXPORTABLE_DOMAIN,
        capabilities=OPAQUE_CAPABILITIES,
    )


def test_object_outside_the_ondemand_domain_is_not_counted_as_loaded(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    """
    Outside restore mode only the on-demand domain is searched, so a key
    and certificate stored in the exportable domain alone are loaded
    again, which the device refuses since both IDs are taken.
    """
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)

    with pytest.raises(YubiHsmDeviceError) as raised:
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert raised.value.code == ERROR.OBJECT_EXISTS
    assert _changes(device) == []


def test_restore_mode_also_counts_objects_in_the_exportable_domain(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2000, domains=EXPORTABLE_DOMAIN)

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False, restore_mode=True),
    )

    assert _changes(device) == []


def test_object_outside_the_ondemand_domain_is_not_evicted(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001, domains=UNEXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2001, domains=UNEXPORTABLE_DOMAIN)
    assert device.storage()[0] == 1

    with pytest.raises(RuntimeError, match="Could not find any on-demand key"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

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
    unexportable domain alone, so the only on-demand object, 0x2001, is
    evicted instead.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 4 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2001)
    _certificate(device, tmp_path, 0x2001)
    _key(device, tmp_path, 0x2003, domains=UNEXPORTABLE_DOMAIN)
    _certificate(device, tmp_path, 0x2003, domains=UNEXPORTABLE_DOMAIN)
    assert device.storage()[0] == 1

    ensure_keys_are_available(
        config(yubihsm),
        tmp_path,
        ["0x2000"],
        **_kwargs(verify_key_ids=False),
    )

    assert _changes(device) == [
        (COMMAND.DELETE_OBJECT, 0x2001),
        (COMMAND.IMPORT_WRAPPED, 0x2000),
        (COMMAND.DELETE_OBJECT, 0x2001),
        (COMMAND.PUT_OPAQUE, 0x2000),
    ]
    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2000, OBJECT.OPAQUE),
        (0x2003, OBJECT.ASYMMETRIC_KEY),
        (0x2003, OBJECT.OPAQUE),
    }


def test_load_is_refused_when_the_device_rejects_the_import(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    device.fail_next(COMMAND.IMPORT_WRAPPED, ERROR.INVALID_DATA)

    with pytest.raises(YubiHsmDeviceError) as raised:
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

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
    backup before the error is raised.
    """
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    _key(device, tmp_path, 0x2000, loaded=False)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    backup = _backup_path(tmp_path, 0x2000)
    backup.write_bytes(
        base64.b64encode(base64.b64decode(backup.read_bytes())[:-16]),
    )
    evicted = _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(YubiHsmDeviceError) as raised:
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

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
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 2 + 1)
    _key(device, tmp_path, 0x2004, loaded=False)
    _backup_path(tmp_path, 0x2000).write_bytes(
        _backup_path(tmp_path, 0x2004).read_bytes(),
    )
    _certificate(device, tmp_path, 0x2000, loaded=False)
    evicted = _key(device, tmp_path, 0x2002)
    _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1

    with pytest.raises(ValueError, match="does not match expected key id"):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert _stored(device) == {
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }
    _assert_restored(device, 0x2002, evicted)


def test_failed_certificate_import_loads_the_evicted_certificate_again(
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    device = _plug(yubihsm, total_records=FIXED_RECORDS + 3 + 1)
    _key(device, tmp_path, 0x2000)
    _certificate(device, tmp_path, 0x2000, loaded=False)
    _key(device, tmp_path, 0x2002)
    evicted = _certificate(device, tmp_path, 0x2002)
    assert device.storage()[0] == 1
    device.fail_next(COMMAND.PUT_OPAQUE, ERROR.INVALID_DATA)

    with pytest.raises(YubiHsmDeviceError):
        ensure_keys_are_available(
            config(yubihsm),
            tmp_path,
            ["0x2000"],
            **_kwargs(verify_key_ids=False),
        )

    assert _stored(device) == {
        (0x2000, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.ASYMMETRIC_KEY),
        (0x2002, OBJECT.OPAQUE),
    }
    _assert_certificate(
        device,
        0x2002,
        evicted,
        domains=ONDEMAND_DOMAINS,
        capabilities=OPAQUE_CAPABILITIES,
    )
