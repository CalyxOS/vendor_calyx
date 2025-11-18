#!/usr/bin/env python3
# Generates a wrap key and imports it into two HSMs.
# Then split the key into shards, exports those encrypted with age to public SSH keys.
# Creates three auth keys: signing, admin, audit

import os
import subprocess
import sys
from datetime import datetime, timezone
from itertools import combinations

import yubihsm.defs
import yubihsm.objects
from yubihsm import YubiHsm
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, OPTION, OBJECT, ERROR
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm.objects import WrapKey, AuthenticationKey

from audit import extract_and_save_logs

WRAP_KEY_ID = 0x0010
WRAP_KEY_LEN = 32
WRAP_KEY_CAPS = (CAPABILITY.IMPORT_WRAPPED | CAPABILITY.EXPORT_WRAPPED)
WRAP_KEY_DEL_CAPS = (
        CAPABILITY.DECRYPT_PKCS |
        CAPABILITY.DECRYPT_OAEP |
        CAPABILITY.GENERATE_ASYMMETRIC_KEY |
        CAPABILITY.SIGN_PKCS |
        CAPABILITY.SIGN_PSS |
        CAPABILITY.SIGN_ECDSA |
        CAPABILITY.SIGN_EDDSA |
        CAPABILITY.DERIVE_ECDH |
        CAPABILITY.IMPORT_WRAPPED |
        CAPABILITY.EXPORT_WRAPPED |
        CAPABILITY.EXPORTABLE_UNDER_WRAP |
        CAPABILITY.GET_LOG_ENTRIES |
        CAPABILITY.GET_OPTION
)
SIGNING_AUTHKEY_ID = 0x0001
# Authkey capabilities are based on yubihsm-setup, with some changes for our use cases.
SIGNING_AUTHKEY_CAPS = (
        CAPABILITY.GENERATE_ASYMMETRIC_KEY |
        CAPABILITY.SIGN_PKCS |
        CAPABILITY.SIGN_PSS |
        CAPABILITY.SIGN_ECDSA |
        CAPABILITY.SIGN_EDDSA |
        CAPABILITY.DERIVE_ECDH |
        CAPABILITY.IMPORT_WRAPPED |
        CAPABILITY.EXPORT_WRAPPED |
        CAPABILITY.EXPORTABLE_UNDER_WRAP |
        CAPABILITY.GET_OPTION |
        CAPABILITY.SIGN_ATTESTATION_CERTIFICATE |
        CAPABILITY.GET_LOG_ENTRIES |
        CAPABILITY.CHANGE_AUTHENTICATION_KEY |
        CAPABILITY.DECRYPT_PKCS |
        CAPABILITY.DECRYPT_OAEP |
        CAPABILITY.PUT_OPAQUE |
        CAPABILITY.GET_OPAQUE |
        CAPABILITY.DELETE_OPAQUE |
        CAPABILITY.DELETE_ASYMMETRIC_KEY
)
SIGNING_AUTHKEY_DEL_CAPS = (
        CAPABILITY.GENERATE_ASYMMETRIC_KEY |
        CAPABILITY.SIGN_PKCS |
        CAPABILITY.SIGN_PSS |
        CAPABILITY.SIGN_ECDSA |
        CAPABILITY.SIGN_EDDSA |
        CAPABILITY.DERIVE_ECDH |
        CAPABILITY.EXPORTABLE_UNDER_WRAP |
        CAPABILITY.GET_OPTION |
        CAPABILITY.DECRYPT_PKCS |
        CAPABILITY.DECRYPT_OAEP
)

ADMIN_AUTHKEY_ID = 0x00ad
# Admin authkey defaults to having the same capabilities as signing, plus some more.
ADMIN_AUTHKEY_CAPS = (
        SIGNING_AUTHKEY_CAPS |
        CAPABILITY.PUT_ASYMMETRIC |
        CAPABILITY.DELETE_SYMMETRIC_KEY |
        CAPABILITY.GENERATE_SYMMETRIC_KEY |
        CAPABILITY.PUT_SYMMETRIC_KEY |
        CAPABILITY.DELETE_HMAC_KEY |
        CAPABILITY.GENERATE_HMAC_KEY |
        CAPABILITY.PUT_HMAC_KEY |  # put-mac-key
        CAPABILITY.SIGN_HMAC |
        CAPABILITY.VERIFY_HMAC |
        CAPABILITY.DELETE_TEMPLATE |
        CAPABILITY.GET_TEMPLATE |
        CAPABILITY.PUT_TEMPLATE |
        CAPABILITY.SIGN_SSH_CERTIFICATE |
        CAPABILITY.DECRYPT_CBC |
        CAPABILITY.ENCRYPT_CBC |
        CAPABILITY.DECRYPT_ECB |
        CAPABILITY.ENCRYPT_ECB |
        CAPABILITY.DELETE_OTP_AEAD_KEY |
        CAPABILITY.GENERATE_OTP_AEAD_KEY |
        CAPABILITY.PUT_OTP_AEAD_KEY |
        CAPABILITY.CREATE_OTP_AEAD |
        CAPABILITY.RANDOMIZE_OTP_AEAD |
        CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY |
        CAPABILITY.REWRAP_TO_OTP_AEAD_KEY |
        CAPABILITY.DELETE_OPAQUE |
        CAPABILITY.DELETE_AUTHENTICATION_KEY |
        CAPABILITY.PUT_AUTHENTICATION_KEY |
        CAPABILITY.SET_OPTION |
        CAPABILITY.RESET_DEVICE
)
# Admin authkey has the same delegated capabilities as the signing authkey's main capabilities, plus more.
# It needs to be able to re-create the signing authkey, after all.
ADMIN_AUTHKEY_DEL_CAPS = (
        SIGNING_AUTHKEY_CAPS |
        CAPABILITY.PUT_ASYMMETRIC |
        CAPABILITY.DELETE_SYMMETRIC_KEY |
        CAPABILITY.GENERATE_SYMMETRIC_KEY |
        CAPABILITY.PUT_SYMMETRIC_KEY |
        CAPABILITY.DELETE_HMAC_KEY |
        CAPABILITY.GENERATE_HMAC_KEY |
        CAPABILITY.PUT_HMAC_KEY |  # put-mac-key
        CAPABILITY.SIGN_HMAC |
        CAPABILITY.VERIFY_HMAC |
        CAPABILITY.DELETE_TEMPLATE |
        CAPABILITY.GET_TEMPLATE |
        CAPABILITY.PUT_TEMPLATE |
        CAPABILITY.SIGN_SSH_CERTIFICATE |
        CAPABILITY.ENCRYPT_CBC |
        CAPABILITY.DECRYPT_ECB |
        CAPABILITY.ENCRYPT_ECB |
        CAPABILITY.DELETE_OTP_AEAD_KEY |
        CAPABILITY.GENERATE_OTP_AEAD_KEY |
        CAPABILITY.PUT_OTP_AEAD_KEY |
        CAPABILITY.CREATE_OTP_AEAD |
        CAPABILITY.RANDOMIZE_OTP_AEAD |
        CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY |
        CAPABILITY.REWRAP_TO_OTP_AEAD_KEY |
        CAPABILITY.DELETE_OPAQUE
)
AUDIT_AUTHKEY_ID = 0x0002
AUDIT_AUTHKEY_CAPS = (
        CAPABILITY.GET_LOG_ENTRIES |
        CAPABILITY.EXPORTABLE_UNDER_WRAP |
        CAPABILITY.GET_OPAQUE
)
AUDIT_AUTHKEY_DEL_CAPS = CAPABILITY.NONE

SSS_NUM_SHARDS = 5
SSS_THRESHOLD = 3


def main():
    # Check required env variables
    if not os.path.isdir(os.getenv("KEEP_PATH", "No KEEP_PATH specified")):
        print(f"Error: $KEEP_PATH is not a directory.", file=sys.stderr)
        sys.exit(1)
    password_admin = check_password("YUBIHSM_ADMIN_AUTHKEY_PASSWORD")
    password_signing = check_password("YUBIHSM_SIGNING_AUTHKEY_PASSWORD")
    password_audit = check_password("YUBIHSM_AUDIT_AUTHKEY_PASSWORD")

    # provision primary HSM
    print("Please connect the primary YubiHSM 2.\n")
    input("Press any key when primary HSM is connected.")
    wrap_key_bytes = provision_hsm(password_admin, password_signing, password_audit,
                                   lambda session: provision_wrap_key(session))
    # split wrap key into shards and store them encrypted
    create_and_export_shards(wrap_key_bytes)

    # provision secondary HSM
    print("\n\nPlease unplug the primary YubiHSM 2\n")
    print("and connect the secondary YubiHSM 2\n")
    input("Press any key when secondary HSM is connected.")
    provision_hsm(password_admin, password_signing, password_audit,
                  lambda session: wrap_key_bytes)
    print("\nCongratulations! Both HSMs provisioned.")


def provision_hsm(password_admin, password_signing, password_audit, get_wrap_key):
    # Connect to the YubiHSM via the connector using the default password:
    connector_url = os.getenv("YUBIHSM_CONNECTOR", "http://127.0.0.1:12345")
    hsm = YubiHsm.connect(connector_url)
    try:
        # establish session (using factory default credentials)
        session = hsm.create_session_derived(0x0001, "password")
    except yubihsm.exceptions.YubiHsmAuthenticationError as e:
        # if we can't authenticate with default credentials, the HSM isn't factory reset
        on_not_factory_reset()
        raise e
    try:
        hsm_name = print_and_get_info(hsm, session)
        enable_auditing(session)
        wrap_key = get_wrap_key(session)
        provision_admin_auth_key(session, password_admin)
        # session will get replaced by a new one after switching to our own admin auth key
        session = delete_default_auth_key(hsm, session, password_admin)
        provision_signing_auth_key(session, password_signing)
        provision_audit_auth_key(session, password_audit)
    finally:
        session.close()
    save_audit_log(session, hsm_name, password_signing)
    return wrap_key


def check_password(env_name):
    password = os.getenv(env_name, None)
    if password is None:
        print(f"Error: Password for {env_name} missing.", file=sys.stderr)
        sys.exit(1)
    return password


def print_and_get_info(hsm, session):
    device_info = hsm.get_device_info()
    version = f"v{device_info.version[0]}.{device_info.version[1]}.{device_info.version[2]}"
    print(f"Connected to YubiHSM 2 {version} Serial: {device_info.serial} Part: {device_info.part_number}\n")

    # get all keys on device and check if this is factory default
    keys = session.list_objects()
    if len(keys) != 1 or keys[0].get_info().label != "DEFAULT AUTHKEY CHANGE THIS ASAP":
        on_not_factory_reset()
    else:
        print("\nDevice seems to be factory reset, continuing...\n")

    # return HSM name to be used as a folder name to identify this specific HSM
    return f"{device_info.part_number}-{device_info.serial}"


# Turn on (forced) audit log
def enable_auditing(session):
    existing_audit_option = session.get_option(OPTION.COMMAND_AUDIT)
    expected_option = "0100030004000500060007000900080040004100420243004402450246024702" + \
                      "550256024800490057004a024b024c024d0067004e004f025000510252025302" + \
                      "5400580259005a025b025c005d005e025f006000610062026302640265026602" + \
                      "680269026a026b006c020a006d026e026f0070007100720073027402750276027702"
    if existing_audit_option.hex() == expected_option:
        print("Already set up audit logs, not doing it again.")
        return
    print("Provisioning auditing...")

    # Much of this was gleaned from https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e
    # By default, no command is logged into the audit trail, only boot events.
    # We want everything logged, force it until factory reset (0x02).
    session.put_option(OPTION.COMMAND_AUDIT, COMMAND.SET_OPTION.to_bytes() + b'\x02')

    # By default, if force-audit is turned off (0x00), when the YubiHSM internal audit log (62 entries) is reached,
    # new operations will overwrite old ones, losing the trail.
    # Turning it on (0x01) will cause the HSM to refuse further operations until the logs are exported;
    # and setting it to 0x02 will lock the option in until a factory reset.
    # We want the latter one to ensure no operation goes unnoticed.
    session.put_option(OPTION.FORCE_AUDIT, b'\x02')

    # Enable audit log for all auditable commands
    # from: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html
    # command Tc values
    commands_to_audit = (
        COMMAND.CHANGE_AUTHENTICATION_KEY,
        COMMAND.DELETE_OBJECT,
        COMMAND.EXPORT_WRAPPED,
        COMMAND.EXPORT_WRAPPED_RSA,
        COMMAND.WRAP_KEY_RSA,
        COMMAND.GENERATE_ASYMMETRIC_KEY,
        COMMAND.GENERATE_HMAC_KEY,
        COMMAND.GENERATE_OTP_AEAD_KEY,
        COMMAND.GENERATE_SYMMETRIC_KEY,
        COMMAND.GENERATE_WRAP_KEY,
        COMMAND.GET_PSEUDO_RANDOM,
        COMMAND.IMPORT_WRAPPED,
        COMMAND.IMPORT_WRAPPED_RSA,
        COMMAND.UNWRAP_KEY_RSA,
        COMMAND.PUT_ASYMMETRIC_KEY,
        COMMAND.PUT_AUTHENTICATION_KEY,
        COMMAND.PUT_HMAC_KEY,
        COMMAND.PUT_OPAQUE,
        COMMAND.PUT_OTP_AEAD_KEY,
        COMMAND.PUT_PUBLIC_WRAP_KEY,
        COMMAND.PUT_SYMMETRIC_KEY,
        COMMAND.PUT_TEMPLATE,
        COMMAND.PUT_WRAP_KEY,
        COMMAND.RANDOMIZE_OTP_AEAD,
        COMMAND.REWRAP_OTP_AEAD,
        COMMAND.SIGN_ATTESTATION_CERTIFICATE,
        COMMAND.SIGN_ECDSA,
        COMMAND.SIGN_EDDSA,
        COMMAND.SIGN_HMAC,
        COMMAND.SIGN_PKCS1,
        COMMAND.SIGN_PSS,
        COMMAND.UNWRAP_DATA,
        COMMAND.WRAP_DATA,
    )
    for command in commands_to_audit:
        session.put_option(OPTION.COMMAND_AUDIT, command.to_bytes() + b"\x02")
    print("Successfully provisioned auditing options.")


def is_proper_wrap_key(wrap_key_obj):
    if wrap_key_obj is None: return False
    info = wrap_key_obj.get_info()
    if info.label != "Wrap key": return False
    if info.algorithm != ALGORITHM.AES256_CCM_WRAP: return False
    if info.size != 40: return False
    if info.domains != 0xFFFF: return False
    # if info.sequence != 0: return False # gets increased when deleting key and re-creating it
    if info.origin != yubihsm.defs.ORIGIN.IMPORTED: return False
    if info.capabilities != 12288: return False
    if info.delegated_capabilities != 17121264: return False
    return True


def provision_wrap_key(session):
    # provision wrap key
    # https://github.com/Yubico/yubihsm-setup/blob/68bf3c7aa2d5c7e3efb05af471fafb551fa84e11/src/main.rs
    wrap_key_bytes = session.get_pseudo_random(WRAP_KEY_LEN)
    wrap_key_obj = WrapKey.put(
        session=session,
        object_id=WRAP_KEY_ID,
        label="Wrap key",
        domains=0xFFFF,  # all
        capabilities=WRAP_KEY_CAPS,
        algorithm=ALGORITHM.AES256_CCM_WRAP,
        delegated_capabilities=WRAP_KEY_DEL_CAPS,
        key=wrap_key_bytes,
    )
    if not is_proper_wrap_key(wrap_key_obj): raise RuntimeError("Created improper wrap key")
    print(f"Imported Wrap Key with ID {wrap_key_obj.id}")
    return wrap_key_bytes


def create_and_export_shards(wrap_key_bytes):
    # TODO may switch to a different SSS tool
    # split wrap key into shards
    command = ['ssss-split', '-t', str(SSS_THRESHOLD), '-n', str(SSS_NUM_SHARDS), '-x', '-q']
    result = subprocess.run(command, input=wrap_key_bytes.hex(), capture_output=True, text=True, check=True)
    shards = result.stdout.splitlines()
    verify_shards(shards, wrap_key_bytes)

    # ensure shard dir exists
    shard_dir = os.path.join(os.getenv("KEEP_PATH"), "shards")
    os.makedirs(shard_dir, exist_ok=True)

    # encrypt shards with age
    script_dir = os.path.dirname(os.path.realpath(__file__))
    for i, shard in enumerate(shards):
        key_path = os.path.join(script_dir, "keys", f"{i + 1}.pub")
        shard_path = os.path.join(shard_dir, f"{i + 1}.shard")
        age_command = ['age', '-R', key_path, '-o', shard_path]
        subprocess.run(age_command, input=shard, text=True, check=True)


def verify_shards(shards, wrap_key_bytes):
    if len(shards) != SSS_NUM_SHARDS:
        print(f"ERROR: Unexpected number of shards: {len(shards)} != {SSS_NUM_SHARDS}", file=sys.stderr)
        sys.exit(1)
    # test that *each* combination of shards can in fact be used to restore the wrap_key_bytes
    shard_combinations = list(combinations(shards, r=3)) + list(combinations(shards, r=4)) + [shards]
    for combination in shard_combinations:
        command = ['ssss-combine', '-t', str(SSS_THRESHOLD), '-x', '-q']
        result = subprocess.run(command, input="\n".join(combination), capture_output=True, text=True, check=True)
        combined_key = result.stderr.rstrip()
        if combined_key != wrap_key_bytes.hex():
            print(f"ERROR: Could not verify all shards", file=sys.stderr)
            sys.exit(1)


def provision_admin_auth_key(session, admin_password):
    provision_auth_key(
        session=session,
        object_id=ADMIN_AUTHKEY_ID,
        label="Admin auth key",
        capabilities=ADMIN_AUTHKEY_CAPS,
        delegated_capabilities=ADMIN_AUTHKEY_DEL_CAPS,
        password=admin_password,
    )


def delete_default_auth_key(hsm, session, admin_password):
    # first double check that new admin auth key really exists, or we lock ourselves out
    admin_key = session.get_object(ADMIN_AUTHKEY_ID, OBJECT.AUTHENTICATION_KEY)
    admin_key.get_info()
    try:
        default_auth_key = session.get_object(0x0001, OBJECT.AUTHENTICATION_KEY)
        default_auth_key.get_info()  # causes OBJECT_NOT_FOUND if key doesn't exist
        default_auth_key.delete()
        print(f"Deleted default auth key")
        return hsm.create_session_derived(ADMIN_AUTHKEY_ID, admin_password)
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            print(f"ALREADY DELETED DEFAULT AUTH KEY, NOT DELETING AGAIN!")
            return session
        raise e


def provision_signing_auth_key(session, password):
    provision_auth_key(
        session=session,
        object_id=SIGNING_AUTHKEY_ID,
        label="Signing auth key",
        capabilities=SIGNING_AUTHKEY_CAPS,
        delegated_capabilities=SIGNING_AUTHKEY_DEL_CAPS,
        password=password,
    )


def provision_audit_auth_key(session, password):
    provision_auth_key(
        session=session,
        object_id=AUDIT_AUTHKEY_ID,
        label="Audit auth key",
        capabilities=AUDIT_AUTHKEY_CAPS,
        delegated_capabilities=AUDIT_AUTHKEY_DEL_CAPS,
        password=password,
    )


def provision_auth_key(session, object_id, label, capabilities, delegated_capabilities, password):
    try:
        auth_key = session.get_object(object_id, OBJECT.AUTHENTICATION_KEY)
        auth_key.get_info()  # needed to cause OBJECT_NOT_FOUND
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            auth_key = AuthenticationKey.put_derived(
                session=session,
                object_id=object_id,
                label=label,
                domains=0xFFFF,  # all
                capabilities=capabilities,
                delegated_capabilities=delegated_capabilities,
                password=password,
            )
            print(f"Generated {label} with ID {auth_key.id}")
            return
        raise e
    print(f"NOT GENERATING {label} {object_id}, BECAUSE ALREADY EXISTS!")


def save_audit_log(session, hsm_name, password):
    # define folder for log files and ensure it exists
    now = datetime.now(timezone.utc)
    log_path = os.path.join(os.getenv("KEEP_PATH"), "logs", hsm_name)
    os.makedirs(log_path, exist_ok=True)
    # define log file path
    date_str = now.strftime("%Y-%m-%d_%H-%M-%S") + f"-{now.strftime("%f")[:3]}"
    log_file = os.path.join(log_path, f"{date_str}-provision.log")
    # use other python script to actually extract logs
    comment = "provisioning: 4f is for audit log options, the rest is key setup"
    extract_and_save_logs(session, log_file, comment)


def on_not_factory_reset():
    print()
    print("ERROR: The HSM does not seem to be factory reset.")
    print()
    print("You will need to reset it manually by removing it")
    print("and pressing on the metal rim for at least 10 seconds.")
    print("Then try again.")
    sys.exit(1)


if __name__ == "__main__":
    main()
