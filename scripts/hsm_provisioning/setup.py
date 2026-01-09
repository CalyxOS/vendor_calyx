#!/usr/bin/env python3
# Generates a wrap key and imports it into two HSMs.
# Then split the key into shards, exports those encrypted with age to public SSH keys.
# Creates three auth keys: signing, admin, audit

import os
import pathlib
import secrets
import string
import subprocess
import sys
from datetime import datetime, timezone

import yubihsm.defs
import yubihsm.objects
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption, Encoding, PublicFormat
from yubihsm import YubiHsm
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, OPTION, OBJECT, ERROR
from yubihsm.exceptions import YubiHsmDeviceError
from yubihsm.objects import WrapKey, AuthenticationKey, Opaque

from audit import extract_and_save_logs

SSS_NUM_SHARDS = 5
SSS_THRESHOLD = 3

KEEP_PATH = os.getenv("KEEP_PATH", os.path.join(pathlib.Path.home(), "CalyxHSM"))

WRAP_KEY_ID = 0x0010
WRAP_KEY_LEN = 32
WRAP_KEY_CAPS = (CAPABILITY.IMPORT_WRAPPED | CAPABILITY.EXPORT_WRAPPED)
WRAP_KEY_DEL_CAPS = (
        CAPABILITY.DECRYPT_PKCS |
        CAPABILITY.DECRYPT_OAEP |
        CAPABILITY.SIGN_PKCS |
        CAPABILITY.SIGN_PSS |
        CAPABILITY.SIGN_ECDSA |
        CAPABILITY.SIGN_EDDSA |
        CAPABILITY.DERIVE_ECDH |
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
        CAPABILITY.GET_OPTION
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
        CAPABILITY.GET_OPAQUE
)
AUDIT_AUTHKEY_DEL_CAPS = CAPABILITY.NONE

script_dir = os.path.dirname(os.path.realpath(__file__))


def main():
    # ensure auth key dir exists
    auth_key_dir = os.path.join(KEEP_PATH, "auth-keys")
    os.makedirs(auth_key_dir, exist_ok=True)

    # create and get auth keys
    password_signing = create_auth_password(auth_key_dir, "signing", "5")
    admin_private_key, admin_public_key = create_auth_key(auth_key_dir, "admin", "4")
    _, audit_public_key = create_auth_key(auth_key_dir, "audit", "3")

    # provision primary HSM
    print("\nPlease connect the primary YubiHSM 2.\n")
    input("Press any key when primary HSM is connected.")
    wrap_key_bytes = provision_hsm(admin_private_key, admin_public_key, password_signing, audit_public_key,
                                   lambda session: create_and_provision_wrap_key(session))
    # split wrap key into shards and store them encrypted
    create_and_export_shards(wrap_key_bytes)

    # provision secondary HSM
    print("\n\nPlease unplug the primary YubiHSM 2")
    print("and connect the secondary YubiHSM 2\n")
    input("Press any key when secondary HSM is connected.")
    provision_hsm(admin_private_key, admin_public_key, password_signing, audit_public_key,
                  lambda session: provision_wrap_key(session, wrap_key_bytes))
    print("\nCongratulations! Both HSMs provisioned.")
    print()
    print(f"IMPORTANT: Save the contents of {KEEP_PATH} now!")


def create_auth_password(auth_key_dir, name, public_key_id):
    # generate password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(40))

    # encrypt password with age
    public_key_path = os.path.join(script_dir, "keys", f"{public_key_id}.pub")
    auth_key_path = os.path.join(auth_key_dir, f"{name}.key")
    age_command = ['age', '-R', public_key_path, '-o', auth_key_path]
    subprocess.run(age_command, input=password, text=True, check=True)

    return password


def create_auth_key(auth_key_dir, name, public_key_id):
    # create key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_private_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    auth_key = pem_public_key + b'\n' + pem_private_key

    # encrypt auth key pair with age
    public_key_path = os.path.join(script_dir, "keys", f"{public_key_id}.pub")
    auth_key_path = os.path.join(auth_key_dir, f"{name}.key")
    age_command = ['age', '-R', public_key_path, '-o', auth_key_path]
    subprocess.run(age_command, input=auth_key, check=True)

    return private_key, public_key


def provision_hsm(admin_private_key, admin_public_key, password_signing, audit_public_key, get_wrap_key):
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
        provision_admin_auth_key(session, admin_public_key)
        # session will get replaced by a new one after switching to our own admin auth key
        session = delete_default_auth_key(hsm, session, admin_private_key)
        provision_signing_auth_key(session, password_signing)
        provision_audit_auth_key(session, audit_public_key)
        save_audit_log(session, hsm_name)
    finally:
        session.close()
    return wrap_key


def print_and_get_info(hsm, session):
    device_info = hsm.get_device_info()
    version = f"v{device_info.version[0]}.{device_info.version[1]}.{device_info.version[2]}"
    hsm_name = f"{device_info.part_number}-{device_info.serial}"
    print(f"Connected to YubiHSM 2 {version} Serial: {device_info.serial} Part: {device_info.part_number}\n")

    # get all keys on device and check if this is factory default
    keys = session.list_objects()
    if len(keys) != 1 or keys[0].get_info().label != "DEFAULT AUTHKEY CHANGE THIS ASAP":
        on_not_factory_reset()
    else:
        print("\nDevice seems to be factory reset, continuing...\n")

    # get and print attestation certificate
    attestation_cert = Opaque(session, 0).get_certificate()
    attestation_cert_pem = attestation_cert.public_bytes(encoding=Encoding.PEM)
    print(attestation_cert_pem.decode('utf-8'))
    print()

    # save attestation certificate to file
    keys_path = os.path.join(KEEP_PATH, hsm_name)
    os.makedirs(keys_path, exist_ok=True)
    with open(os.path.join(keys_path, "attestation.pem"), "wb") as f:
        f.write(attestation_cert_pem)

    # get and print HSMs public key
    public_key = hsm.get_device_public_key()
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    print(public_key_pem.decode('utf-8'))
    print()

    # save public key to file
    with open(os.path.join(keys_path, "public_key.pem"), "wb") as f:
        f.write(public_key_pem)

    # return HSM name to be used as a folder name to identify this specific HSM
    return hsm_name


# Turn on (forced) audit log
def enable_auditing(session):
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

    # Enable audit log for most auditable commands, not uncritical ones that create too much noise
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
        COMMAND.DECRYPT_PKCS1,
        COMMAND.DERIVE_ECDH,
        COMMAND.DECRYPT_OAEP,
        COMMAND.VERIFY_HMAC,
        COMMAND.SIGN_SSH_CERTIFICATE,
        COMMAND.GET_TEMPLATE,
        COMMAND.CREATE_OTP_AEAD,
        COMMAND.DECRYPT_ECB,
        COMMAND.ENCRYPT_ECB,
        COMMAND.DECRYPT_CBC,
        COMMAND.ENCRYPT_CBC,
    )
    for command in commands_to_audit:
        session.put_option(OPTION.COMMAND_AUDIT, command.to_bytes() + b"\x02")
    print("Successfully provisioned auditing options.")


def create_and_provision_wrap_key(session):
    # provision wrap key
    # https://github.com/Yubico/yubihsm-setup/blob/68bf3c7aa2d5c7e3efb05af471fafb551fa84e11/src/main.rs
    wrap_key_bytes = session.get_pseudo_random(WRAP_KEY_LEN)
    return provision_wrap_key(session, wrap_key_bytes)


def provision_wrap_key(session, wrap_key_bytes):
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
    print(f"Imported Wrap Key with ID {wrap_key_obj.id}")
    return wrap_key_bytes


def create_and_export_shards(wrap_key_bytes):
    split_path = os.path.join(script_dir, "calyx-shamir-split")
    # ensure that split program can be executed
    os.chmod(split_path, 0o755)
    # split wrap key into shards
    command = [split_path, '--threshold', str(SSS_THRESHOLD), '--shares', str(SSS_NUM_SHARDS)]
    result = subprocess.run(command, input=wrap_key_bytes.hex(), capture_output=True, text=True, check=True)
    shards = result.stdout.splitlines()

    # ensure shard dir exists
    shard_dir = os.path.join(KEEP_PATH, "shards")
    os.makedirs(shard_dir, exist_ok=True)

    # encrypt shards with age
    for i, shard in enumerate(shards):
        key_path = os.path.join(script_dir, "keys", f"{i + 1}.pub")
        shard_path = os.path.join(shard_dir, f"{i + 1}.shard")
        age_command = ['age', '-R', key_path, '-o', shard_path]
        subprocess.run(age_command, input=shard, text=True, check=True)


def provision_admin_auth_key(session, admin_key):
    label = "Admin auth key"
    auth_key = AuthenticationKey.put_public_key(
        session=session,
        object_id=ADMIN_AUTHKEY_ID,
        label=label,
        domains=0xFFFF,  # all
        capabilities=ADMIN_AUTHKEY_CAPS,
        delegated_capabilities=ADMIN_AUTHKEY_DEL_CAPS,
        public_key=admin_key,
    )
    print(f"Generated {label} with ID {auth_key.id}")


def delete_default_auth_key(hsm, session, admin_private_key):
    # close old session and open new one
    session.close()
    new_session = hsm.create_session_asymmetric(ADMIN_AUTHKEY_ID, admin_private_key)

    default_auth_key = new_session.get_object(0x0001, OBJECT.AUTHENTICATION_KEY)
    default_auth_key.get_info()  # causes OBJECT_NOT_FOUND if key doesn't exist
    default_auth_key.delete()
    print("Deleted default auth key")
    return new_session


def provision_signing_auth_key(session, password):
    label = "Signing auth key"
    auth_key = AuthenticationKey.put_derived(
        session=session,
        object_id=SIGNING_AUTHKEY_ID,
        label=label,
        domains=0xFFFF,  # all
        capabilities=SIGNING_AUTHKEY_CAPS,
        delegated_capabilities=SIGNING_AUTHKEY_DEL_CAPS,
        password=password,
    )
    print(f"Generated {label} with ID {auth_key.id}")


def provision_audit_auth_key(session, audit_key):
    label = "Audit auth key"
    auth_key = AuthenticationKey.put_public_key(
        session=session,
        object_id=AUDIT_AUTHKEY_ID,
        label=label,
        domains=0xFFFF,  # all
        capabilities=AUDIT_AUTHKEY_CAPS,
        delegated_capabilities=AUDIT_AUTHKEY_DEL_CAPS,
        public_key=audit_key,
    )
    print(f"Generated {label} with ID {auth_key.id}")


def save_audit_log(session, hsm_name):
    # define folder for log files and ensure it exists
    now = datetime.now(timezone.utc)
    log_path = os.path.join(KEEP_PATH, "logs", hsm_name)
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
