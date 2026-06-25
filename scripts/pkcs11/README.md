# YubiHSM scripts

## Provisioning

See [dedicated documentation on provisioning](../hsm_provisioning/README.md).

## Adding new keys

Edit `scripts/metadata` and run:

    KEYMAPPER=id2b ./scripts/generate_keymap.sh > scripts/pkcs11/keymap.tsv

Note that adding new devices also requires them adding them to the following file in another repo:

    ../../calyx/scripts/vars/devices

## Key generation

The following Debian 13 packages are needed:

    sudo apt install yubihsm-pkcs11 python3-yubihsm python3-usb python3-git yubihsm-shell yubihsm-connector opensc openssl libengine-pkcs11-openssl

Alternatively for Ubuntu 24.04/Mint 22.2, install the following packages:

    sudo apt install python3-usb python3-git opensc openssl libengine-pkcs11-openssl

and manually install the YubiHSM packages:

[python3-yubihsm](http://ftp.us.debian.org/debian/pool/main/p/python-yubihsm/python3-yubihsm_3.1.1-1_all.deb),
[yubihsm-connector](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-connector/yubihsm-connector_3.0.5-2_amd64.deb),
[libykhsmauth2](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-shell/libykhsmauth2_2.6.0-5_amd64.deb),
[libyubihsm2](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-shell/libyubihsm2_2.6.0-5_amd64.deb),
[libyubihsm-http2](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-shell/libyubihsm-http2_2.6.0-5_amd64.deb),
[yubihsm-pkcs11](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-shell/yubihsm-pkcs11_2.6.0-5_amd64.deb),
[yubihsm-shell](http://ftp.us.debian.org/debian/pool/main/y/yubihsm-shell/yubihsm-shell_2.6.0-5_amd64.deb)

Creating keys is a manual step that is required before signing anything.

Before generating keys, make sure the audit log git repository is set up locally
under in your otatools root under `./logs`
and that the log file from provisioning is commited.

You should have `CalyxHSM/auth-keys/signing.key` from the provisioning process.
For the next step you will have to decrypt it using your private key:
`age --decrypt --identity ~/.ssh/calyxos_shard_ed25519 signing.key`

Build and extract `otatools-keys.zip`.
Run `./vendor/calyx/scripts/pkcs11/vendor.yubihsm.keygen.sh ./keys` in the folder
where you extracted `otatools-keys.zip`.
You will be asked for a password which was the one decrypted in the previous step.
It generates **all** keys and exports them wrapped (i.e. encrypted)
to the provided `./keys` folder.
It automatically removes keys from HSM when it runs out of storage.

If you get an error about `KEYMAP_FILE` not being found,
prepend `KEYMAP_FILE=vendor/calyx/scripts/pkcs11/keymap.tsv` to the command line.

Each time new keys have been generated,
the contents of the `./keys` folder should get securely backed up.

In case the machine was offline during key generation,
the audit logs in the `./logs` repository must be manually pushed to the remote.

## Signing

Additionally to the packages installed in the key generation step, the following packages are needed:

    sudo apt install parallel openjdk-21-jdk zip

### Environment variables

The `vendor/calyx/scripts/sign.sh` script (recommended) will prompt for these automatically if unset.
Otherwise, if using `vendor/calyx/scripts/release.sh` or `vendor/calyx/scripts/generate_delta.sh`,
they will need to be specified manually.

- `PKCS11_VENDOR`: Vendor to use for signing. Typically, should always be `yubihsm`,
  or unset to use legacy signing.
  Other supported values: `softhsm`
- `YUBIHSM_AUTHKEY`: Authkey ID to use for signing. Should always be `0x0001`.
- `YUBIHSM_PASSWORD`: Password to use for signing.

Contrary to the old signing scripts,
the `vendor/calyx/scripts/sign.sh` script attempts to automate the selection of `BUILD_NUMBER` and `PREV_BUILD_NUMBER`.
It supports signing different build numbers in one go,
and most importantly it ensures that devices' required keys are loaded into the HSM
prior to launching parallel signing;
devices whose keys are not loaded will be signed in parallel *after* devices whose keys *are* loaded.

You will be asked for a password which is the one you decrypted in the key generation step.

### Example with a local machine

In extracted `otatools-keys.zip` directory:
```bash
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign.sh
```

### Example with a remote server

1. Start yubihsm-connector locally (install package if necessary): `yubihsm-connector`
2. Connect to remote server, forwarding the yubihsm-connector port: `ssh -R 12345:localhost:12345 user@hostname`

On server, in extracted `otatools-keys.zip` directory:
```bash
NEVER_START_YUBIHSM_CONNECTOR=y \
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign.sh
```

## Signing individual apps

Copy the apk you want to sign (in this example `app-release-unsigned.apk` for GCamPhotosPreview)
to the top of your extracted `otatools-keys.zip` directory.

You will be asked for a password which is the one you decrypted in the key generation step.

### Example with a local machine

In extracted `otatools-keys.zip` directory:
```bash
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign-app.sh com.google.android.apps.photos app-release-unsigned.apk
```

### Example with a remote server

1. Start yubihsm-connector locally (install package if necessary): `yubihsm-connector`
2. Connect to remote server, forwarding the yubihsm-connector port: `ssh -R 12345:localhost:12345 user@hostname`

On server, in extracted `otatools-keys.zip` directory:
```bash
NEVER_START_YUBIHSM_CONNECTOR=y \
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign-app.sh com.google.android.apps.photos app-release-unsigned.apk
```

### Signing Internals

* payload signer is just for OTA payloads
* [signing helper](https://android.googlesource.com/platform/external/avb/+/0bcd559d39fbddec44fcadd38a3f91ee44e0108a/avbtool.py#439)
  is for AVB partitions and APEX payloads
