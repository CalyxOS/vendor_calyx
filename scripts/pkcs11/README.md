# YubiHSM scripts

## Provisioning

This is for loading initial secret key material onto the HSM
and exporting encrypted shards for an n of m backup scheme.

### Preparation for the key ceremony

- Tails 7 (on a flash drive for live-booting into trusted environment)
- Randomly bought PC in a physical store right before the ceremony to minimize chance of hardware compromise
- Flash drive with prepared files for signing
  - Format a flash drive to exFAT
  - unzip `otatools-keys.zip`
  - `vendor/calyx/scripts/pkcs11/vendor.yubihsm.provision.sh prepare-directory /path/to/tmp/dir`
  - `zip ceremony.zip /path/to/tmp/dir`
  - Print out expected hash `sha256sum ceremony.zip`
  - Copy `ceremony.zip` to flash drive (and have it audited)

### Environment variables

- `KEEP_PATH`: Parent directory for `keys/` and `logs/`.
  Depending on context, defaults to `/dev/shm/keep` (typically the case when provisioning) 
  or the current working directory.

### Running provisioning

1. Boot Tails
2. Set an administrator password using additional options, prior to launching into the Tails desktop environment
3. Plug in flash drive and run `sha256sum /media/user/uuid-of-prepared-flash-drive/ceremony.zip`
4. Carefully compare printed hash with what had been recorded before and abort if it doesn't match
5. Unzip `ceremony.zip` and run: `/media/user/uuid-of-prepared-flash-drive/start.sh`
6. Follow the guided process
   * There will be three passwords needed for three roles: admin, audit and signing
   * Decide upfront who will know which passwords, how they get backed up and entered
7. Ensure to copy the contents of `KEEP_PATH` to the flash drive, before shutting down the PC

## Command line options

Options for run `scripts/pkcs11/vendor.yubihsm.provision.sh`:
(will get removed/simplified)

- `backup` - **not** recommended: uses yubihsm-setup tool to back up all objects on the HSM
- `restore` - prepares a secondary HSM with the wrap key, loading any keys found in the process. Should be run with the `KEEP_PATH` environment variable set to a location that contains a `keys/` and `logs/` directory: e.g. `KEEP_PATH=/media/amnesia/uuid-of-drive-with-keys-and-logs /media/amnesia/uuid-of-prepared-flash-drive/start.sh restore`.
- `primary` provisions primary HSM, creates wrap key
- `limited-keygen` generates two keys, just for testing restore on secondary HSM
- `keygen` generates **all** keys and exports them wrapped to `KEY_DIR`, automatically removes keys from HSM when it runs out of storage
- `full` does `primary` and then `restore` to provision secondary HSM
- `load-keys` used to restore wrapped keys from filesystem into HSM that already has the wrap key
- `prepare-directory` prepares files for usage in key ceremony

## Prerequisites

- YubiHSM 2 SDK
    - https://developers.yubico.com/YubiHSM2/Releases/
    - or Debian packages:
      `yubihsm-pkcs11 python3-yubihsm python3-usb yubihsm-shell yubihsm-connector opensc openssl libengine-pkcs11-openssl`
- An `otatools-keys.zip` package
    - To create one requires a CalyxOS checkout with `source build/envsetup.sh` as usual
      along with a `lunch`'d/`breakfast`'d device.
      Then, run `m otatools-keys-package`.
      It outputs to `$OUT/otatools-keys.zip`.

## Key generation

Creating keys is a manual step that is required before signing anything.

`vendor.yubihsm.provision.sh keygen` or `vendor.yubihsm.keygen.sh` generates **all** keys
and exports them wrapped (i.e. encrypted) to `./keys`
It automatically removes keys from HSM when it runs out of storage

## Signing

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

### Example with a remote server

1. Start yubihsm-connector locally (install package if necessary): `yubihsm-connector`
2. Connect to remote server, forwarding the yubihsm-connector port: `ssh -R 12345:localhost:12345 user@hostname`

On server, in extracted `otatools-keys.zip` directory:
```bash
YUBIHSM_EXTRACT_LOGS_AFTER_EVERY_N_COMMANDS=16 \
NEVER_START_YUBIHSM_CONNECTOR=y \
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign.sh
```

### Signing Internals

* payload signer is just for OTA payloads
* [signing helper](https://android.googlesource.com/platform/external/avb/+/0bcd559d39fbddec44fcadd38a3f91ee44e0108a/avbtool.py#439)
  is for AVB partitions and APEX payloads
