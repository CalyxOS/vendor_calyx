# YubiHSM scripts

## Provisioning

See [dedicated documentation on provisioning](../hsm_provisioning/README.md).

## Key generation

Creating keys is a manual step that is required before signing anything.

Run `./vendor.yubihsm.keygen.sh ./keys`
It generates **all** keys and exports them wrapped (i.e. encrypted)
to the provided `./keys` folder.
It automatically removes keys from HSM when it runs out of storage.

Each time new keys have been generated,
the contents of the `./keys` folder should get securely backed up.

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
NEVER_START_YUBIHSM_CONNECTOR=y \
PKCS11_VENDOR=yubihsm \
vendor/calyx/scripts/sign.sh
```

### Signing Internals

* payload signer is just for OTA payloads
* [signing helper](https://android.googlesource.com/platform/external/avb/+/0bcd559d39fbddec44fcadd38a3f91ee44e0108a/avbtool.py#439)
  is for AVB partitions and APEX payloads
