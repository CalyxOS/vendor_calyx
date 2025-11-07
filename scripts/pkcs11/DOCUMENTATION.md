[toc]

# CalyxOS Signing Documentation

This documents attempts to describe exactly how CalyxOS signing is working,
how keys are handled and what changes were needed to accomplish this.

We try to be brief and to the point, linking to additional information where necessary.

## Terminology

* HSM: Hardware Security Module, keeps keys in hardware, extremely hard to extract (not possible for normal people)
* Primary HSM: The one used for signing OS builds as needed.
* Secondary HSM: A backup HSM with the wrap key imported, ready to take-over if the primary fails.
* APEX: (Android Pony EXpress) used for updating lower-level system modules
* APK signing + schemes: Each app comes in an individual module called APK (Android Package Kit). 
* AVB keys: The key used for verified boot, attesting to the integrity of the OS.
  It's fingerprint is shown on the screen when phone boots up. Usually can't be rotated.
* Wrap key: a AES symmetric key. This key is generated once on a trusted machine running TailsOS instead of the HSM.
* Key ID: a unique numeric identifier for keys used by the HSM.
* Core keys: Keys used to sign core OS components and some apps, such as SeedVault.
* Target files: All files created by the AOSP build process.
  These include `.img` disk images to be flashed to device partitions, but also their extracted contents.

## Goals

The Android Open Source Project (AOSP) which CalyxOS is built on
doesn't support signing with a HSM.
AOSP documentation and processes assumes that private key files will be accessible in plain text
during the time they are needed for signing.

Our goal is to improve on that and ensure that no single person ever
has access to the private key material.
This is to ensure that the organisation will always be able to
produce valid signatures, even after staff is leaving.
At the same time, it shouldn't be possible to copy private key material
to ensure that only authorized signatures get produced.
If we can't prevent unauthorized signatures (by e.g. a rogue employee),
we at least want to be able to detect them as soon as possible.

As a small non-profit, we like to familiarize ourselves with HSM signing
without making large up-front investments, e.g. in expensive HSM hardware.
Therefore, we aim for an interim solution that enables us to learn
and be fast to produce HSM signature as soon as possible.
Ideally, it should be possible to migrate key material to a more long term solution,
potentially involving more potent HSM devices
than the commodity devices we are starting with.

We typically need to sign releases for ~30 devices every 1-3 months.
Occasionally there may be an extra signature required if we update apps out of band using F-Droid repositories.
So signing speed or networked access are not a priority at the moment.

Being a distributed team we like to minimize the need for trusted in-person ceremonies as much as possible.
For starting normal operations, an initial ceremony should be sufficient.
Extra ceremonies (e.g. for key generation) should be avoided, if possible at all.

The bulk of our work is in making it possible
to produce all required signatures for an AOSP (or CalyxOS) release.
[Many modifications](https://review.calyxos.org/q/hashtag:%22pkcs11%22+(status:open%20OR%20status:merged)) are required for this.
We aim to make this work use the standard PKCS #11 interface,
so it is reusable for other HSM devices as well.

## Signing Keys

From [official documentation](https://source.android.com/docs/core/ota/sign_builds):

> Each key comes in two files: the certificate, which has the extension .x509.pem, and the private key, which has the extension .pk8. The private key should be kept secret and is needed to sign a package. The key may itself be protected by a password. The certificate, in contrast, contains only the public half of the key, so it can be distributed widely. It is used to verify a package has been signed by the corresponding private key.

Since we store the private parts of the keys on the HSM,
only the public `.pem` part is available in plain text on the file system.
The private part is stored encrypted with the wrap key.

### Overview of keys involved

Typically, each device has a large number of keys
that sign various parts of the operating system
such as partitions, apps and APEXes.
Since space on the HSM is limited
and unwrapping keys many times can lead to destroyed storage on the HSM,
we re-use keys as much as possible.

One reason to use different keys for each device
is to limit the impact of key compromise.
If keys leak in one point of time,
devices that were added after the leak aren't affected.
Since all our keys are in one HSM anyway,
this reason doesn't apply as strongly.

Keys are currently defined in a few places
and should be updated sparingly.
We need to ensure that the order is maintained.
Otherwise the key mapping script may generate different IDs
which will cause issues when builds are signed with unexpected keys.
A [static keymapper script](https://review.calyxos.org/c/CalyxOS/vendor_calyx/+/41752)
was developed, but more work is needed to prevent unintended key ID changes in the future.

As of writing, [the current list of all keys](https://gitlab.com/-/snippets/4889398)
and their ID was generated [with this script](https://review.calyxos.org/c/CalyxOS/vendor_calyx/+/41571/5/scripts/keymapper.id2b.include.sh).
The YubiHSM uses just IDs and the mapping shows
which ID matches which device/apex/etc key.
The available ID space of the device is `0x20` to `0xfe`.

By default, everything is shared by every device.
For example, `platform` will sign all platform for all devices.
Same for the other `7` core keys in `product/security`
and the various APEX keys: `apex_apk`, `apex_container`, `apex_payload`.

The only keys unique to each device is the `avb` key (Android Verified Boot).
However, that same device specific key is being used for OTA as well as
the other AVB variants
(`boot`, `dtbo`, `init_boot`, `recovery`, `system`, `system_other`, `vbmeta`, `vbmeta_system`, `vbmeta_vendor`, `vendor`).
These multiple AVB partitions could be signed by separate keys.
However, historically, we just have been signing all those partitions
with the same avb key (with the exception of `vbmeta_system`,
which might be a remnant of how stock Android did things).

An advantage of using the same key for all devices is
that it simplifies out-of-band updates
by using a single F-Droid repo for all devices with the same app
that can be updated on all devices.
This is specifically relevant to
Seedvault's platform key, microG, Chromium, etc.

For reference, [we link to](https://github.com/CalyxOS/vendor_calyx/blob/staging/android16/scripts/mkkeys.sh)
CalyxOS's old script to create keys.

#### Authentication Keys

In order to authenticate the usage of certain roles interaction with the HSM,
a specific key is needed.
Usually, this comes in the form of a password that the actual key is derived from.
The user typically only interacts with the password.

Each authentication key has capabilities and delegated capabilities
which limit the capabilities that can be given to new keys
created with that authentication key.

There are three Yubi HSM authentication keys we use:
* `signing_auth_key`: required for signing
* `audit_auth_key`: read-only to examine audit logs for a third party, does not allow signing access
* `admin_auth_key`: Just enough permissions to create more signing auth keys and audit auth keys, if needed

Each key requires it's own password.
Only the admin key is set up to have the ability to reset the HSM
to factory settings (outside of physically holding the rim of the HSM).

The capabilities and delegated capabilities of each key
are defined [at the top of our setup script](vendor.yubihsm.setup.py).

**TODO** Are all of those capabilities needed or could we reduce them
without shooting ourselves in the foot with regards to later usage.

**TODO** Define internal policy where/how to store auth key passwords and we will have access to them.

### Rationale of used key types

ECC (NIST P-384 curve) use less storage space
and signing with them is faster.
However, there are concerns about possible NSA backdoors
as there's precedent of NSA pushing backdoors through NIST.
There are more trusted ECC curves,
but those [aren't supported by Android](https://source.android.com/docs/security/features/apksigning/v2#signature-algorithm-ids).

Some keys need to be RSA for technical reasons,
specifically AVB and APEX payload keys.

The team feels that it is safer to use RSA keys across the board
and forego the benefits of using ECC keys.

### Wrapping of keys

Storage on Yubi HSM is limited to a point that it doesn't fit all keys. 
Therefore, keys are wrapped (i.e. encrypted with a wrap key)
and stored outside the HSM on the file system.
They get re-imported when needed.
It is important that the keys get backed up or they would be lost
as the HSM is not necessarily holding on to them.

While the keys are encrypted, for defense in depth
they should still not get published or shared with other team members. 

For a different device, the Nitrokey HSM
[the chip manufacturer stated](https://support.nitrokey.com/t/hsm2-possible-write-cycles/2593)
that there are guaranteed 500.000 writes per cell
and they tested it and got to 3 million writes
before the chip actually failed.
Our hope is that the Yubi HSM behaves similarly.

Ideally, we'd use key derivation instead, but that isn't supported by the Yubi HSM
for our use-case.

## Provisioning Ceremony

The goal of this ceremony is to generate initial key material on two HSMs
in a secure fashion, so we have one device as a backup,
but also export the wrap key in several shards,
so disaster recovery (in case both devices break) is possible
without just a few people being able to access our key material
in plain text.

There is [a provisioning script](https://review.calyxos.org/c/CalyxOS/vendor_calyx/+/41510/49/scripts/pkcs11/vendor.yubihsm.provision.sh)
that guides through the entire setup procedure.
Ideally its code gets audited
and the audited version is being used and verified during the ceremony.
This could be as simple as a SHA256 hash of a zip file
that the participants of the ceremony compare in full.

We are using TailsOS as an ephemeral operating system 
which is designed for live use (with optional persistence)
and has a good track record for security sensitive usages.
It's networking capabilities are not needed
and we plan to use it completely offline in an air gapped fashion.
Ideally, Tails runs on a trusted machine.

We plan on verifying the integrity of Tails used at the ceremony
to ensure it wasn't modified in any way.
The pre-existing OS can be used to hash the entire drive and then verify that hash.
[JuiceBox](https://github.com/juicebox-systems/ceremony)
[has scripts](https://github.com/juicebox-systems/ceremony/blob/2aaacadf6e6b86e1796bd4d5c65d4d8e23016d01/instructions/ceremony.typ#L545)
and documentation for doing that.

We'll use a flash drive with some prepared content/files preloaded.
The provision tooling also has a script to prepare the flash drive
with the necessary Debian packages needed for the ceremony.
The provisioning script will install the required packages offline on Tails.

It does not use the official yubikey tool for creating an AES wrap key
and exporting shards using Shamir Secret Sharing,
because the official setup tool shows the shards on screen for all to see
and doesn't provide an encrypted export mechanism.
It is also rather inflexible and does set up other keys in ways that are not useful for us.
Therefore, we use our own small python script to create a wrap key
and export encrypted shards.
Our own script also provisions a secondary HSM with the same wrap key,
so it can be used in case the primary fails without needing another trusted ceremony.

During setup, different keys get created each having their own password:
  * signing password: only one that usually gets used
  * audit password: read only key only for auditing
  * admin password: hsm admin stuff

YubiHSM domains are used to mark keys exportable (domain #2) and on demand keys (domain #3).
Domains are not exclusive, can belong to both sets. 
Any key that is generated on the device that is marked non-exportable,
cannot get backed up.

At the end of the ceremony, there's audit logs and keys in the `/dev/shm/keep` folder.
This folder must be manually saved and backed up.

In order to generate the rest of the signing keys,
the HSM must get plugged into a machine with the correct 'utilities'
and run the key generator script.
This doesn't need to happen during the ceremony
as these keys will get exported encrypted with the wrap key
and added to the overall backup.

### How shards are exported and kept safe

Before the provisioning ceremony each participant provides a public SSH key.
Ideally, this key [is not used for anything else](https://github.com/FiloSottile/age/discussions/540).
If that is not possible, the recommendation is to at least use an Ed25519 key.
All keys are part of the audited and verified provisioning package.

Unfortunately, the YubiHSM doesn't support generating the wrap key on device
and splitting it into encrypted shards.
This would be preferable for never exposing key material in plain text.
Even the official YubiHSM setup utility briefly holds the key material in RAM.
Since we are running a trusted ephemeral OS on a randomly bought machine
in an undisclosed location to generate the key material,
we decided that this is still a reasonable trade-off to make.

Our own provisioning script generates the wrap key with random bytes from the HSM (like the official setup tool)
and then using a [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
library to split the key into shards.
These shards get encrypted to the provided SSH public keys using [age](https://age-encryption.org/),
so no shard will leave the ceremony unencrypted.

A certain threshold of shards will be required
for recovering the wrap key to get access to all other keys.
This could happen when both HSMs fail
or when we want to move to another signing solution
and import our old keys into the new long-term solution.
Therefore, it is very important that all shard holders securely backup their access to the shard.
If too many participants lose access to their shard (or leave the organization), the wrap key can not be recovered.
Ideally, such a situation is recognized early, so re-keying can happen in another ceremony creating new shards.

## Signing Process

### Hardware requirements

* Memory: Estimated 25GB per parallel-signed device based on observations
* Disk space: Estimated 25GB per parallel-signed device.
* CPU: x86_64 (amd64)

### How AOSP signing works

Google has some [upstream documentation](https://source.android.com/docs/core/ota/sign_builds)
which may help to understand the process.

On a technical level, there are three scripts involved
in [making an AOSP release](https://github.com/CalyxOS/vendor_calyx/blob/staging/android16/scripts/release.sh):

1. [`sign_target_files_apks`](https://gitlab.com/CalyxOS/platform_build/-/blob/staging/android16/tools/releasetools/sign_target_files_apks.py?ref_type=heads)
 goes through all target files
 and *signs* everything that needs to be signed.
 It repackages the target files into a signed target files zip.
2. [`ota_from_target_files`](https://gitlab.com/CalyxOS/platform_build/-/blob/staging/android16/tools/releasetools/ota_from_target_files.py?ref_type=heads)
 *signs* the entire image with the release key.
3. `img_from_target_files` doesn't do any signing, just repackaging.


### APEX signing

> APEX files are signed in two ways.
> First, the apex_payload.img
> (specifically, the vbmeta descriptor appended to apex_payload.img) file is signed with a key.
> Then, the entire APEX is signed using the APK signature scheme v3.
> Two different keys are used in this process.
> 
> On the device side,
> a public key corresponding to the private key used to sign the vbmeta descriptor is installed.
> The APEX manager uses the public key to verify APEXes that are requested to be installed.
> Each APEX must be signed with different keys and is enforced both at build time and at runtime.

### Changes made to AOSP signing

In order to enable HSM signing for AOSP or to make the process faster,
we applied several changes to the signing process.
Here, we explain what we had to change and why.

The central change is hooking into the `sign_target_files_apks` script
with an interceptor
and change signing commands as needed
to allow for using keys stored on the HSM.
The interceptor is also needed for retrieving audit logs after each command.

**TODO** add more relevant changes we made

#### `apksigner` instead of `signapk`

[`signapk`](https://cs.android.com/android/platform/superproject/main/+/main:build/make/tools/signapk/src/com/android/signapk/SignApk.java)
was used to sign APEX containers and APKs,
but it was failing with YubiHSM 2 due to session exhaustion
that [we couldn't overcome](https://gitlab.com/CalyxOS/calyxos/-/work_items/3417),
but apksigner has been a viable alternative.
However, there was an alignment issue
that we could only fix [with a custom patch](https://review.calyxos.org/c/CalyxOS/platform_tools_apksig/+/41359).

### Closing signing sessions with `apksigner`

The `apksigner` tool which is heavily used doesn't close the Yubi HSM sessions on its own
leading to errors and requires waiting for sessions to time out.
We use [a patch](https://review.calyxos.org/c/CalyxOS/platform_tools_apksig/+/41550)
that does log out of `SunPKCS11` on exit.

### Batch mode for `apksigner` for improved performance

[This change](https://review.calyxos.org/c/CalyxOS/platform_tools_apksig/+/41551) is intended to enhance performance
by keeping the keystore loaded,
as `PKCS#11` keystores may take a significant time to load depending on the implementation.

### Parallel Signing

The HSM can only be used for one operation at a time,
but signing involves a lot more processing
most of which could be done in parallel.
Therefore we use our own `sign.sh` script which supports signing several builds at the same time.
It also sorts builds by keys available on the HSM
to reduce storage wear caused by deleting some keys and importing others.

## Backup and Restore

The wrap key gets backed up to shards which are distributed
among participants of the provisioning ceremony.
All other keys are stored on the file system
with their private parts encrypted with the wrap key.
These files should probably plugged into a trusted backup system
such as restic or borgbackup which back up to one or more location.
The backup password needs to have backups as well.
The backup should run periodically,
but at least after creating new keys.

In case of a storage failure, the key files can simply get restored
using the respective backup system.
The HSM can then pick them up again, unwrap and import them as needed.

If the HSM itself breaks, the secondary one can be used in its place.
Keys not yet imported, can be unwrapped and imported from the file system.
This typically happens automatically by our signing scripts.
When the secondary HSM breaks as well or ideally before,
a sufficient number of participants from initial provisioning ceremony 
needs to meet and repeat the ceremony with new HSM devices.


## Logging / Auditing

How do we make sure that people with physical access to the HSM
are not signing rogue builds?

We'll employ the [built-in audit functionality](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-logging.html)
of the Yubi HSM,
because that is the only way to reliably detect key usage.
It's logs get extracted after each operation
to ensure we are not having any holes in the log during normal operation.
Logs are then appended, published to a git repository 
and automatically verified for integrity by the CI system.

More work is needed to make sure operations that did happen
and did get published were expected and are matching actual releases.
As the key ID for each signing operation gets logged,
it may be possible to also automatically verify
that the expected keys got used the expected number of times.

The secondary HSM should get plugged in at specific intervals
(e.g. after each signing session with the primary HSM)
and audit logs exported to ensure that no signing is happening
without us noticing. 

For the initial audit log entry,
a random string of 32 bytes is used,
instead of the digest of the previous message.
It is essential to record and backup this initial value from both HSMs,
because it allows us to verify that future hash chains 
are in fact starting in this initial trust anchor.

**TODO** How can we be sure that exported audit logs are recent
and no replay attacks are happening?
[GitHub issue](https://github.com/Yubico/yubihsm-shell/issues/479)

The secondary HSM especially may be asked to perform (a set of) operations
that are impossible to guess in advance
and that manifest themselves in the audit log
to ensure that the presented log is indeed current and not replayed or prepared in advance.

Another option may be to allow auditors a network connection to the HSM
and perform auditing themselves.

### Technical implementation

As per provisioning scripts (see above), the YubiHSM 2 is configured
to force auditing of every command, and to refuse additional commands
when the log buffer is full.

To make sure all logs are extracted in a timely manner
and in association with the triggering command,
every signing-related command is passed through an
[interceptor script](https://review.calyxos.org/c/CalyxOS/vendor_calyx/+/41510), `scripts/pkcs11/vendor.yubihsm.interceptor.sh`
(link: [Gerrit](https://review.calyxos.org/q/%22Issue:+calyxos%233431%22),
[GitLab](https://gitlab.com/CalyxOS/calyxos/-/issues/3431)).
In addition to facilitating the success of signing transactions
by restarting failed components or retrying as needed,
this interceptor extracts logs to a file after each signing command.

Logs are extracted using the `extract_logs` function
in [`scripts/pkcs11/vendor.yubihsm.include.sh`](https://review.calyxos.org/c/CalyxOS/vendor_calyx/+/41510).
Its format is simple and plaintext,
but all aspects of log extraction can be modified in this function.

Example of a log entry written by `extract_logs`:
```
# 1763079385491  avbtool make_vbmeta_image --output IMAGES/vbmeta_vendor.img --key keys/0x2e00.pem --algorithm SHA256_RSA4096 --signing_helper vendor/calyx/scripts/pkcs11/signing_helper.openssl.sh --include_descriptors_from_image IMAGES/vendor.img --padding_size 4096 --rollback_index 1756684800 # Result: 0
 1479 cmd: 0x47 len:    53 sKey: 0x0001 tKey: 0x2e00 2Key: 0xffff res: 0xc7 tick:     862298 hash: 951a1b524623c98fa42dc016eba9183c
```
In this example, `1479` indicates that this was the `1479`th command that the HSM has audited.
There should be at least 1479 log entries, starting at 1, within the logs we store and maintain.

Although log entries are not specific about the exact interaction, by keeping these records,
an audit can ensure that each executed command is accounted for.

## Key attestation

Allows interested people to verify that our keys are in fact in a YubiHSM.
This is important to ensure that the signing officer is not using RSA keys to sign builds
that they have the plaintext key material for.
Our HSMs are set up so keys can only ever leave the HSM encrypted with the wrap key.
The HSM itself signs a attestation certificate for the keys
which proofs that keys were created on device.
As long as those keys are used for signing, there should be no way to acquire the key material
without knowledge of the complete wrap key.
Verifying the attestation certificate is
[documented on Gitlab](https://gitlab.com/CalyxOS/calyxos/-/work_items/3410#note_2722331678).

## YubiHSM 2

### Storage limitations

The YubiHSM 2 has limited storage space.
Example from an in-use HSM:
```bash
$ yubihsm-shell -a get-storage-info
free records: 177/256, free pages: 80/1024 page size: 126 bytes
```

YubiHSM 2's storage is divided into `256` records and `1024` pages,
with `126` bytes per page.

In practice, the following storage usage has been observed for a key and certificate of a given type:
- RSA 4096: 25 pages
    - Key: 1792 bytes (15 pages)
    - Cert: 1146 bytes (10 pages)
- ECC 384: 8 pages
    - Key: 144 bytes (2 pages)
    - Cert: 717 bytes (6 pages)
    - *Yes, the key uses much less space than the cert, here.*

When accounting for the negligible usage of other required objects - 
the authentication keys and wrap key -
this leaves room for a maximum of `40` RSA 4096-bit keys to be loaded
at any given time, assuming no other keys are present.

## Potential future improvements

### YubiHSM Networked

It may be possible to connect to the YubiHSM connector via the internet.
The connection can be encrypted and authenticated
via certificates in the HSM itself.
A small trusted computer such as a RaspberryPi is needed
to expose the HSM to the network.
Extra security measures such as Tor onion services
or wireguard tunnels (or both) could be employed to further secure the connection.

This would make it possible that the person who possesses HSM physically
does not even have the `auth_keys` (and password) themselves,
but are only able to share it over the network to authorized users
with the relevant authentication.

### Publicly auditability

It would be nice to soft-proof to the public
that we only sign official releases and nothing else.

[Third-party article about publicly auditable YubiHSM](https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e)

### Off-HSM certificate storage

As [outlined earlier](#Storage-limitations),
a certificate consumes significant storage space,
comprising `40%` of the on-HSM usage for an RSA 4096-bit entry
or 75% of the usage for an ECC 384-bit entry.
If these certificates could be kept off-HSM,
it would make more on-HSM storage available
without needing to move wrapped keys in and out (as often),
thus reducing complexity and wear on the HSM.
So, do they need to be stored on the HSM at all?
Kind of, due to the way Java's PKCS#11 support works.

Our whole reason for using an HSM is to secure our private keys.
Unlike private keys, certificates are public objects
that don't need to be stored in a non-extractable manner. 
Ultimately, an asymmetric signing operation makes use of a private key,
not a certificate.
However, by current design, PKCS#11 support via Java
requires certificates to be obtainable via the PKCS#11 provider
in order to perform signing.
For YubiHSM 2's implementation,
this does mean that the certificates need to be loaded into the HSM as well.

AOSP supports a `--signing_helper` for AVB signing,
and we implement this support in a script via pkcs11-tool or openssl.
Although they both use PKCS#11 for this signing,
*neither requires a certificate object on the HSM*;
they merely make use of the private key, 
and refer to on-disk certificate files when needed.
Already, this would seem to offer an opportunity to remove dozens of certificates from the HSM.
However, currently, our AVB keys also act as OTA keys,
which are used for whole-file signing with `signapk -w`
and by `--payload_signer`.
The former is Java-based,
so it continues to require a certificate to be loaded.

Investigating the behavior of `signapk -w`
and replacing it with an alternative
that does not depend on PKCS#11 via Java should eliminate the need,
in our current scheme, to have certificates stored on-HSM
for any of our device-specific keys (currently 27).
This would save 270 pages,
making room for another 10 RSA 4096-bit entries (including their certs)
or 33 ECC 384-bit entries (including their certs);
if certs weren't required, that number of pages would allow for
an additional 18 RSA 4096-bit keys or 135 ECC 384-bit keys.

To go further and free up even more space,
and potentially offer greater flexibility in signing implementation,
one idea could be to expand apksigner to support a signing helper itself, 
thereby eliminating the need to interact with Java's PKCS#11 at all.

Alternatively, perhaps YubiHSM's PKCS#11 library could be adapted
to support an option of providing certificate objects 
via on-disk storage rather than on-HSM storage.
