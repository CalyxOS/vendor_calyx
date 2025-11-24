# Provision a YubiHSM 2

This folder includes provisioning scripts for a YubiHSM 2.
They are meant to be used in a trusted provisioning ceremony
and will expect two factory reset HSMs.

## Preparing ceremony code

Ensure that all code and settings is properly set up.
E.g. make sure the proper public keys are stored in the `keys` folder
and added to `manifest.tsv`.
Similarly, the SDK and Debian packages should be current
and installable on the ephemeral ceremony OS (e.g. Tails). 

Once everything is good to go,
run the following script to create a `ceremony.zip`:

    ./prepare.package.sh

At the end, the SHA256 hash of the generated `ceremony.zip` file gets printed out
for verification purposes.
The `ceremony.zip` file should get audited
and its hash verified inside the trusted execution environment
of the ceremony before unpacking it.

## Ceremony setup

This was written for Tails 7.2,
but should be adaptable for other or future OSes as well.

* buy a sealed laptop in a random store right before the ceremony
* boot the pre-installed OS (most likely Windows)
* verify the Tails DVD (using powershell commands) 
  and compare with SHA256 hash of official `.iso` file
* boot into Tails environment using verified DVD
* set-up an admin account with a random password
* open Files program and insert flash drive with `ceremony.zip`
* verify there's nothing else on that drive and nothing else gets executed
* copy `ceremony.zip` to home folder
* extract with `7z x ceremony.zip` in terminal
* run `cd ceremony` to enter folder with ceremony scripts

## Executing the ceremony

Run `./start.sh` to begin the ceremony
and follow on-screen instructions.

The scripts will set-up three auth passwords and a secret wrap key
which will be split into a pre-configured number of shards using Shamir's secret sharing.
These shards and the initial audit logs will be saved to `$HOME/CalyxHSM`
or a different folder, if set with the `KEEP_PATH` environment variable.

## After the ceremony

Send each encrypted shard to the owner of the respective public key
and `git push` the contents of `$HOME/CalyxHSM/logs`
to an append-only git repository
that has force pushing disabled and has an independent party regularly pulling from it.
