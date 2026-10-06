#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import json
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, install_executable, run

SUBJECT = "/C=US/O=Calyx Institute/CN=updatekeys recovery"
NONCE = "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \\n')"

AVBTOOL = """#!/bin/bash
set -euo pipefail
while (($#)); do
  case "$1" in
    --key) key=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
: > "${output:?}"
target=$(realpath -m --relative-to="$PWD" "${output%.tmp}")
[ "${FAIL_AVB_OUTPUT:-}" != "$target" ] || exit 31
printf 'AVB PUBLIC KEY for %s\\n' "$(head -n1 "${key:?}")" > "$output"
"""

OPENSSL = f"""#!/bin/bash
set -euo pipefail
command=$1
shift
[ "${{FAIL_KEY_GENERATION:-}}" != y ] || [ "$command" != genpkey ] || {{
  echo "genpkey: simulated failure" >&2
  exit 20
}}
[ "${{FAIL_CERTIFICATE_GENERATION:-}}" != y ] || [ "$command" != req ] || \\
  exit 21
while (($#)); do
  case "$1" in
    -out) output=$2; shift 2 ;;
    -in) input=$2; shift 2 ;;
    -key) key=$2; shift 2 ;;
    -subj) subject=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -z "${{FAIL_OPENSSL_OUTPUT:-}}" ] || \\
  [ "$FAIL_OPENSSL_OUTPUT" != "${{output:-}}" ] || exit 22
case "$command" in
  genrsa|genpkey) printf 'PRIVATE KEY #%s\\n' "{NONCE}" > "${{output:?}}" ;;
  pkcs8) head -n1 "${{input:?}}" > "${{output:?}}" ;;
  req)
    printf 'CERTIFICATE subject=%s for %s\\n' "${{subject:?}}" \\
      "$(head -n1 "${{key:?}}")" > "${{output:?}}"
    ;;
  *) echo "unexpected openssl command: $command" >&2; exit 2 ;;
esac
"""


MOVE = """#!/bin/bash
set -euo pipefail
[ -z "${FAIL_MOVE_SOURCE:-}" ] || \\
  [ "$FAIL_MOVE_SOURCE" != "$1" ] || exit 40
exec /usr/bin/mv "$@"
"""


Manifest = dict[str, tuple[int, bytes]]


@dataclass(frozen=True)
class Tree:
    """
    Keys and stand-in tools for running updatekeys.sh.

    Every generated private key carries a fresh generation tag, and every
    certificate and AVB public key names the private key it was made from.
    """

    root: Path
    keymapper_file: str | None = None

    @property
    def keys(self) -> Path:
        return self.root / "keys"

    def run(
        self,
        device: str = "bramble",
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        (self.keys / device).mkdir(parents=True, exist_ok=True)
        tools = self.root / "tools"
        environment = {
            "KEYMAPPER": "id2b",
            "PATH": f"{self.root / 'mock-bin'}:/usr/bin:/bin",
            "AVBTOOL_BIN": str(tools / "avbtool"),
        }
        if self.keymapper_file:
            environment["KEYMAPPER_FILE"] = self.keymapper_file
        environment.update(overrides)
        return run(
            [SCRIPTS_DIR / "updatekeys.sh", f"keys/{device}", SUBJECT],
            cwd=self.root,
            env=environment,
            check=False,
        )

    def succeed(self, **overrides: str) -> Manifest:
        result = self.run(**overrides)
        assert result.returncode == 0, result.stderr
        return self.manifest()

    def fail(self, **overrides: str) -> Manifest:
        result = self.run(**overrides)
        assert result.returncode != 0, result.stdout
        return self.manifest()

    def manifest(self) -> Manifest:
        if not self.keys.exists():
            return {}
        return {
            str(path.relative_to(self.keys)): (
                stat.S_IMODE(path.stat().st_mode),
                path.read_bytes(),
            )
            for path in sorted(self.keys.rglob("*"))
            if path.is_file()
        }

    def seed(self, name: str, contents: str) -> None:
        path = self.keys / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)


def install_tree(
    root: Path,
    *,
    keymapper_config: dict[str, str] | None = None,
) -> Tree:
    tools = root / "tools"
    tools.mkdir(parents=True)
    install_executable(tools / "avbtool", AVBTOOL)

    mock_directory = root / "mock-bin"
    mock_directory.mkdir()
    install_executable(mock_directory / "openssl", OPENSSL)
    install_executable(mock_directory / "mv", MOVE)

    keymapper_file = None
    if keymapper_config:
        keymapper_file = str(root / "keymapper.id2b.configured.py")
        Path(keymapper_file).write_text(
            "import dataclasses\n"
            "from signing.keymap import Id2bKeymapper\n"
            "\n"
            "def create_keymapper(environment, metadata, *, extra_devices):\n"
            "    mapper = Id2bKeymapper(\n"
            "        metadata, extra_devices=extra_devices\n"
            "    )\n"
            "    mapper.config = dataclasses.replace(\n"
            f"        mapper.config, **{keymapper_config!r}\n"
            "    )\n"
            "    return mapper\n",
        )
    return Tree(root, keymapper_file)


def assert_derived_from_private_keys(manifest: Manifest) -> None:
    for path, (_, contents) in manifest.items():
        if path.endswith(".x509.pem"):
            private_key = manifest[path.removesuffix(".x509.pem") + ".pk8"]
            assert contents.endswith(b" for " + private_key[1])
        elif path.endswith(".avbpubkey"):
            private_key = manifest[path.removesuffix(".avbpubkey") + ".pem"]
            assert contents == b"AVB PUBLIC KEY for " + private_key[1]


@pytest.mark.parametrize(
    "left_behind",
    (b"", b"STALE PUBLIC KEY\n", None),
    ids=("empty", "stale", "removed"),
)
def test_rerun_restores_avb_public_keys(
    tmp_path: Path,
    left_behind: bytes | None,
) -> None:
    tree = install_tree(tmp_path)
    original = tree.succeed()
    assert "0x2000.pem" in original
    assert "0x2008.pem" not in original
    assert_derived_from_private_keys(original)

    for public_key in ("0x1300.avbpubkey", "0x2000.avbpubkey"):
        path = tree.keys / public_key
        if left_behind is None:
            path.unlink()
        else:
            path.write_bytes(left_behind)
    assert tree.succeed() == original


def test_avb_pkmd_bin_replaces_the_vbmeta_public_key(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)
    tree.seed("avb_pkmd.bin", "CUSTOM PUBLIC KEY\n")

    manifest = tree.succeed()
    assert "avb_pkmd.bin" not in manifest
    assert manifest["0x2000.avbpubkey"][1] == b"CUSTOM PUBLIC KEY\n"


def test_legacy_vbmeta_system_failure_recovers(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)
    failed = tree.fail(
        device="cheetah",
        KEYMAPPER="legacy",
        FAIL_OPENSSL_OUTPUT="keys/cheetah/avb_vbmeta_system.pem",
    )
    assert "cheetah/avb.pem" in failed
    assert "cheetah/avb_vbmeta_system.pem" not in failed

    recovered = tree.succeed(device="cheetah", KEYMAPPER="legacy")
    assert "cheetah/avb_vbmeta_system.pem" in recovered
    assert recovered["cheetah/avb.pem"] == failed["cheetah/avb.pem"]
    assert_derived_from_private_keys(recovered)


@pytest.mark.parametrize(
    ("keymapper", "device", "vbmeta"),
    (("id2b", "bramble", "0x2000"), ("legacy", "cheetah", "cheetah/avb")),
)
@pytest.mark.parametrize("key_suffix", (".key", ""))
def test_key_suffix_names_the_vbmeta_keys(
    tmp_path: Path,
    keymapper: str,
    device: str,
    vbmeta: str,
    key_suffix: str,
) -> None:
    tree = install_tree(tmp_path)

    manifest = tree.succeed(
        device=device,
        KEYMAPPER=keymapper,
        KEY_SUFFIX=key_suffix,
    )

    assert f"{vbmeta}{key_suffix}" in manifest
    assert f"{vbmeta}.pem" not in manifest


def test_key_without_certificate_is_refused_until_removed(
    tmp_path: Path,
) -> None:
    tree = install_tree(tmp_path)
    failed = tree.fail(FAIL_CERTIFICATE_GENERATION="y")
    assert "0x1100.pk8" in failed
    assert "0x1100.x509.pem" not in failed

    refused = tree.run()
    assert refused.returncode != 0
    assert "exists without" in refused.stderr
    assert "restore the certificate" in refused.stderr.lower()
    assert "Traceback" not in refused.stderr
    assert tree.manifest() == failed

    (tree.keys / "0x1100.pk8").unlink()
    recovered = tree.succeed()
    assert "0x1100.x509.pem" in recovered
    assert_derived_from_private_keys(recovered)


def test_certificate_without_private_key_is_refused(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)
    tree.seed("0x1100.x509.pem", "EXISTING CERTIFICATE\n")
    before = tree.manifest()

    assert tree.fail() == before


def test_key_generation_failure_leaves_no_key(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)

    assert tree.fail(FAIL_KEY_GENERATION="y") == {}
    assert (
        "genpkey: simulated failure"
        in tree.run(
            FAIL_KEY_GENERATION="y",
        ).stderr
    )


def test_avb_key_failures_recover(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)
    vbmeta_failed = tree.fail(FAIL_AVB_OUTPUT="keys/0x2000.avbpubkey")
    assert "0x2000.pem" in vbmeta_failed
    assert "0x2000.avbpubkey" not in vbmeta_failed

    payload_key_failed = tree.fail(FAIL_OPENSSL_OUTPUT="keys/0x1300.pem")
    assert "0x2000.avbpubkey" in payload_key_failed
    assert "0x1300.pem" not in payload_key_failed

    payload_failed = tree.fail(FAIL_AVB_OUTPUT="keys/0x1300.avbpubkey")
    assert "0x1300.pem" in payload_failed
    assert "0x1300.avbpubkey" not in payload_failed

    recovered = tree.succeed()
    assert recovered["0x2000.pem"] == vbmeta_failed["0x2000.pem"]
    assert recovered["0x1300.pem"] == payload_failed["0x1300.pem"]
    assert_derived_from_private_keys(recovered)


def test_orphaned_avb_public_keys_are_replaced(tmp_path: Path) -> None:
    tree = install_tree(tmp_path)
    for public_key in ("0x1300.avbpubkey", "0x2000.avbpubkey"):
        tree.seed(public_key, "ORPHANED PUBLIC KEY\n")

    manifest = tree.succeed()
    assert_derived_from_private_keys(manifest)


def test_separate_vbmeta_system_key_recovers_and_is_kept(
    tmp_path: Path,
) -> None:
    tree = install_tree(
        tmp_path,
        keymapper_config={"avb_consolidation": "none"},
    )
    failed = tree.fail(FAIL_OPENSSL_OUTPUT="keys/0x2008.pem")
    assert "0x2000.pem" in failed
    assert "0x2008.pem" not in failed

    recovered = tree.succeed()
    assert "0x2008.pem" in recovered
    assert tree.succeed() == recovered


def test_separate_apex_payload_keys(tmp_path: Path) -> None:
    tree = install_tree(
        tmp_path,
        keymapper_config={"apex_consolidation": "none"},
    )

    manifest = tree.succeed()

    assert_derived_from_private_keys(manifest)
    payload_keys = [path for path in manifest if path.startswith("0x13")]
    for suffix in (".pem", ".avbpubkey"):
        assert sum(path.endswith(suffix) for path in payload_keys) == 55


def test_runtime_key_migration_recovers_from_move_failure(
    tmp_path: Path,
) -> None:
    tree = install_tree(tmp_path)
    tree.seed("com.android.runtime.release.pk8", "LEGACY KEY\n")
    tree.seed("com.android.runtime.release.x509.pem", "LEGACY CERT\n")

    failed = tree.fail(
        FAIL_MOVE_SOURCE="keys/com.android.runtime.release.x509.pem",
    )
    assert failed["com.android.runtime.pk8"][1] == b"LEGACY KEY\n"
    assert "com.android.runtime.release.x509.pem" in failed

    recovered = tree.succeed()
    assert not any(".release." in path for path in recovered)
    assert recovered["com.android.runtime.pk8"][1] == b"LEGACY KEY\n"
    assert recovered["com.android.runtime.x509.pem"][1] == b"LEGACY CERT\n"


@pytest.mark.parametrize("suffix", (".pk8", ".x509.pem"))
def test_partial_runtime_key_pair_migrates(
    tmp_path: Path,
    suffix: str,
) -> None:
    tree = install_tree(tmp_path)
    tree.seed(f"com.android.runtime.release{suffix}", "LEGACY\n")

    manifest = tree.succeed()
    assert f"com.android.runtime.release{suffix}" not in manifest
    assert manifest[f"com.android.runtime{suffix}"][1] == b"LEGACY\n"


def test_extra_device_gets_its_own_avb_key(tmp_path: Path) -> None:
    bramble = install_tree(tmp_path / "bramble").succeed(KEYMAPPER="id2b")

    manifest = install_tree(tmp_path / "extra").succeed(
        device="newdevice",
        KEYMAPPER="id2b",
        EXTRA_DEVICES="newdevice",
    )

    assert sorted(manifest) == sorted(
        name.replace("0x20", "0x3e", 1) for name in bramble
    )


def test_updatekeys_gives_its_files_the_modes_of_the_bash_run(
    tmp_path: Path,
) -> None:
    expected = json.loads(
        (
            SCRIPTS_DIR / "tests" / "fixtures" / "updatekeys-modes.json"
        ).read_text(),
    )

    manifest = install_tree(tmp_path).succeed()

    assert {path: oct(mode) for path, (mode, _) in manifest.items()} == expected
