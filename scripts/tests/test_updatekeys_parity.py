#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, TEST_METADATA, run
from signing.metadata import load_metadata

SUBJECT = "/C=US/O=Calyx Institute/CN=updatekeys parity"
MODES = ("bash", "guarded", "full")
GUARDED_FLAGS = {
    "USE_PYTHON_SIGNING": "y",
    "USE_PYTHON_AVB": "y",
    "USE_PYTHON_KEY_MIGRATION": "y",
}
FLAGS = {
    "bash": {},
    "guarded": GUARDED_FLAGS,
    "full": {"USE_PYTHON_UPDATEKEYS": "y"},
}
GENERATION = re.compile(rb"#[0-9a-f]{16}")
NONCE = "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \\n')"

MAKE_KEY = f"""#!/bin/bash
set -euo pipefail
mkdir -p "$(dirname "$1")"
[ "${{FAIL_KEY_GENERATION:-}}" != y ] || exit 20
key="PRIVATE KEY #{NONCE}"
printf '%s\\n' "$key" > "$1.pk8"
chmod 0600 "$1.pk8"
[ "${{FAIL_CERTIFICATE_GENERATION:-}}" != y ] || exit 21
printf 'CERTIFICATE subject=%s for %s\\n' "$2" "$key" > "$1.x509.pem"
"""

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
[ "${{FAIL_KEY_GENERATION:-}}" != y ] || [ "$command" != genpkey ] || exit 20
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


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


Manifest = dict[str, tuple[int, bytes]]


@dataclass(frozen=True)
class Tree:
    """
    Keys and stand-in tools for running updatekeys.sh in one orchestration
    mode.

    Every generated private key carries a fresh generation tag, and every
    certificate and AVB public key names the private key it was made from.
    """

    root: Path
    mode: str
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
            "METADATA_FILE": str(TEST_METADATA),
            "MAKE_KEY_BIN": str(tools / "make_key"),
            "AVBTOOL_BIN": str(tools / "avbtool"),
            "GENERATE_VERITY_KEY_BIN": str(tools / "generate_verity_key"),
            **FLAGS[self.mode],
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
    mode: str,
    *,
    keymapper_replacement: tuple[str, str] | None = None,
) -> Tree:
    tools = root / "tools"
    tools.mkdir(parents=True)
    if mode == "bash":
        _write_executable(tools / "make_key", MAKE_KEY)
    _write_executable(tools / "generate_verity_key", "#!/bin/sh\n")
    _write_executable(tools / "avbtool", AVBTOOL)

    mock_directory = root / "mock-bin"
    mock_directory.mkdir()
    _write_executable(mock_directory / "openssl", OPENSSL)
    _write_executable(mock_directory / "mv", MOVE)

    keymapper_file = None
    if keymapper_replacement:
        source = (SCRIPTS_DIR / "keymapper.id2b.include.sh").read_text()
        assert keymapper_replacement[0] in source
        keymapper_file = str(root / "keymapper.id2b.configured.include.sh")
        Path(keymapper_file).write_text(
            source.replace(*keymapper_replacement, 1),
        )
    return Tree(root, mode, keymapper_file)


def install_trees(
    tmp_path: Path,
    modes: tuple[str, ...] = MODES,
    **options: tuple[str, str],
) -> list[Tree]:
    return [install_tree(tmp_path / mode, mode, **options) for mode in modes]


def assert_parity(manifests: list[Manifest]) -> None:
    normalized = [
        {
            path: (mode, GENERATION.sub(b"#N", contents))
            for path, (mode, contents) in manifest.items()
        }
        for manifest in manifests
    ]
    for other in normalized[1:]:
        assert other == normalized[0]


def assert_derived_from_private_keys(manifest: Manifest) -> None:
    for path, (_, contents) in manifest.items():
        if path.endswith(".x509.pem"):
            private_key = manifest[path.removesuffix(".x509.pem") + ".pk8"]
            assert contents.endswith(b" for " + private_key[1])
        elif path.endswith(".avbpubkey"):
            private_key = manifest[path.removesuffix(".avbpubkey") + ".pem"]
            assert contents == b"AVB PUBLIC KEY for " + private_key[1]


def test_reruns_keep_every_key(tmp_path: Path) -> None:
    originals: list[Manifest] = []
    for tree in install_trees(tmp_path):
        original = tree.succeed()
        assert "0x2000.pem" in original
        assert "0x2008.pem" not in original
        assert_derived_from_private_keys(original)

        assert tree.succeed() == original
        originals.append(original)

    assert_parity(originals)


@pytest.mark.parametrize(
    "left_behind",
    (b"", b"STALE PUBLIC KEY\n", None),
    ids=("empty", "stale", "removed"),
)
def test_rerun_restores_avb_public_keys(
    tmp_path: Path,
    left_behind: bytes | None,
) -> None:
    for tree in install_trees(tmp_path):
        original = tree.succeed()

        for public_key in ("0x1300.avbpubkey", "0x2000.avbpubkey"):
            path = tree.keys / public_key
            if left_behind is None:
                path.unlink()
            else:
                path.write_bytes(left_behind)
        assert tree.succeed() == original


def test_avb_pkmd_bin_replaces_the_vbmeta_public_key(tmp_path: Path) -> None:
    manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
        tree.seed("avb_pkmd.bin", "CUSTOM PUBLIC KEY\n")

        manifest = tree.succeed()
        assert "avb_pkmd.bin" not in manifest
        assert manifest["0x2000.avbpubkey"][1] == b"CUSTOM PUBLIC KEY\n"
        manifests.append(manifest)

    assert_parity(manifests)


def test_legacy_vbmeta_system_failure_recovers(tmp_path: Path) -> None:
    failed_manifests: list[Manifest] = []
    recovered_manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
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
        failed_manifests.append(failed)
        recovered_manifests.append(recovered)

    assert_parity(failed_manifests)
    assert_parity(recovered_manifests)


@pytest.mark.parametrize("keymapper", ("id2b", "legacy"))
@pytest.mark.parametrize("key_suffix", (".key", ""))
def test_key_suffix_names_the_vbmeta_keys(
    tmp_path: Path,
    keymapper: str,
    key_suffix: str,
) -> None:
    manifests = [
        tree.succeed(KEYMAPPER=keymapper, KEY_SUFFIX=key_suffix)
        for tree in install_trees(tmp_path)
    ]

    assert_parity(manifests)


def test_key_without_certificate_is_refused_until_removed(
    tmp_path: Path,
) -> None:
    failed_manifests: list[Manifest] = []
    recovered_manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
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
        failed_manifests.append(failed)
        recovered_manifests.append(recovered)

    assert_parity(failed_manifests)
    assert_parity(recovered_manifests)


def test_certificate_without_private_key_is_refused(tmp_path: Path) -> None:
    manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
        tree.seed("0x1100.x509.pem", "EXISTING CERTIFICATE\n")
        before = tree.manifest()

        assert tree.fail() == before
        manifests.append(before)

    assert_parity(manifests)


def test_key_generation_failure_leaves_no_key(tmp_path: Path) -> None:
    for tree in install_trees(tmp_path):
        assert tree.fail(FAIL_KEY_GENERATION="y") == {}


def test_avb_key_failures_recover(tmp_path: Path) -> None:
    steps: list[list[Manifest]] = [[], [], [], []]
    for tree in install_trees(tmp_path):
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
        for step, manifest in zip(
            steps,
            (vbmeta_failed, payload_key_failed, payload_failed, recovered),
        ):
            step.append(manifest)

    for step in steps:
        assert_parity(step)


def test_orphaned_avb_public_keys_are_replaced(tmp_path: Path) -> None:
    manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
        for public_key in ("0x1300.avbpubkey", "0x2000.avbpubkey"):
            tree.seed(public_key, "ORPHANED PUBLIC KEY\n")

        manifest = tree.succeed()
        assert_derived_from_private_keys(manifest)
        manifests.append(manifest)

    assert_parity(manifests)


def test_separate_vbmeta_system_key_recovers_and_is_kept(
    tmp_path: Path,
) -> None:
    failed_manifests: list[Manifest] = []
    recovered_manifests: list[Manifest] = []
    trees = install_trees(
        tmp_path,
        ("bash", "guarded"),
        keymapper_replacement=(
            "key_avb_consolidation=all",
            "key_avb_consolidation=none",
        ),
    )
    for tree in trees:
        failed = tree.fail(FAIL_OPENSSL_OUTPUT="keys/0x2008.pem")
        assert "0x2000.pem" in failed
        assert "0x2008.pem" not in failed

        recovered = tree.succeed()
        assert "0x2008.pem" in recovered
        assert tree.succeed() == recovered
        failed_manifests.append(failed)
        recovered_manifests.append(recovered)

    assert_parity(failed_manifests)
    assert_parity(recovered_manifests)


def test_separate_apex_payload_keys(tmp_path: Path) -> None:
    manifests: list[Manifest] = []
    trees = install_trees(
        tmp_path,
        ("bash", "guarded"),
        keymapper_replacement=(
            "key_apex_consolidation=dual",
            "key_apex_consolidation=none",
        ),
    )
    for tree in trees:
        manifest = tree.succeed()
        assert_derived_from_private_keys(manifest)
        manifests.append(manifest)

    assert_parity(manifests)
    payload_keys = [path for path in manifests[0] if path.startswith("0x13")]
    for suffix in (".pem", ".avbpubkey"):
        assert sum(path.endswith(suffix) for path in payload_keys) == len(
            load_metadata(TEST_METADATA).arrays["keys_apex"],
        )


def test_runtime_key_migration_recovers_from_move_failure(
    tmp_path: Path,
) -> None:
    failed_manifests: list[Manifest] = []
    recovered_manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
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
        failed_manifests.append(failed)
        recovered_manifests.append(recovered)

    assert_parity(failed_manifests)
    assert_parity(recovered_manifests)


@pytest.mark.parametrize("suffix", (".pk8", ".x509.pem"))
def test_partial_runtime_key_pair_migrates(
    tmp_path: Path,
    suffix: str,
) -> None:
    manifests: list[Manifest] = []
    for tree in install_trees(tmp_path):
        tree.seed(f"com.android.runtime.release{suffix}", "LEGACY\n")

        manifest = tree.succeed()
        assert f"com.android.runtime.release{suffix}" not in manifest
        assert manifest[f"com.android.runtime{suffix}"][1] == b"LEGACY\n"
        manifests.append(manifest)

    assert_parity(manifests)


def test_extra_device_gets_its_own_avb_key(tmp_path: Path) -> None:
    manifests = [
        tree.succeed(
            device="newdevice",
            KEYMAPPER="id2b",
            EXTRA_DEVICES="newdevice",
        )
        for tree in install_trees(tmp_path)
    ]

    assert "0x3e00.pem" in manifests[0]
    assert_parity(manifests)
