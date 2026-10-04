#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, default_signal_dispositions, run_cli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from signing.metadata import load_metadata
from signing.sign_orchestration import (
    SignOrchestrator,
    SignStepError,
    load_devices_file,
)
from yubihsm.defs import COMMAND, OBJECT
from yubihsm_emulator import Connector

BUILD_NUMBER = "2026081500"
OLD_BUILD_NUMBER = "2026081400"

FAKE_RELEASE_SH = """\
#!/bin/sh
set -e
device="$1"
case " ${REQUIRE_IMPORTED_KEY:-} " in
  *" $device="*)
    key_id=${REQUIRE_IMPORTED_KEY#*$device=}
    key_id=${key_id%% *}
    yubihsm-has-key "$key_id"
    ;;
esac
mkdir -p "out/release-$device-$BUILD_NUMBER"
printf '%s' "signed-$device-$BUILD_NUMBER" \\
  > "out/release-$device-$BUILD_NUMBER/output.bin"
"""

YUBIHSM_HAS_KEY = f"""#!{sys.executable}
import os
import sys

from yubihsm import YubiHsm
from yubihsm.defs import OBJECT

session = YubiHsm.connect(
    os.environ["YUBIHSM_CONNECTOR"]
).create_session_derived(
    int(os.environ["YUBIHSM_AUTHKEY"], 16), os.environ["YUBIHSM_PASSWORD"]
)
found = session.list_objects(
    object_id=int(sys.argv[1], 16), object_type=OBJECT.ASYMMETRIC_KEY
)
session.close()
sys.exit(0 if found else 1)
"""

FAKE_GENERATE_DELTA_SH = """\
#!/bin/sh
set -e
out="archive/release-$1-$3"
printf '%s' "delta-$1-$2-$3" > "$out/$1-incremental-$2-$3.zip"
"""

FAKE_DF = """\
#!/bin/sh
case "$1" in
  --output=avail) printf 'Avail\\n%s\\n' "${FAKE_DF_AVAIL:-1073741824000}" ;;
  *) printf 'Filesystem Size Used Avail Use%% Mounted on\\n' ;;
esac
"""


def _install(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def sign_tree(tmp_path: Path) -> Path:
    """
    A work directory next to fake release.sh and generate_delta.sh, so
    that `python3 -m signing sign-orchestrate` runs end to end against
    them.
    """
    _install(tmp_path / "fakes" / "release.sh", FAKE_RELEASE_SH)
    _install(tmp_path / "fakes" / "generate_delta.sh", FAKE_GENERATE_DELTA_SH)
    _install(tmp_path / "bin" / "df", FAKE_DF)
    work = tmp_path / "work"
    (work / "tmp").mkdir(parents=True)
    return work


def _write_target_files(work: Path, device: str, build: str) -> None:
    (work / f"calyx_{device}-target_files-{build}.zip").write_bytes(b"")


def _archive_previous_build(work: Path, device: str, build: str) -> None:
    directory = work / "archive" / f"release-{device}-{build}"
    directory.mkdir(parents=True)
    (directory / f"{device}-target_files-{build}.zip").write_bytes(b"")


def _archive_manifest(work: Path) -> dict[str, bytes]:
    archive = work / "archive"
    if not archive.is_dir():
        return {}
    return {
        str(path.relative_to(archive)): path.read_bytes()
        for path in sorted(archive.rglob("*"))
        if path.is_file()
    }


def run_sign_orchestrate(
    work: Path,
    *,
    devices: tuple[str, ...] | None = ("bramble",),
    environment: Mapping[str, str | None] | None = None,
    answers: str = "",
) -> subprocess.CompletedProcess[str]:
    devices_file = work / "devices"
    if devices is not None:
        devices_file.write_text(f"devices=({' '.join(devices)})\n")
    variables = {
        **os.environ,
        "PATH": f"{work.parent / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(SCRIPTS_DIR),
        "TMPDIR": str(work / "tmp"),
        "PKCS11_VENDOR": "",
        "BUILD_NUMBER": BUILD_NUMBER,
        "PREV_BUILD_NUMBER": "",
        "NUM_SIGN_JOBS": "2",
        "NUM_INCREMENTAL_JOBS": "2",
        **(environment or {}),
    }
    return run_cli(
        [
            "sign-orchestrate",
            "--metadata",
            str(SCRIPTS_DIR / "metadata.py"),
            "--devices-file",
            str(devices_file),
            "--release-script",
            str(work.parent / "fakes" / "release.sh"),
            "--generate-delta-script",
            str(work.parent / "fakes" / "generate_delta.sh"),
        ],
        cwd=work,
        env={
            name: value
            for name, value in variables.items()
            if value is not None
        },
        replace_env=True,
        input_text=answers,
        check=False,
    )


def test_sign_orchestrate_signs_into_archive_without_incrementals(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert _archive_manifest(sign_tree) == {
        f"release-bramble-{BUILD_NUMBER}/output.bin": (
            f"signed-bramble-{BUILD_NUMBER}".encode()
        ),
    }
    assert list((sign_tree / "tmp").iterdir()) == []


def test_sign_orchestrate_skips_symlinked_target_files(sign_tree: Path) -> None:
    """
    Target files and archive directories that are symlinks are not
    picked up.
    """
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    elsewhere = (
        sign_tree.parent / f"calyx_redfin-target_files-{BUILD_NUMBER}.zip"
    )
    elsewhere.write_bytes(b"")
    (sign_tree / elsewhere.name).symlink_to(elsewhere)

    result = run_sign_orchestrate(
        sign_tree,
        devices=("bramble", "redfin"),
        environment={"SIGN_ASSUME_YES": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert list(_archive_manifest(sign_tree)) == [
        f"release-bramble-{BUILD_NUMBER}/output.bin",
    ]


def test_sign_orchestrate_dry_run_prints_the_steps_instead_of_running_them(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _archive_previous_build(sign_tree, "bramble", OLD_BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "PREV_BUILD_NUMBER": OLD_BUILD_NUMBER,
            "DRY_RUN": "y",
        },
    )

    assert result.returncode == 0, result.stderr
    assert (
        f"sign_builds bramble,{BUILD_NUMBER},{BUILD_NUMBER}\n\n"
        "upload_logs\n\n"
        f"generate_incrementals bramble,{OLD_BUILD_NUMBER},{BUILD_NUMBER}\n\n"
        "upload_logs\n\n"
    ) in result.stderr
    assert not (
        sign_tree / "archive" / f"release-bramble-{BUILD_NUMBER}"
    ).exists()


def test_sign_orchestrate_finds_no_prior_build_for_a_word_that_is_none(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _archive_previous_build(sign_tree, "bramble", OLD_BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "PREV_BUILD_NUMBER": f"{OLD_BUILD_NUMBER},",
            "DRY_RUN": "y",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "generate_incrementals" not in result.stderr


def test_sign_orchestrate_keeps_a_zero_padded_build_number(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", "0042")

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "BUILD_NUMBER": "0042"},
    )

    assert result.returncode == 0, result.stderr
    assert _archive_manifest(sign_tree) == {
        "release-bramble-0042/output.bin": b"signed-bramble-0042",
    }


def test_sign_orchestrate_stops_without_a_devices_file(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        devices=None,
        environment={"SIGN_ASSUME_YES": "y"},
    )

    assert result.returncode == 1
    assert "devices: No such file or directory" in result.stderr
    assert "SIGN_ASSUME_YES=y is set, not retrying." in result.stderr
    assert "Traceback" not in result.stderr
    assert not (
        sign_tree / "archive" / f"release-bramble-{BUILD_NUMBER}"
    ).exists()


def test_sign_orchestrate_generates_incremental_from_prior_build(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _archive_previous_build(sign_tree, "bramble", OLD_BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "PREV_BUILD_NUMBER": OLD_BUILD_NUMBER,
        },
    )

    assert result.returncode == 0, result.stderr
    incremental = (
        f"release-bramble-{BUILD_NUMBER}/"
        f"bramble-incremental-{OLD_BUILD_NUMBER}-{BUILD_NUMBER}.zip"
    )
    assert _archive_manifest(sign_tree)[incremental] == (
        f"delta-bramble-{OLD_BUILD_NUMBER}-{BUILD_NUMBER}".encode()
    )


def test_sign_orchestrate_exits_cleanly_with_nothing_to_sign(
    sign_tree: Path,
) -> None:
    (sign_tree / "archive").mkdir()

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y"},
    )

    assert result.returncode == 0, result.stderr
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_aborts_when_missing_target_files_declined(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        devices=("bramble", "redfin"),
        answers="n\nn\n",
    )

    assert result.returncode != 0
    assert "redfin" in result.stdout
    assert "Ready?" not in result.stdout
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_asks_for_yubihsm_credentials_after_free_space(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _install(sign_tree / "logs" / "upload.py", "#!/bin/sh\n")
    module = sign_tree / "yubihsm_pkcs11.so"
    module.touch()
    environment = {
        "PKCS11_VENDOR": "yubihsm",
        "PKCS11_MODULE": str(module),
        "PKCS11_PYTHON_INTERCEPTOR": "y",
        "NEVER_START_YUBIHSM_CONNECTOR": "y",
        "YUBIHSM_AUTHKEY": "0x0001",
    }

    result = run_sign_orchestrate(
        sign_tree,
        environment=environment,
        answers="secret\nn\nn\n",
    )

    output = result.stdout.lower()
    assert "free space" in output
    assert "yubihsm_authkey" in output
    assert output.index("free space") < output.index("yubihsm_authkey")


@pytest.mark.parametrize(
    ("available", "expected"),
    ((5 << 30, "Only 5GB free"), ((20 << 30) - 1, "Only 19GB free")),
)
def test_sign_orchestrate_aborts_on_insufficient_free_space(
    sign_tree: Path,
    available: int,
    expected: str,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "FAKE_DF_AVAIL": str(available)},
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert "20GB is needed" in result.stderr
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_aborts_when_final_confirmation_declined(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(sign_tree, answers="n\nn\n")

    assert result.returncode != 0
    assert "Ready?" in result.stdout
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_rejects_empty_upload_script(sign_tree: Path) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    (sign_tree / "logs").mkdir()
    (sign_tree / "logs" / "upload.py").touch()

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "PKCS11_VENDOR": "yubihsm"},
    )

    assert result.returncode == 1
    assert "is not the expected git repository" in result.stderr
    assert "Traceback" not in result.stderr
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_treats_every_softhsm_device_as_loaded(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _install(sign_tree / "logs" / "upload.py", "#!/bin/sh\n")

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "PKCS11_VENDOR": "softhsm",
            "PKCS11_MODULE": "/dev/null",
        },
    )

    assert result.returncode == 0, result.stderr
    assert _archive_manifest(sign_tree) == {
        f"release-bramble-{BUILD_NUMBER}/output.bin": (
            f"signed-bramble-{BUILD_NUMBER}".encode()
        ),
    }


def test_sign_orchestrate_reports_unsupported_vendor(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _install(sign_tree / "logs" / "upload.py", "#!/bin/sh\n")

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "PKCS11_VENDOR": "acme"},
    )

    assert result.returncode == 1
    assert "PKCS11_VENDOR='acme' is not supported" in result.stderr
    assert "Traceback" not in result.stderr
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_signs_nothing_for_a_build_word_that_is_no_number(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "BUILD_NUMBER": f"{BUILD_NUMBER},",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "There is nothing left to sign." in result.stdout
    assert "Traceback" not in result.stderr
    assert _archive_manifest(sign_tree) == {}


def test_sign_orchestrate_refuses_a_rollback_build_that_is_no_number(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "BUILD_NUMBER": "eng",
            "AVB_ROLLBACK_INDEX_OVERRIDE": "1",
        },
    )

    assert result.returncode != 0
    assert "BUILD_NUMBER eng is not a number" in result.stderr
    assert "Traceback" not in result.stderr


def test_sign_orchestrate_survives_an_upload_script_it_cannot_run(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    (sign_tree / "logs").mkdir()
    (sign_tree / "logs" / "upload.py").write_text("#!/bin/sh\n")

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "PKCS11_VENDOR": "acme"},
    )

    assert result.returncode == 1
    assert "Permission denied" in result.stderr
    assert "Traceback" not in result.stderr


def _self_signed_certificate_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_sign_orchestrate_loads_missing_keys_before_signing_their_devices(
    sign_tree: Path,
    yubihsm: Connector,
) -> None:
    for name in ("bramble", "redfin"):
        _write_target_files(sign_tree, name, BUILD_NUMBER)
    keymap_file = sign_tree / "keymap.tsv"
    keymap_file.write_text(
        "ID\tDevice\tKey Type\tKey\n"
        "0x2000\tbramble\tavb\tvbmeta\n"
        "0x2100\tredfin\tavb\tvbmeta\n",
    )
    device = yubihsm.device
    device.put_authentication_key(0x0001, "secret")
    device.put_wrap_key(0x0010)
    device.put_asymmetric_key(0x2000)
    device.put_certificate(
        0x2000,
        x509.load_pem_x509_certificate(_self_signed_certificate_pem()),
    )
    device.put_asymmetric_key(0x2100)
    key_dir = sign_tree / "keys"
    key_dir.mkdir()
    (key_dir / "0x2100-asymmetric-key.yhw").write_bytes(
        base64.b64encode(device.wrapped(0x2100, OBJECT.ASYMMETRIC_KEY, 0x0010)),
    )
    del device.objects[(0x2100, OBJECT.ASYMMETRIC_KEY)]
    (key_dir / "0x2100.x509.pem").write_bytes(_self_signed_certificate_pem())
    _install(sign_tree / "logs" / "upload.py", "#!/bin/sh\n")
    _install(sign_tree.parent / "bin" / "yubihsm-has-key", YUBIHSM_HAS_KEY)

    result = run_sign_orchestrate(
        sign_tree,
        devices=("bramble", "redfin"),
        environment={
            "SIGN_ASSUME_YES": "y",
            "PKCS11_VENDOR": "yubihsm",
            "PKCS11_MODULE": "/dev/null",
            "PKCS11_PYTHON_INTERCEPTOR": "y",
            "PKCS11_VENDOR_INITIALIZED": "y",
            "PKCS11_VENDOR_INITIALIZED_INTERACTIVE": "y",
            "KEYMAP_FILE": str(keymap_file),
            "KEY_DIR": str(key_dir),
            "YUBIHSM_EXPORTABLE_DOMAIN": "1",
            "YUBIHSM_ONDEMAND_DOMAIN": "3",
            "YUBIHSM_KEY_CAPABILITIES": "sign-pkcs",
            "YUBIHSM_OPAQUE_CAPABILITIES": "get-opaque",
            "YUBIHSM_AUTHKEY": "0x0001",
            "YUBIHSM_PASSWORD": "secret",
            "SKIP_LOG_UPLOAD": "true",
            "YUBIHSM_CONNECTOR": yubihsm.url,
            "REQUIRE_IMPORTED_KEY": "redfin=0x2100",
        },
    )

    assert result.returncode == 0, result.stderr
    assert device.get(0x2100, OBJECT.ASYMMETRIC_KEY) is not None
    assert [
        target
        for _, command, target in device.history
        if command == COMMAND.IMPORT_WRAPPED
    ] == [(0x0010, 0x2100)]
    (load_keys_log,) = (sign_tree / "logs").glob("*/*-load-keys.log")
    assert [
        line.split(" ", 2)[2]
        for line in load_keys_log.read_text().splitlines()
        if line.startswith("# ")
    ] == ["Function: ensure_key_is_available Key: 0x2100 Result: 0"]
    assert set(_archive_manifest(sign_tree)) == {
        f"release-bramble-{BUILD_NUMBER}/output.bin",
        f"release-redfin-{BUILD_NUMBER}/output.bin",
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        ("devices=(bramble redfin)\n", ("bramble", "redfin")),
        ("devices=()\n", ()),
        ("other=(bramble)\n", ()),
    ),
)
def test_load_devices_file_reads_the_devices_array(
    tmp_path: Path,
    text: str,
    expected: tuple[str, ...],
) -> None:
    devices_file = tmp_path / "devices"
    devices_file.write_text(text)

    assert load_devices_file(devices_file) == expected


def test_load_devices_file_gives_bash_no_standard_input(tmp_path: Path) -> None:
    stdin = tmp_path / "stdin"
    devices_file = tmp_path / "devices"
    devices_file.write_text(
        f'readlink /proc/$$/fd/0 > "{stdin}"\ndevices=(bramble)\n',
    )
    read_end, write_end = os.pipe()
    saved = os.dup(0)
    os.dup2(read_end, 0)
    try:
        devices = load_devices_file(devices_file)
    finally:
        os.dup2(saved, 0)
        for fd in (saved, read_end, write_end):
            os.close(fd)

    assert devices == ("bramble",)
    assert stdin.read_text() == "/dev/null\n"


def test_sign_orchestrate_skips_previous_builds_matching_the_build_number(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _archive_previous_build(sign_tree, "redfin", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        devices=("bramble", "redfin"),
        environment={"SIGN_ASSUME_YES": "y", "PREV_BUILD_NUMBER": BUILD_NUMBER},
    )

    assert result.returncode == 0, result.stderr
    assert "  None." in result.stdout
    assert f"  {BUILD_NUMBER}: redfin" not in result.stdout


def test_sign_orchestrate_refuses_a_malformed_job_count(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "NUM_SIGN_JOBS": "many"},
    )

    assert result.returncode == 1
    assert "NUM_SIGN_JOBS must be a positive number, not 'many'" in (
        result.stderr
    )
    assert "Traceback" not in result.stderr


def test_sign_orchestrate_refuses_yubihsm_without_the_interceptor_first(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _install(sign_tree / "logs" / "upload.py", "#!/bin/sh\n")
    module = sign_tree / "yubihsm_pkcs11.so"
    module.touch()

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "PKCS11_VENDOR": "yubihsm",
            "PKCS11_MODULE": str(module),
            "NEVER_START_YUBIHSM_CONNECTOR": "y",
        },
    )

    assert result.returncode == 1
    assert "requires PKCS11_PYTHON_INTERCEPTOR=y" in result.stderr
    assert "yubihsm_authkey" not in result.stdout.lower()


def test_sign_orchestrate_refuses_an_unknown_keymapper(sign_tree: Path) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "KEYMAPPER": "bogus"},
    )

    assert result.returncode == 1
    assert "Could not find keymapper 'bogus'." in result.stderr


def test_sign_orchestrate_reports_an_unreadable_keymap_file(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "KEYMAPPER": "static",
            "KEYMAP_FILE": str(sign_tree / "missing-keymap.tsv"),
        },
    )

    assert result.returncode == 1
    assert "missing-keymap.tsv" in result.stderr
    assert "Traceback" not in result.stderr


def test_sign_orchestrate_reuses_its_tmpdir_when_initialization_is_retried(
    tmp_path: Path,
) -> None:
    (tmp_path / "tmp").mkdir()
    orchestrator = SignOrchestrator(
        {
            "TMPDIR": str(tmp_path / "tmp"),
            "PKCS11_VENDOR": "yubihsm",
            "PKCS11_PYTHON_INTERCEPTOR": "y",
            "NEVER_START_YUBIHSM_CONNECTOR": "y",
            "YUBIHSM_AUTHKEY": "0x0001",
            "YUBIHSM_PASSWORD": "password",
        },
        cwd=tmp_path,
        devices_file=tmp_path / "devices",
        metadata=load_metadata(SCRIPTS_DIR / "metadata.py"),
        release_script=tmp_path / "release.sh",
        generate_delta_script=tmp_path / "generate_delta.sh",
    )

    for _ in range(2):
        with pytest.raises(SignStepError):
            orchestrator.initialize()
    created = list((tmp_path / "tmp").glob("signing_tmp.*"))
    orchestrator.cleanup()

    assert len(created) == 1
    assert not list((tmp_path / "tmp").glob("signing_tmp.*"))


def _wait_until_reading_stdin(pid: int) -> None:
    """
    Wait until the process blocks in read() on its standard input. A
    signal that arrives after input() writes its prompt but before it
    reads leaves the handler pending until the read returns.
    """
    read = {"x86_64": 0, "aarch64": 63}[os.uname().machine]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        fields = Path(f"/proc/{pid}/syscall").read_text().split()
        if fields[:2] == [str(read), "0x0"]:
            return
        time.sleep(0.01)
    pytest.fail("the process never blocked reading its standard input")


@pytest.mark.parametrize(
    "signum",
    (signal.SIGTERM, signal.SIGHUP),
    ids=("sigterm", "sighup"),
)
def test_sign_orchestrate_cleans_up_when_terminated(
    sign_tree: Path,
    signum: signal.Signals,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    devices_file = sign_tree / "devices"
    devices_file.write_text("devices=(bramble)\n")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "signing",
            "sign-orchestrate",
            "--metadata",
            str(SCRIPTS_DIR / "metadata.py"),
            "--devices-file",
            str(devices_file),
            "--release-script",
            str(sign_tree.parent / "fakes" / "release.sh"),
            "--generate-delta-script",
            str(sign_tree.parent / "fakes" / "generate_delta.sh"),
        ],
        cwd=sign_tree,
        env={
            **os.environ,
            "PATH": (
                f"{sign_tree.parent / 'bin'}{os.pathsep}{os.environ['PATH']}"
            ),
            "PYTHONPATH": str(SCRIPTS_DIR),
            "TMPDIR": str(sign_tree / "tmp"),
            "PKCS11_VENDOR": "",
            "BUILD_NUMBER": BUILD_NUMBER,
            "PREV_BUILD_NUMBER": "",
            "NUM_SIGN_JOBS": "2",
            "NUM_INCREMENTAL_JOBS": "2",
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=default_signal_dispositions,
    )
    assert process.stdin is not None and process.stdout is not None
    output = ""
    while "Ready?" not in output:
        character = process.stdout.read(1)
        assert character, output
        output += character
    assert list((sign_tree / "tmp").glob("signing_tmp.*"))

    _wait_until_reading_stdin(process.pid)
    process.send_signal(signum)

    assert process.wait(timeout=30) == 128 + signum
    assert not list((sign_tree / "tmp").glob("signing_tmp.*"))


def test_sign_orchestrator_applies_a_keymapper_files_key_dir(
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "keymapper.plugin.py"
    plugin.write_text(
        "from signing.keymap import Id2bKeymapper\n"
        "class PluginKeymapper(Id2bKeymapper):\n"
        "    def key_dir(self, environment):\n"
        "        environment['KEY_DIR'] = 'plugin-keys/'\n"
        "        return 'plugin-keys/'\n"
        "def create_keymapper(environment, metadata, *, extra_devices):\n"
        "    return PluginKeymapper(metadata, extra_devices=extra_devices)\n",
    )
    environment = {"KEYMAPPER_FILE": str(plugin)}
    orchestrator = SignOrchestrator(
        environment,
        cwd=tmp_path,
        devices_file=tmp_path / "devices",
        metadata=load_metadata(SCRIPTS_DIR / "metadata.py"),
        release_script=tmp_path / "release.sh",
        generate_delta_script=tmp_path / "generate_delta.sh",
    )

    orchestrator.keymapper()

    assert environment["KEY_DIR"] == "plugin-keys/"


def test_sign_orchestrate_reports_an_unreadable_free_space(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "FAKE_DF_AVAIL": "unknown"},
    )

    assert result.returncode != 0
    assert "Could not read the free space" in result.stderr
    assert "Traceback" not in result.stderr


def test_sign_orchestrate_offers_no_previous_build_newer_than_the_one_signed(
    sign_tree: Path,
) -> None:
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _write_target_files(sign_tree, "bramble", str(int(BUILD_NUMBER) + 100))
    _archive_previous_build(sign_tree, "bramble", OLD_BUILD_NUMBER)
    _archive_previous_build(sign_tree, "bramble", str(int(BUILD_NUMBER) + 50))

    result = run_sign_orchestrate(
        sign_tree,
        environment={"SIGN_ASSUME_YES": "y", "PREV_BUILD_NUMBER": None},
        answers="\n",
    )

    assert result.returncode == 0, result.stderr
    assert (
        f"Generating incremental updates for: bramble,{OLD_BUILD_NUMBER},"
        f"{BUILD_NUMBER}"
    ) in result.stdout


def test_sign_orchestrate_asks_for_no_previous_build_for_a_rollback_build(
    sign_tree: Path,
) -> None:
    (sign_tree.parent / "fakes" / "release.sh").write_text(
        "#!/bin/sh\n"
        "set -e\n"
        "build=$((BUILD_NUMBER + 1))\n"
        'mkdir -p "out/release-$1-$build"\n'
        'printf "%s" "${PREV_BUILD_NUMBER-unset}" '
        '> "out/release-$1-$build/output.bin"\n',
    )
    _write_target_files(sign_tree, "bramble", BUILD_NUMBER)
    _archive_previous_build(sign_tree, "bramble", OLD_BUILD_NUMBER)

    result = run_sign_orchestrate(
        sign_tree,
        environment={
            "SIGN_ASSUME_YES": "y",
            "AVB_ROLLBACK_INDEX_OVERRIDE": "1",
            "PREV_BUILD_NUMBER": None,
        },
        answers=f"{OLD_BUILD_NUMBER}\n",
    )

    assert result.returncode == 0, result.stderr
    output = sign_tree / "archive" / f"release-bramble-{int(BUILD_NUMBER) + 1}"
    assert (output / "output.bin").read_text() == "unset"
