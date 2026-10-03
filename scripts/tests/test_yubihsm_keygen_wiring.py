#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import datetime
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from yubihsm.defs import ALGORITHM, OBJECT
from yubihsm_emulator import Connector, EmulatedYubiHsm, stored_certificate

KEYGEN_SH = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.keygen.sh"
INCLUDE_SH = SCRIPTS_DIR / "pkcs11" / "vendor.yubihsm.include.sh"
STATIC_KEYMAPPER_SH = SCRIPTS_DIR / "keymapper.static.include.sh"


def _extract_function(name: str) -> str:
    """
    Return one function's current source text from keygen.sh, unmodified.

    Args:
        name: Bash function name to extract.

    Returns:
        The function definition, brace-delimited, as written in the file.
    """
    lines = KEYGEN_SH.read_text().splitlines()
    start = lines.index(f"{name}() {{")
    end = next(
        index for index in range(start + 1, len(lines)) if lines[index] == "}"
    )
    return "\n".join(lines[start : end + 1])


def run_keygen_functions(
    body: str,
    functions: tuple[str, ...] = (
        "generate_keypair",
        "generate_cert",
        "limit_keygen_ondemand_objects",
    ),
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Source keygen.sh's own function bodies, unmodified, plus a minimal
    supporting environment (vendor.yubihsm.include.sh for the Python-CLI
    helpers and device metadata functions, stub replacements for the
    handful of things only the full keygen.sh init chain would set up),
    then run body.

    keygen.sh's functions can't be sourced directly the way
    test_sign_orchestration.py does for sign.sh: keygen.sh resolves its
    own path via $0 (only meaningful when executed, not sourced) and
    pulls in a `set -euo pipefail` init chain with hardware-detection
    side effects. Extracting just the functions this wiring touches,
    from their unmodified current source text, tests the wiring
    without needing to fake that entire chain.

    Args:
        body: Bash statements to run after loading functions and stubs.
        functions: Names of keygen.sh functions to extract and define.
        env: Additional environment variables for the subprocess.

    Returns:
        The Bash subprocess result.
    """
    program = r"""
source "$1" || exit $?
source "$2" || exit $?
eval "$3"
copy_exported_file_to_other_dirs() { :; }
eval "$4"
"""
    extracted = "\n".join(_extract_function(name) for name in functions)
    return run(
        [
            "bash",
            "-c",
            program,
            "keygen-wiring-test",
            INCLUDE_SH,
            STATIC_KEYMAPPER_SH,
            extracted,
            body,
        ],
        env=env,
    )


@pytest.fixture
def fake_yubihsm_shell(tmp_path: Path) -> Path:
    """
    A `yubihsm-shell` double that records keygen's device operations.
    """
    script = tmp_path / "fake-yubihsm-shell"
    script.write_text(
        "#!/bin/sh\n"
        'out=""\n'
        'prev=""\n'
        'for arg in "$@"; do\n'
        '  if [ "$prev" = "--out" ]; then out="$arg"; fi\n'
        '  prev="$arg"\n'
        "done\n"
        'if [ -n "$out" ]; then\n'
        '  printf %s "shell-output-bytes" > "$out"\n'
        "fi\n",
    )
    script.chmod(script.stat().st_mode | 0o111)
    return script


def _keygen_env(
    tmp_path: Path,
    fake_shell: Path,
    yubihsm: Connector,
    **extra: str,
) -> dict[str, str]:
    yubihsm.device.put_wrap_key(0x0010)
    return {
        "PYTHONPATH": str(SCRIPTS_DIR),
        "YUBIHSM_PYTHON_TOOLS": "y",
        "YUBIHSM_CONNECTOR": yubihsm.url,
        "YUBIHSM_AUTHKEY": "0x0001",
        "YUBIHSM_PASSWORD": "password",
        "YUBIHSM_SHELL_BIN": str(fake_shell),
        "YUBIHSM_WRAP_KEY_ID": "0x0010",
        "unique_key_out_dir": str(tmp_path / "unique"),
        "AUDIT_LOG_PATH": str(tmp_path / "audit.log"),
        **extra,
    }


def _certificate(device: EmulatedYubiHsm, key_id: int) -> None:
    key = device.put_asymmetric_key(key_id)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "key")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    device.put_certificate(
        key_id,
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()),
    )


def test_generate_keypair_exports_wrapped_key_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    result = run_keygen_functions(
        r"""
generate_keypair 2000 releasekey RSA:4096 \
  || { echo "generate_keypair failed" >&2; exit 1; }
cat "$unique_key_out_dir/2000-asymmetric-key.yhw"
""",
        env=_keygen_env(tmp_path, fake_yubihsm_shell, yubihsm),
    )

    assert yubihsm.device.unwrap(base64.b64decode(result.stdout), 0x0010) == (
        0x2000,
        OBJECT.ASYMMETRIC_KEY,
    ), result.stderr
    assert (tmp_path / "audit.log").exists()


def test_generate_keypair_generates_key_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    run_keygen_functions(
        r"""
generate_keypair 2000 releasekey RSA:4096 \
  || { echo "generate_keypair failed" >&2; exit 1; }
""",
        env=_keygen_env(tmp_path, fake_yubihsm_shell, yubihsm),
    )

    key = yubihsm.device.get(0x2000, OBJECT.ASYMMETRIC_KEY)
    assert key is not None
    assert key.algorithm == ALGORITHM.RSA_4096


def test_generate_cert_writes_attestation_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    key = yubihsm.device.put_asymmetric_key(0x1500)

    result = run_keygen_functions(
        r"""
GENERATE_USING_PKCS11=n
generate_cert 1500 releasekey app RSA:4096 \
  || { echo "generate_cert failed" >&2; exit 1; }
cat "$unique_key_out_dir/1500.attestation.pem"
""",
        env=_keygen_env(tmp_path, fake_yubihsm_shell, yubihsm),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate.public_key() == key.public_key(), result.stderr
    stored = yubihsm.device.get(0x1500, OBJECT.OPAQUE)
    assert stored is not None
    assert stored_certificate(stored) == certificate
    assert (tmp_path / "audit.log").exists()


def test_extract_attestation_key_writes_certificate_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    result = run_keygen_functions(
        r"""
extract_attestation_key \
  || { echo "extract_attestation_key failed" >&2; exit 1; }
cat "$unique_key_out_dir/YubiHSM_attestation.pem"
""",
        functions=("extract_attestation_key",),
        env=_keygen_env(tmp_path, fake_yubihsm_shell, yubihsm),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate == yubihsm.device.attestation_certificate


def test_existence_checks_ask_the_sdk_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    _certificate(yubihsm.device, 0x2000)
    yubihsm.device.put_asymmetric_key(0x2100)
    key_out_dir = tmp_path / "keys"
    key_out_dir.mkdir()
    result = run_keygen_functions(
        r"""
does_key_exist_yn_pkcs11() { echo pkcs11; }
does_cert_exist_yn_pkcs11() { echo pkcs11; }
for id in 0x2000 0x2100 0x2200; do
  printf '%s key=%s cert=%s\n' "$id" \
    "$(does_key_exist_yn "$id")" "$(does_cert_exist_yn "$id")"
done
""",
        functions=(
            "does_key_exist_yn",
            "does_cert_exist_yn",
            "_does_object_exist_yn",
        ),
        env=_keygen_env(
            tmp_path,
            fake_yubihsm_shell,
            yubihsm,
            key_out_dir=str(key_out_dir),
        ),
    )

    assert result.stdout.splitlines() == [
        "0x2000 key=y cert=y",
        "0x2100 key=y cert=n",
        "0x2200 key=n cert=n",
    ]


def test_generate_keypair_passes_an_unexported_password_to_python(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    environment = _keygen_env(tmp_path, fake_yubihsm_shell, yubihsm)
    del environment["YUBIHSM_PASSWORD"]

    result = run_keygen_functions(
        r"""
YUBIHSM_PASSWORD=password
generate_keypair 2000 releasekey RSA:4096 \
  || { echo "generate_keypair failed" >&2; exit 1; }
""",
        env=environment,
    )

    assert result.returncode == 0, result.stderr
