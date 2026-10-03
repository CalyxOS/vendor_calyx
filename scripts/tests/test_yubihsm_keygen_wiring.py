#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import base64
import subprocess
from pathlib import Path

import pytest
from conftest import SCRIPTS_DIR, run
from cryptography import x509
from yubihsm.defs import OBJECT
from yubihsm_emulator import Connector

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
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Source the generate_keypair/generate_cert bodies plus a minimal
    supporting environment (vendor.yubihsm.include.sh for the Python-CLI
    helpers and device metadata functions, stub replacements for the
    handful of things only the full keygen.sh init chain would set up),
    then run body.

    generate_keypair/generate_cert can't be sourced directly the way
    test_sign_orchestration.py does for sign.sh: keygen.sh resolves its
    own path via $0 (only meaningful when executed, not sourced) and
    pulls in a `set -euo pipefail` init chain with hardware-detection
    side effects. Extracting just the two functions this wiring touches,
    from their current source text, tests the wiring without needing to
    fake that entire chain.

    Args:
        body: Bash statements to run after loading functions and stubs.
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
eval "$5"
"""
    return run(
        [
            "bash",
            "-c",
            program,
            "keygen-wiring-test",
            INCLUDE_SH,
            STATIC_KEYMAPPER_SH,
            _extract_function("generate_keypair"),
            _extract_function("generate_cert"),
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


def test_generate_keypair_exports_wrapped_key_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000)

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


def test_generate_cert_writes_attestation_via_python_when_flagged(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    key = yubihsm.device.put_asymmetric_key(0x1500)

    result = run_keygen_functions(
        r"""
GENERATE_USING_PKCS11=n
generate_cert 1500 releasekey app RSA:4096
cat "$unique_key_out_dir/1500.attestation.pem"
""",
        env=_keygen_env(tmp_path, fake_yubihsm_shell, yubihsm),
    )

    certificate = x509.load_pem_x509_certificate(result.stdout.encode())
    assert certificate.public_key() == key.public_key(), result.stderr
    assert (tmp_path / "audit.log").exists()


def test_generate_keypair_passes_an_unexported_password_to_python(
    fake_yubihsm_shell: Path,
    yubihsm: Connector,
    tmp_path: Path,
) -> None:
    yubihsm.device.put_asymmetric_key(0x2000)
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
