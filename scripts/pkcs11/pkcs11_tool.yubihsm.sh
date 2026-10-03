#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

# Preload the module so that its getopt state binds to pkcs11-tool's, which
# loading it with RTLD_DEEPBIND prevents. See "pkcs11-tool and the YubiHSM
# PKCS#11 module" in DOCUMENTATION.md.

if [ -n "${PKCS11_MODULE:-}" ]; then
  export LD_PRELOAD=$PKCS11_MODULE${LD_PRELOAD:+:$LD_PRELOAD}
fi
exec "${YUBIHSM_UNDERLYING_PKCS11_TOOL_BIN:-pkcs11-tool}" "$@"
