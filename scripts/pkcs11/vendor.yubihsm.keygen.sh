#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

scripts=$(cd "$(dirname "$0")/.." && pwd -P) || exit
PKCS11_VENDOR=yubihsm \
  PYTHONPATH="$scripts${PYTHONPATH:+:$PYTHONPATH}" \
  exec python3 -P -m signing keygen "$@"
