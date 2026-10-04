#!/bin/bash
#
# SPDX-FileCopyrightText: 2018 Daniel Micay
# SPDX-FileCopyrightText: 2018-2026 The Calyx Institute
# SPDX-License-Identifier: MIT OR Apache-2.0
#

scripts=$(cd "$(dirname "$0")" && pwd -P) || exit
PYTHONPATH="$scripts${PYTHONPATH:+:$PYTHONPATH}" \
  exec python3 -P -m signing generate-delta "$0" "$@"
