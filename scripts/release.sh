#!/bin/bash
#
# SPDX-FileCopyrightText: 2018 Daniel Micay
# SPDX-FileCopyrightText: 2018-2026 The Calyx Institute
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Script to sign a target files package, and generate ota packages and factory images
# Refer to https://source.android.com/devices/tech/ota/sign_builds for more details

scripts=$(cd "$(dirname "$0")" && pwd -P) || exit
PYTHONPATH="$scripts${PYTHONPATH:+:$PYTHONPATH}" \
  exec python3 -P -m signing release-orchestrate "$0" "$@"
