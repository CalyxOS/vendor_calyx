#!/bin/bash
#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#

cd "$(dirname "$0")/.." || exit

status=0
ruff check . || status=1
ruff format --check . || status=1
mypy || status=1
pyright || status=1
pytest || status=1
exit "$status"
