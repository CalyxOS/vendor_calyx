#
# SPDX-FileCopyrightText: The Calyx Institute
# SPDX-License-Identifier: Apache-2.0
#
"""
Interactive yes/no confirmation and variable prompts.
"""

from __future__ import annotations

import getpass
import sys
from collections.abc import MutableMapping


def confirm(question: str, *, assume_yes: bool = False) -> bool:
    """
    Ask a yes/no question until the answer, without leading and trailing
    blanks, is Y/y or N/n, reprompting with "Please enter Y or N." on
    stderr after any other.

    Args:
        question: The question to ask, without a trailing "(Y/N)".
        assume_yes: Auto-answer yes without prompting, printing the same
            "[auto-answered by SIGN_ASSUME_YES=y]" marker.

    Returns:
        Whether the answer was yes.
    """
    if assume_yes:
        print(f"{question} (Y/N) Y  [auto-answered by SIGN_ASSUME_YES=y]")
        return True
    while True:
        try:
            response = input(f"{question} (Y/N) ").strip(" \t")
        except EOFError:
            return False
        if response in ("Y", "y"):
            return True
        if response in ("N", "n"):
            return False
        print("Please enter Y or N.", file=sys.stderr)


def ask_variable(
    name: str,
    environment: MutableMapping[str, str],
    *,
    default: str = "",
    private: bool = False,
    needs_value: bool = True,
) -> str:
    """
    Resolve one variable from environment or an interactive prompt.

    The prompt goes to stderr and only to a terminal, and the answer loses
    its leading and trailing blanks.

    A variable already in environment, non-empty or, when needs_value is
    False, merely present, is used as it is. Otherwise the user is asked
    for it, with default for an empty answer. When needs_value is False,
    a literal '""' answer asks for an empty value.

    Args:
        name: The variable's name, which is its key in environment.
        environment: The mapping to read the existing value from and
            write the resolved value into.
        default: Value to use when the user enters nothing.
        private: Prompt silently (no echo) and never log the value.
        needs_value: When True, prompting repeats until the answer is
            not empty. When False, an empty answer is final.

    Returns:
        The resolved value (also left in environment[name]).

    Raises:
        RuntimeError: If input ends before a required value is entered.
    """
    existing = environment.get(name)
    if existing or (not needs_value and existing is not None):
        if private:
            print(f"Using {name} from environment.")
        else:
            print(f"Using {name}={existing} from environment.")
        return existing or ""

    prompt = f"Enter {name}"
    if default:
        prompt += f" [{default}]"
        if not needs_value:
            prompt += ' ("" for none)'
    elif not needs_value:
        prompt += " (blank for none)"

    while True:
        try:
            if private and sys.stdin.isatty():
                value = getpass.getpass(f"{prompt}: ")
            else:
                if sys.stdin.isatty():
                    sys.stderr.write(f"{prompt}: ")
                    sys.stderr.flush()
                value = input()
                if private:
                    print()
        except EOFError as error:
            if needs_value and not default:
                raise RuntimeError(
                    f"No value entered for {name} before end of input",
                ) from error
            value = ""
        value = value.strip(" \t") or default
        if not needs_value:
            if value == '""':
                value = ""
            environment[name] = value
            return value
        if value:
            environment[name] = value
            return value
