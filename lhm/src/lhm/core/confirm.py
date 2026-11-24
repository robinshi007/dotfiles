"""Interactive confirmation with a TTY gate. Non-TTY write runs fail closed."""

import os
import sys
from collections.abc import Sequence

# Test/scripting escape hatch. It skips ONLY the y/N prompt; the
# idempotency check that runs before any plan is never affected, so a bypassed
# run still does nothing when the target state is already reached.
# Intended for the integration suite (lhm/integration) and for root-owned
# unattended scripts; it is not a CLI flag on purpose.
BYPASS_ENV = "LHM_CONFIRM_BYPASS"


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def bypass_requested() -> bool:
    """True only for the exact value ``1`` (typos must not disable the gate)."""
    return os.environ.get(BYPASS_ENV, "") == "1"


def confirm_once(
    plan_text: Sequence[str], tty_check: bool = True, *, allow_bypass: bool = True
) -> bool:
    """Print the plan and require one exact ``y`` answer.

    Returns False (and warns) when stdin is not a TTY and ``tty_check`` is set.
    If ``allow_bypass`` is set, ``LHM_CONFIRM_BYPASS=1`` skips the prompt
    but still prints the plan (test-only / scripted root use; see ``BYPASS_ENV``).
    """
    bypass = allow_bypass and bypass_requested()
    if tty_check and not sys.stdin.isatty() and not bypass:
        options = (
            "re-run interactively, use --dry-run, or set LHM_CONFIRM_BYPASS=1 "
            "for an unattended root run"
            if allow_bypass
            else "re-run interactively or use --dry-run"
        )
        print(
            f"lhm: refusing to continue: stdin is not a TTY ({options})",
            file=sys.stderr,
        )
        return False

    for line in plan_text:
        print(line)

    if bypass:
        print(
            f"lhm: confirmation skipped ({BYPASS_ENV}=1); "
            "use only for tests or scripted root runs",
            file=sys.stderr,
        )
        return True

    try:
        answer = input("Apply this plan? type 'y' to continue: ")
    except EOFError:
        print("lhm: aborted: no input available.", file=sys.stderr)
        return False
    if answer != "y":
        print("lhm: aborted, nothing further was changed.", file=sys.stderr)
        return False
    return True
