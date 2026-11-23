"""Double confirmation with a TTY gate. Non-TTY write runs fail closed."""

import os
import sys
from collections.abc import Sequence

# Test/scripting escape hatch. It skips ONLY the two y/N prompts; the
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
    return os.environ.get(BYPASS_ENV, "").strip() == "1"


def confirm_twice(plan_text: Sequence[str], tty_check: bool = True) -> bool:
    """Print the plan and require two exact ``y`` answers.

    Returns False (and warns) when stdin is not a TTY and ``tty_check`` is set.
    With ``LHM_CONFIRM_BYPASS=1`` the plan is printed and both prompts are
    skipped (test-only / scripted root use; see ``BYPASS_ENV``).
    """
    if tty_check and not sys.stdin.isatty() and not bypass_requested():
        print(
            "lhm: refusing to continue: stdin is not a TTY "
            "(re-run interactively, use --dry-run, or set LHM_CONFIRM_BYPASS=1 "
            "for an unattended root run)",
            file=sys.stderr,
        )
        return False

    for line in plan_text:
        print(line)

    if bypass_requested():
        print(
            f"lhm: both confirmations skipped ({BYPASS_ENV}=1); "
            "use only for tests or scripted root runs",
            file=sys.stderr,
        )
        return True

    for attempt in (1, 2):
        try:
            answer = input(f"Apply this plan? [{attempt}/2] type 'y' to continue: ")
        except EOFError:
            print("lhm: aborted: no input available.", file=sys.stderr)
            return False
        if answer != "y":
            print("lhm: aborted, nothing further was changed.", file=sys.stderr)
            return False
    return True
