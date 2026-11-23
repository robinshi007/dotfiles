"""Logging module: persistent journald and logrotate for the audit log."""

from pathlib import Path

from lhm.core.confirm import confirm_twice
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

JOURNALD_TEMPLATE = "journald.conf.tmpl"
LOGROTATE_TEMPLATE = "logrotate-audit.tmpl"
JOURNALD_DROPIN = Path("/etc/systemd/journald.conf.d/99-lhm.conf")
LOGROTATE_CONF = Path("/etc/logrotate.d/lhm-audit")
JOURNAL_DIR = Path("/var/log/journal")


def desired_journald() -> str:
    return render_template(JOURNALD_TEMPLATE)


def desired_logrotate() -> str:
    return render_template(LOGROTATE_TEMPLATE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def apply_logging(runner: Runner) -> list[StepResult]:
    journald_needed = _read(JOURNALD_DROPIN) != desired_journald()
    logrotate_needed = _read(LOGROTATE_CONF) != desired_logrotate()

    plan = ["Plan (logging):"]
    plan.append(
        f"  - write {JOURNALD_DROPIN} (Storage=persistent; backup existing file)"
        if journald_needed
        else f"  - {JOURNALD_DROPIN} already current (skip)"
    )
    plan.append(
        f"  - write {LOGROTATE_CONF} (daily, 30 rotations, compressed)"
        if logrotate_needed
        else f"  - {LOGROTATE_CONF} already current (skip)"
    )
    plan.append("  - systemctl restart systemd-journald (journal moves to /var/log/journal)")
    plan.append("  - risk: restarting journald briefly interrupts log writes")

    if runner.dry_run:
        for line in plan:
            print(line)
        runner.run(["systemctl", "restart", "systemd-journald"])
        return [
            StepResult(
                f"write {JOURNALD_DROPIN}",
                Status.PLANNED if journald_needed else Status.SKIPPED,
                "" if journald_needed else "already current",
            ),
            StepResult(
                f"write {LOGROTATE_CONF}",
                Status.PLANNED if logrotate_needed else Status.SKIPPED,
                "" if logrotate_needed else "already current",
            ),
            StepResult("restart systemd-journald", Status.PLANNED),
        ]

    if not journald_needed and not logrotate_needed:
        return [
            StepResult(f"write {JOURNALD_DROPIN}", Status.SKIPPED, "already current"),
            StepResult(f"write {LOGROTATE_CONF}", Status.SKIPPED, "already current"),
            StepResult("restart systemd-journald", Status.SKIPPED, "config unchanged"),
            _verify(),
        ]

    if not confirm_twice(plan):
        return [StepResult("logging", Status.SKIPPED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        if journald_needed:
            JOURNALD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
            outcome = write_dropin(JOURNALD_DROPIN, desired_journald())
            results.append(
                StepResult(
                    f"write {JOURNALD_DROPIN}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(
                StepResult(f"write {JOURNALD_DROPIN}", Status.SKIPPED, "already current")
            )
        if logrotate_needed:
            outcome = write_dropin(LOGROTATE_CONF, desired_logrotate())
            results.append(
                StepResult(
                    f"write {LOGROTATE_CONF}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {LOGROTATE_CONF}", Status.SKIPPED, "already current"))
        runner.run(["systemctl", "restart", "systemd-journald"])
        results.append(StepResult("restart systemd-journald", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("logging", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {JOURNALD_DROPIN}", flush=True)
        return results

    results.append(_verify())
    return results


def _verify() -> StepResult:
    problems: list[str] = []
    if not JOURNAL_DIR.is_dir():
        problems.append(f"{JOURNAL_DIR} missing (journal not persistent yet)")
    if not LOGROTATE_CONF.is_file():
        problems.append(f"{LOGROTATE_CONF} missing")
    if problems:
        return StepResult("verify", Status.FAIL, "; ".join(problems))
    return StepResult("verify", Status.OK, "journal persistent, logrotate config present")


def inspect() -> dict[str, object]:
    """Read-only state used by ``check``."""
    return {
        "journald_dropin": str(JOURNALD_DROPIN),
        "journald_current": _read(JOURNALD_DROPIN) == desired_journald(),
        "journal_persistent": JOURNAL_DIR.is_dir(),
        "logrotate": str(LOGROTATE_CONF),
        "logrotate_current": _read(LOGROTATE_CONF) == desired_logrotate(),
    }


class LoggingModule:
    name = "logging"
    description = "Persistent journald and logrotate configuration"
    implemented = True

    def apply(self, runner: Runner, **options: object) -> list[StepResult]:
        return apply_logging(runner)
