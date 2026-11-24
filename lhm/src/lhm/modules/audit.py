"""Audit module: auditd, /etc/audit/rules.d/99-lhm.rules and augenrules."""

from pathlib import Path

from lhm.core.checks import probe_service
from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend, DistroError
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGE = "auditd"
TEMPLATE = "audit-rules.tmpl"
RULES_DROPIN = Path("/etc/audit/rules.d/99-lhm.rules")
LOAD_TIMEOUT = 120.0


def desired_rules() -> str:
    return render_template(TEMPLATE)


def _read_rules() -> str | None:
    try:
        return RULES_DROPIN.read_text(encoding="utf-8")
    except OSError:
        return None


def _rules_immutable(runner: Runner) -> bool:
    """True when the kernel already has the immutable audit flag set (-e 2)."""
    result = runner.run(["auditctl", "-s"], timeout=15.0, check=False)
    if not result.ok:
        return False
    return any(
        line.startswith("enabled") and line.split()[-1] == "2"
        for line in result.stdout.splitlines()
    )


def _verify(runner: Runner) -> StepResult:
    check = runner.run(["augenrules", "--check"], timeout=LOAD_TIMEOUT, check=False)
    if not check.ok:
        detail = f"augenrules --check rc={check.returncode}"
        if check.stderr.strip():
            detail += f": {check.stderr.strip()}"
        return StepResult("verify", Status.FAIL, detail)
    return StepResult("verify", Status.OK, "augenrules --check accepted the rules")


def apply_audit(runner: Runner) -> list[StepResult]:
    backend = AptBackend(runner)
    try:
        installed = False if runner.dry_run else backend.pkg_installed(PACKAGE)
    except DistroError as exc:
        return [StepResult("audit", Status.FAIL, str(exc))]

    desired = desired_rules()
    file_needed = _read_rules() != desired
    active = False if runner.dry_run else bool(probe_service(runner, PACKAGE).active)
    # The rules end with `-e 2` (immutable). Reloading them while already loaded
    # immutable fails by design, so an identical file plus a running auditd
    # means "nothing to do".
    skip_load = not file_needed and active

    plan = ["Plan (audit):"]
    plan.append(
        f"  - install {PACKAGE}" if not installed else f"  - {PACKAGE} already installed"
    )
    plan.append(
        f"  - write {RULES_DROPIN} (backup existing file)"
        if file_needed
        else f"  - {RULES_DROPIN} already current (skip write)"
    )
    plan.append(
        "  - skip augenrules --load: rules already loaded immutable"
        if skip_load
        else "  - augenrules --load"
    )
    plan.append(f"  - systemctl enable --now {PACKAGE}")
    plan.append("  - verify: augenrules --check")

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        if not installed:
            backend.install([PACKAGE])
            results.append(StepResult(f"install {PACKAGE}", Status.PLANNED))
        results.append(
            StepResult(
                f"write {RULES_DROPIN}",
                Status.PLANNED if file_needed else Status.SKIPPED,
                "" if file_needed else "already current",
            )
        )
        if not skip_load:
            runner.run(["augenrules", "--load"], timeout=LOAD_TIMEOUT)
        results.append(
            StepResult(
                "augenrules --load",
                Status.SKIPPED if skip_load else Status.PLANNED,
                "already loaded (immutable, -e 2)" if skip_load else "",
            )
        )
        runner.run(["systemctl", "enable", "--now", PACKAGE])
        results.append(StepResult(f"enable --now {PACKAGE}", Status.PLANNED))
        return results

    if not file_needed and installed and active:
        return [
            StepResult(f"install {PACKAGE}", Status.SKIPPED, "installed"),
            StepResult(f"write {RULES_DROPIN}", Status.SKIPPED, "already current"),
            StepResult("augenrules --load", Status.SKIPPED, "already loaded (immutable, -e 2)"),
            StepResult(f"enable --now {PACKAGE}", Status.SKIPPED, "already active"),
            _verify(runner),
        ]

    if not confirm_once(plan):
        return [StepResult("audit", Status.ABORTED, "aborted; no changes made")]

    results = []
    try:
        if installed:
            results.append(StepResult(f"install {PACKAGE}", Status.SKIPPED, "installed"))
        else:
            backend.install([PACKAGE])
            results.append(StepResult(f"install {PACKAGE}", Status.CHANGED))
        if file_needed:
            outcome = write_dropin(RULES_DROPIN, desired)
            results.append(
                StepResult(
                    f"write {RULES_DROPIN}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {RULES_DROPIN}", Status.SKIPPED, "already current"))
        if skip_load:
            results.append(
                StepResult("augenrules --load", Status.SKIPPED, "already loaded (immutable, -e 2)")
            )
        else:
            load = runner.run(["augenrules", "--load"], timeout=LOAD_TIMEOUT, check=False)
            if load.ok:
                results.append(StepResult("augenrules --load", Status.CHANGED))
            elif not file_needed and _rules_immutable(runner):
                # Identical file and the kernel confirms `-e 2`: the rules are
                # already loaded immutable, so this load failure is a warning.
                results.append(
                    StepResult(
                        "augenrules --load",
                        Status.OK,
                        f"warning: rc={load.returncode} "
                        "(rules already loaded immutable; run reboot to apply)",
                    )
                )
            else:
                detail = f"rc={load.returncode}"
                if not file_needed:
                    detail += " (immutability not confirmed by auditctl -s enabled=2)"
                if load.stderr.strip():
                    detail += f": {load.stderr.strip()}"
                results.append(StepResult("augenrules --load", Status.FAIL, detail))
                print(f"lhm: rollback hint: lhm rollback {RULES_DROPIN}", flush=True)
                return results
        runner.run(["systemctl", "enable", "--now", PACKAGE])
        results.append(StepResult(f"enable --now {PACKAGE}", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("audit", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {RULES_DROPIN}", flush=True)
        return results

    results.append(_verify(runner))
    return results


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    """Read-only state used by ``query audit`` and ``check``."""
    try:
        installed = AptBackend(runner).pkg_installed(PACKAGE) if probe_package else None
    except DistroError:
        installed = None
    state = probe_service(runner, PACKAGE)
    status = runner.run(["auditctl", "-s"], timeout=15.0, check=False)
    return {
        "package": PACKAGE,
        "installed": installed,
        "active": state.active,
        "rules": str(RULES_DROPIN),
        "rules_current": _read_rules() == desired_rules(),
        "immutable": _rules_immutable(runner),
        "auditctl_status": status.stdout.strip() if status.ok else "",
    }


class AuditModule:
    name = "audit"
    description = "auditd rules drop-in and augenrules check"
    implemented = True

    def apply(self, runner: Runner, **options: object) -> list[StepResult]:
        return apply_audit(runner)
