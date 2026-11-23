"""sysctl module: kernel hardening drop-in, reload and spot checks."""

from pathlib import Path

from lhm.core import checks
from lhm.core.confirm import confirm_twice
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

TEMPLATE = "99-lhm-sysctl.conf.tmpl"
SYSCTL_DROPIN = Path("/etc/sysctl.d/99-lhm.conf")
LOAD_TIMEOUT = 120.0

# Only these three keys gate verification. Everything else in the drop-in is
# best-effort (some keys do not exist on every kernel).
SPOT_CHECKS: dict[str, str] = {
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "net.ipv4.conf.all.rp_filter": "1",
}

# kernel.unprivileged_userns_clone is absent on some kernels; sysctl --system
# then warns about it (and may exit non-zero). That is tolerated. Matches appear
# as either the dotted sysctl key or the /proc/sys path leaf.
OPTIONAL_KEYS = ("kernel.unprivileged_userns_clone", "unprivileged_userns_clone")


def desired_conf() -> str:
    return render_template(TEMPLATE)


def _read_conf() -> str | None:
    try:
        return SYSCTL_DROPIN.read_text(encoding="utf-8")
    except OSError:
        return None


def read_value(runner: Runner, key: str) -> str | None:
    """Read one live kernel setting via ``sysctl -n``."""
    result = runner.run(["sysctl", "-n", key], timeout=15.0, check=False)
    if not result.ok:
        return None
    return result.stdout.strip()


def spot_values(runner: Runner) -> dict[str, str | None]:
    return {key: read_value(runner, key) for key in SPOT_CHECKS}


def _tolerated(stderr: str) -> bool:
    lines = [line for line in stderr.splitlines() if line.strip()]
    return bool(lines) and all(
        any(key in line for key in OPTIONAL_KEYS) for line in lines
    )


def _verify(runner: Runner) -> StepResult:
    problems: list[str] = []
    for key, want in SPOT_CHECKS.items():
        got = read_value(runner, key)
        if got != want:
            problems.append(f"{key}={got or 'unreadable'} (want {want})")
    if problems:
        return StepResult("verify", Status.FAIL, "; ".join(problems))
    note = ""
    if read_value(runner, OPTIONAL_KEYS[0]) is None:
        note = f"; {OPTIONAL_KEYS[0]} absent on this kernel (tolerated)"
    return StepResult("verify", Status.OK, "spot checks match" + note)


def apply_sysctl(runner: Runner) -> list[StepResult]:
    desired = desired_conf()
    file_needed = _read_conf() != desired
    drift = True if runner.dry_run else any(
        spot_values(runner)[key] != want for key, want in SPOT_CHECKS.items()
    )

    plan = ["Plan (sysctl):"]
    plan.append(
        f"  - write {SYSCTL_DROPIN} (backup existing file)"
        if file_needed
        else f"  - {SYSCTL_DROPIN} already current (skip write)"
    )
    plan.append(
        "  - sysctl --system (load every /etc/sysctl.d drop-in)"
        if file_needed or drift
        else "  - live values already correct (skip sysctl --system)"
    )
    plan.append(
        "  - verify kernel.kptr_restrict=2, kernel.dmesg_restrict=1, "
        "net.ipv4.conf.all.rp_filter=1"
    )
    plan.append(
        f"  - note: {OPTIONAL_KEYS[0]} is absent on some kernels; that warning is tolerated"
    )

    if runner.dry_run:
        for line in plan:
            print(line)
        steps = [
            StepResult(
                f"write {SYSCTL_DROPIN}",
                Status.PLANNED if file_needed else Status.SKIPPED,
                "" if file_needed else "already current",
            )
        ]
        runner.run(["sysctl", "--system"])
        steps.append(StepResult("sysctl --system", Status.PLANNED))
        steps.append(StepResult("verify", Status.PLANNED, "spot checks after load"))
        return steps

    if not file_needed and not drift:
        return [
            StepResult(f"write {SYSCTL_DROPIN}", Status.SKIPPED, "already current"),
            StepResult("sysctl --system", Status.SKIPPED, "values already loaded"),
            _verify(runner),
        ]

    if not confirm_twice(plan):
        return [StepResult("sysctl", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        if file_needed:
            outcome = write_dropin(SYSCTL_DROPIN, desired)
            results.append(
                StepResult(
                    f"write {SYSCTL_DROPIN}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {SYSCTL_DROPIN}", Status.SKIPPED, "already current"))
        load = runner.run(["sysctl", "--system"], timeout=LOAD_TIMEOUT, check=False)
        detail = ""
        if not load.ok:
            detail = (
                f"rc={load.returncode}; unknown-key warning tolerated"
                if _tolerated(load.stderr)
                else f"rc={load.returncode}"
            )
        results.append(StepResult("sysctl --system", Status.CHANGED, detail))
    except (CommandError, OSError) as exc:
        results.append(StepResult("sysctl", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {SYSCTL_DROPIN}", flush=True)
        return results

    results.append(_verify(runner))
    return results


def inspect() -> dict[str, object]:
    """Read-only state used by ``query sysctl`` and ``check`` (no root needed)."""
    spot = {
        key: {"want": want, "current": checks.sysctl_value(key)}
        for key, want in SPOT_CHECKS.items()
    }
    return {
        "dropin": str(SYSCTL_DROPIN),
        "dropin_current": _read_conf() == desired_conf(),
        "spot_checks": spot,
    }


class SysctlModule:
    name = "sysctl"
    description = "Kernel hardening drop-in /etc/sysctl.d/99-lhm.conf"
    implemented = True

    def apply(self, runner: Runner, **options: object) -> list[StepResult]:
        return apply_sysctl(runner)
