"""Updates module: apt refresh/upgrade, unattended-upgrades and 51-lhm config."""

from pathlib import Path

from lhm.core.checks import probe_service
from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGE = "unattended-upgrades"
TEMPLATE = "unattended-upgrades.conf.tmpl"
APT_CONF = Path("/etc/apt/apt.conf.d/51-lhm")


def _read_conf() -> str | None:
    try:
        return APT_CONF.read_text(encoding="utf-8")
    except OSError:
        return None


def desired_conf() -> str:
    return render_template(TEMPLATE)


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    """Read-only state used by ``query updates`` and ``check``."""
    installed = AptBackend(runner).pkg_installed(PACKAGE) if probe_package else None
    return {
        "package": PACKAGE,
        "installed": installed,
        "apt_conf": str(APT_CONF),
        "apt_conf_current": _read_conf() == desired_conf(),
    }


class UpdatesModule:
    name = "updates"
    description = "apt update/upgrade, install unattended-upgrades, write security-only 51-lhm"
    implemented = True

    def apply(self, runner: Runner, *, security_only: bool = False) -> list[StepResult]:
        backend = AptBackend(runner)
        desired = desired_conf()
        conf_needed = _read_conf() != desired

        if runner.dry_run:
            installed = False
        else:
            installed = backend.pkg_installed(PACKAGE)

        upgrade_label = "security upgrade" if security_only else "apt upgrade"
        upgrade_detail = "unattended-upgrade" if security_only else ""
        upgrade_cmd = (
            "unattended-upgrade (security updates only)" if security_only else "apt-get upgrade"
        )
        plan = ["Plan (updates):", "  - apt-get update"]
        if security_only and not installed:
            plan.append(f"  - install {PACKAGE}")
        plan.append(f"  - {upgrade_cmd}")
        if not security_only and not installed:
            plan.append(f"  - install {PACKAGE}")
        plan.append(
            f"  - write {APT_CONF} (backup existing file)"
            if conf_needed
            else f"  - {APT_CONF} already current (skip)"
        )

        if runner.dry_run:
            for line in plan:
                print(line)
            install_step = (
                StepResult(f"install {PACKAGE}", Status.SKIPPED, "already installed")
                if installed
                else StepResult(f"install {PACKAGE}", Status.PLANNED)
            )
            return [
                StepResult("apt update", Status.PLANNED, "refresh package lists"),
                install_step,
                StepResult(upgrade_label, Status.PLANNED, upgrade_detail),
                StepResult(
                    f"write {APT_CONF}",
                    Status.PLANNED if conf_needed else Status.SKIPPED,
                    "" if conf_needed else "already current",
                ),
            ]

        if not confirm_once(plan):
            return [StepResult("updates", Status.ABORTED, "aborted; no changes made")]

        results: list[StepResult] = []
        try:
            backend.update()
            results.append(StepResult("apt update", Status.CHANGED, "package lists refreshed"))

            if security_only:
                if not installed:
                    backend.install([PACKAGE])
                    installed = True
                    results.append(StepResult(f"install {PACKAGE}", Status.CHANGED))
                else:
                    results.append(StepResult(f"install {PACKAGE}", Status.SKIPPED, "installed"))
                backend.upgrade(security_only=True)
                results.append(StepResult(upgrade_label, Status.CHANGED, upgrade_detail))
            else:
                backend.upgrade(security_only=False)
                results.append(StepResult(upgrade_label, Status.CHANGED))
                if not installed:
                    backend.install([PACKAGE])
                    installed = True
                    results.append(StepResult(f"install {PACKAGE}", Status.CHANGED))
                else:
                    results.append(StepResult(f"install {PACKAGE}", Status.SKIPPED, "installed"))

            if conf_needed:
                outcome = write_dropin(APT_CONF, desired)
                results.append(
                    StepResult(
                        f"write {APT_CONF}",
                        Status.CHANGED if outcome == "written" else Status.SKIPPED,
                    )
                )
            else:
                results.append(StepResult(f"write {APT_CONF}", Status.SKIPPED, "already current"))
        except (CommandError, OSError) as exc:
            results.append(StepResult("updates", Status.FAIL, str(exc)))
            print(f"lhm: rollback hint: lhm rollback {APT_CONF}", flush=True)
            return results

        results.append(self._verify(runner, desired))
        return results

    def _verify(self, runner: Runner, desired: str) -> StepResult:
        state = probe_service(runner, PACKAGE)
        service_ok = bool(state.active or state.enabled)
        conf_ok = _read_conf() == desired
        if service_ok and conf_ok:
            return StepResult("verify", Status.OK, "service active/enabled and 51-lhm current")
        problems = []
        if not service_ok:
            problems.append(f"{PACKAGE} not active or enabled")
        if not conf_ok:
            problems.append(f"{APT_CONF} content mismatch")
        return StepResult("verify", Status.FAIL, "; ".join(problems))
