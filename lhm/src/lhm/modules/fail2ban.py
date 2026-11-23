"""fail2ban module: install, jail.local for the sshd jail, enable and verify."""

import re
import socket
from pathlib import Path

from lhm.core.confirm import confirm_twice
from lhm.core.distro import AptBackend, DistroError
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGES = ("fail2ban", "nftables")  # nftables is only a Recommends of fail2ban
TEMPLATE = "jail.local.tmpl"
JAIL_LOCAL = Path("/etc/fail2ban/jail.local")
SSH_PORT = 22345
TIME_RE = re.compile(r"\d+[smhdw]?")


class JailError(ValueError):
    """Raised when a jail duration or retry value is malformed."""


def _time_value(name: str, value: str) -> str:
    if not TIME_RE.fullmatch(value):
        raise JailError(f"invalid {name} {value!r}: use e.g. 1h, 10m, 3600")
    return value


def desired_conf(
    *, bantime: str = "1h", findtime: str = "10m", maxretry: str = "5", hostname: str = ""
) -> str:
    return render_template(
        TEMPLATE,
        bantime=_time_value("bantime", bantime),
        findtime=_time_value("findtime", findtime),
        maxretry=str(int(_time_value("maxretry", maxretry))),
        ssh_port=str(SSH_PORT),
        hostname=hostname or socket.gethostname(),
    )


def _read_jail() -> str | None:
    try:
        return JAIL_LOCAL.read_text(encoding="utf-8")
    except OSError:
        return None


def _verify(runner: Runner) -> StepResult:
    result = runner.run(["fail2ban-client", "status", "sshd"], check=False)
    if not result.ok or "sshd" not in result.stdout:
        detail = f"fail2ban-client status sshd rc={result.returncode}"
        if result.stderr.strip():
            detail += f": {result.stderr.strip()}"
        return StepResult("verify", Status.FAIL, detail)
    match = re.search(r"Currently banned:\s*(\d+)", result.stdout)
    banned = match.group(1) if match else "?"
    return StepResult("verify", Status.OK, f"sshd jail active, currently banned: {banned}")


def apply_fail2ban(
    runner: Runner,
    *,
    bantime: str = "1h",
    findtime: str = "10m",
    maxretry: str = "5",
) -> list[StepResult]:
    try:
        desired = desired_conf(bantime=bantime, findtime=findtime, maxretry=maxretry)
    except (JailError, ValueError) as exc:
        return [StepResult("fail2ban", Status.FAIL, str(exc))]

    backend = AptBackend(runner)
    installed = [p for p in PACKAGES if not runner.dry_run and backend.pkg_installed(p)]
    missing = [p for p in PACKAGES if p not in installed]
    needed = _read_jail() != desired

    plan = ["Plan (fail2ban):"]
    if missing:
        plan.append(f"  - install {' '.join(missing)}")
    else:
        plan.append(f"  - {' '.join(PACKAGES)} already installed")
    plan.append(
        f"  - write {JAIL_LOCAL} (sshd jail, port {SSH_PORT}, backend systemd, "
        f"bantime {bantime}, findtime {findtime}, maxretry {maxretry})"
        if needed
        else f"  - {JAIL_LOCAL} already current (skip)"
    )
    plan.append("  - systemctl enable --now fail2ban")
    plan.append("  - risk: check your own IP is not banned before closing the session")

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        if missing:
            backend.install(missing)
            results.append(StepResult(f"install {' '.join(missing)}", Status.PLANNED))
        else:
            results.append(StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"))
        results.append(
            StepResult(
                f"write {JAIL_LOCAL}",
                Status.PLANNED if needed else Status.SKIPPED,
                "" if needed else "already current",
            )
        )
        runner.run(["systemctl", "enable", "--now", "fail2ban"])
        results.append(StepResult("enable --now fail2ban", Status.PLANNED))
        return results

    if not needed and not missing:
        state = runner.run(["systemctl", "is-active", "fail2ban"], check=False)
        if state.ok:
            return [
                StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"),
                StepResult(f"write {JAIL_LOCAL}", Status.SKIPPED, "already current"),
                StepResult("enable --now fail2ban", Status.SKIPPED, "already active"),
                _verify(runner),
            ]

    if not confirm_twice(plan):
        return [StepResult("fail2ban", Status.SKIPPED, "aborted; no changes made")]

    results = []
    try:
        if missing:
            backend.install(missing)
            results.append(StepResult(f"install {' '.join(missing)}", Status.CHANGED))
        else:
            results.append(StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"))
        if needed:
            outcome = write_dropin(JAIL_LOCAL, desired)
            results.append(
                StepResult(
                    f"write {JAIL_LOCAL}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {JAIL_LOCAL}", Status.SKIPPED, "already current"))
        runner.run(["systemctl", "enable", "--now", "fail2ban"])
        results.append(StepResult("enable --now fail2ban", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("fail2ban", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {JAIL_LOCAL}", flush=True)
        return results

    results.append(_verify(runner))
    return results


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    try:
        installed = AptBackend(runner).pkg_installed("fail2ban") if probe_package else None
    except DistroError:
        installed = None
    active = runner.run(["systemctl", "is-active", "fail2ban"], check=False)
    return {
        "package": "fail2ban",
        "nftables_dependency": "explicitly installed by lhm",
        "installed": installed,
        "active": active.ok,
        "jail_local": str(JAIL_LOCAL),
        "jail_current": _read_jail() == desired_conf(),
    }


class Fail2banModule:
    name = "fail2ban"
    description = "Install fail2ban and write jail.local for sshd"
    implemented = True

    def apply(
        self,
        runner: Runner,
        *,
        bantime: str = "1h",
        findtime: str = "10m",
        maxretry: str = "5",
    ) -> list[StepResult]:
        return apply_fail2ban(
            runner, bantime=bantime, findtime=findtime, maxretry=maxretry
        )
