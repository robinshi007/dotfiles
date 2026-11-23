"""Sandbox module: systemd hardening drop-ins for a fixed service whitelist."""

import re
from collections.abc import Sequence
from pathlib import Path

from lhm.core import colors
from lhm.core.backup import newest_backup, rollback_file
from lhm.core.confirm import confirm_twice
from lhm.core.files import write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

UNIT_DIR = Path("/etc/systemd/system")
UNIT_SUFFIX = ".service"

# Fixed whitelist (DESIGN.md module row 5). Anything else is refused.
WHITELIST: dict[str, tuple[tuple[str, str], ...]] = {
    "ssh": (
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        # read-only (not yes): sshd must read /home/<user>/.ssh/authorized_keys.
        ("ProtectHome", "read-only"),
        ("PrivateTmp", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectControlGroups", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("ReadWritePaths", "/etc/ssh"),
    ),
    # nginx uses ProtectSystem=full instead of strict: its master process reads
    # /etc/nginx and legitimately writes to /var/log/nginx and /var/lib/nginx,
    # which would require an ever-growing ReadWritePaths list under strict.
    # full (read-only /usr, /boot, /etc) is the conservative middle ground.
    "nginx": (
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "full"),
        ("PrivateTmp", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectControlGroups", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("ReadWritePaths", "/var/log/nginx /var/lib/nginx"),
        ("RuntimeDirectory", "nginx"),
    ),
    "fail2ban": (
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "full"),
        ("PrivateTmp", "yes"),
        ("ReadWritePaths", "/var/lib/fail2ban /var/log/fail2ban"),
    ),
}

ALLOWED = tuple(WHITELIST)


class SandboxError(ValueError):
    """Raised for a service outside the fixed whitelist."""


def check_whitelist(services: Sequence[str]) -> list[str]:
    """Return the requested services or raise ``SandboxError`` on the first stranger."""
    for service in services:
        if service not in WHITELIST:
            raise SandboxError(
                f"refusing sandbox for {service!r}: allowed services are "
                + ", ".join(ALLOWED)
            )
    return list(dict.fromkeys(services))


def unit_name(service: str) -> str:
    return f"{service}{UNIT_SUFFIX}"


def dropin_path(service: str) -> Path:
    return UNIT_DIR / f"{unit_name(service)}.d" / "99-lhm-sandbox.conf"


def desired_dropin(service: str) -> str:
    lines = [
        f"# ===== lhm sandbox for {unit_name(service)} =====",
        "# Managed by lhm (/etc/systemd/system/<unit>.d/99-lhm-sandbox.conf).",
        "[Service]",
    ]
    lines.extend(f"{key}={value}" for key, value in WHITELIST[service])
    return "\n".join(lines) + "\n"


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _installed(runner: Runner, service: str) -> bool:
    result = runner.run(
        ["systemctl", "show", "-p", "LoadState", "--value", unit_name(service)], check=False
    )
    return result.ok and result.stdout.strip() in {"loaded", "masked"}


_SCORE_RE = re.compile(r"Overall exposure level for .*?:\s*(.+)$")


def _exposure(runner: Runner, service: str) -> str:
    result = runner.run(["systemd-analyze", "security", unit_name(service)], check=False)
    if not result.ok:
        return "systemd-analyze security unavailable"
    for line in result.stdout.splitlines():
        match = _SCORE_RE.search(line.strip())
        if match:
            return match.group(1).strip()
    return "score unavailable"


def apply_sandbox(runner: Runner, *, services: Sequence[str] = ()) -> list[StepResult]:
    requested = list(services) or list(ALLOWED)
    try:
        targets = check_whitelist(requested)
    except SandboxError as exc:
        return [StepResult("sandbox", Status.FAIL, str(exc))]

    if runner.dry_run:
        present = {service: True for service in targets}
    else:
        present = {service: _installed(runner, service) for service in targets}
    usable = [service for service in targets if present[service]]
    missing = [service for service in targets if not present[service]]

    pending = [
        service
        for service in usable
        if _read(dropin_path(service)) != desired_dropin(service)
    ]
    for service in missing:
        print(f"lhm: warning: {unit_name(service)} not installed, skipping sandbox", flush=True)

    plan = ["Plan (sandbox):"]
    for service in targets:
        if not present[service]:
            plan.append(f"  - skip {unit_name(service)}: unit not installed (warning)")
        elif service in pending:
            plan.append(f"  - write {dropin_path(service)} (backup existing file)")
        else:
            plan.append(f"  - {dropin_path(service)} already current (skip)")
    plan.append("  - systemctl daemon-reload")
    for service in usable:
        plan.append(f"  - systemctl restart {unit_name(service)}")
    plan.append("  - risk: a too-strict sandbox can break a service; check its logs on failure")

    if runner.dry_run:
        for line in plan:
            print(line)
        results = [
            StepResult(f"skip {unit_name(s)}", Status.SKIPPED, "unit not installed")
            for s in missing
        ]
        for service in usable:
            results.append(
                StepResult(
                    f"write {dropin_path(service)}",
                    Status.PLANNED if service in pending else Status.SKIPPED,
                    "" if service in pending else "already current",
                )
            )
        runner.run(["systemctl", "daemon-reload"])
        results.append(StepResult("daemon-reload", Status.PLANNED))
        for service in usable:
            runner.run(["systemctl", "restart", unit_name(service)])
            results.append(StepResult(f"restart {unit_name(service)}", Status.PLANNED))
        return results

    if not missing and not pending:
        results = [
            StepResult(f"write {dropin_path(s)}", Status.SKIPPED, "already current") for s in usable
        ]
        results.append(StepResult("daemon-reload", Status.SKIPPED, "no drop-in changed"))
        return [*results, *_verify_all(runner, usable)]

    if not confirm_twice(plan):
        return [StepResult("sandbox", Status.SKIPPED, "aborted; no changes made")]

    results = [
        StepResult(f"skip {unit_name(s)}", Status.SKIPPED, "unit not installed")
        for s in missing
    ]
    try:
        for service in usable:
            if service in pending:
                outcome = write_dropin(dropin_path(service), desired_dropin(service))
                results.append(
                    StepResult(
                        f"write {dropin_path(service)}",
                        Status.CHANGED if outcome == "written" else Status.SKIPPED,
                    )
                )
            else:
                results.append(
                    StepResult(f"write {dropin_path(service)}", Status.SKIPPED, "already current")
                )
        runner.run(["systemctl", "daemon-reload"])
        results.append(StepResult("daemon-reload", Status.CHANGED))
        for service in usable:
            restart = runner.run(["systemctl", "restart", unit_name(service)], check=False)
            if not restart.ok:
                # A broken unit would leave the service down: restore the previous
                # drop-in automatically instead of only printing a hint.
                restored = _rollback_dropin(service)
                if restored:
                    runner.run(["systemctl", "daemon-reload"], check=False)
                    runner.run(["systemctl", "restart", unit_name(service)], check=False)
                detail = f"restart failed (rc={restart.returncode})"
                if restart.stderr.strip():
                    detail += f": {restart.stderr.strip()}"
                detail += f"; {restored}"
                results.append(StepResult(f"restart {unit_name(service)}", Status.FAIL, detail))
                return results
            results.append(StepResult(f"restart {unit_name(service)}", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("sandbox", Status.FAIL, str(exc)))
        for service in usable:
            if dropin_path(service).exists():
                print(f"lhm: rollback hint: lhm rollback {dropin_path(service)}", flush=True)
                break
        return results

    return [*results, *_verify_all(runner, usable)]


def _rollback_dropin(service: str) -> str:
    """Restore the newest backup of the drop-in, or delete a newly created one."""
    path = dropin_path(service)
    backup = newest_backup(path)
    if backup is not None:
        rollback_file(path)
        return f"restored {backup.name}"
    if path.exists():
        try:
            old = path.read_text(encoding="utf-8")
        except OSError:
            old = None
        path.unlink()
        colors.file_change("deleted", path, old=old)
        return "removed the new drop-in"
    return "no drop-in to roll back"


def _verify_all(runner: Runner, services: Sequence[str]) -> list[StepResult]:
    steps: list[StepResult] = []
    for service in services:
        path = dropin_path(service)
        if not path.is_file():
            steps.append(StepResult(f"verify {unit_name(service)}", Status.FAIL, f"{path} missing"))
            continue
        steps.append(
            StepResult(
                f"verify {unit_name(service)}",
                Status.OK,
                f"exposure {_exposure(runner, service)}",
            )
        )
    return steps


def inspect() -> dict[str, object]:
    """Read-only state used by ``check`` (whitelist and drop-in currency)."""
    return {
        service: {
            "unit": unit_name(service),
            "dropin": str(dropin_path(service)),
            "current": _read(dropin_path(service)) == desired_dropin(service),
        }
        for service in ALLOWED
    }


class SandboxModule:
    name = "sandbox"
    description = "systemd sandboxing drop-ins for a fixed service whitelist"
    implemented = True

    def apply(self, runner: Runner, *, services: Sequence[str] = ()) -> list[StepResult]:
        return apply_sandbox(runner, services=services)
