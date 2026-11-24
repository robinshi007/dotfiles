"""fail2ban module: install, jail.d drop-in for sshd/caddy, enable and verify.

lhm writes a ``jail.d/99-lhm.local`` drop-in, never ``/etc/fail2ban/jail.local``:
load order is jail.conf -> jail.d/*.conf -> jail.local -> jail.d/*.local, so the
drop-in overrides the host's hand-maintained jail.local, which stays untouched.
"""

import re
import socket
from pathlib import Path

from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend, DistroError
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGES = ("fail2ban", "nftables")  # nftables is only a Recommends of fail2ban
TEMPLATE = "99-lhm.local.tmpl"
CADDY_TEMPLATE = "caddy-filter.conf.tmpl"

JAIL_DROPIN = Path("/etc/fail2ban/jail.d/99-lhm.local")
CADDY_FILTER = Path("/etc/fail2ban/filter.d/caddy-lhm.conf")
DBFILE = Path("/var/lib/fail2ban/fail2ban.sqlite3")
CADDY_UNIT = "caddy.service"

# Never written by lhm: it holds the host's own custom jails. Guards any future
# code path that might target it (the drop-in overrides it by load order).
LEGACY_JAIL_LOCAL = Path("/etc/fail2ban/jail.local")

SSH_PORT = 22345
CADDY_PORTS = "80,443"
SSHD_BANTIME = "8h"
SSHD_FINDTIME = "30m"
SSHD_MAXRETRY = "3"
CADDY_MAXRETRY = "5"
TIME_RE = re.compile(r"\d+[smhdw]?")
RETRY_RE = re.compile(r"\d+")


class JailError(ValueError):
    """Raised when a jail duration or retry value is malformed."""


def _time_value(name: str, value: str) -> str:
    if not TIME_RE.fullmatch(value):
        raise JailError(f"invalid {name} {value!r}: use e.g. 1h, 10m, 3600")
    if _seconds(value) == 0:
        raise JailError(
            f"invalid {name} {value!r}: must be strictly positive "
            "(a zero duration disables the jail, e.g. use 1h, 10m, 3600)"
        )
    return value


def _retry_value(name: str, value: str) -> str:
    if not RETRY_RE.fullmatch(value):
        raise JailError(
            f"invalid {name} {value!r}: use a positive integer without a unit "
            "suffix (e.g. 3)"
        )
    if int(value) == 0:
        raise JailError(
            f"invalid {name} {value!r}: must be strictly positive "
            "(0 would disable banning, e.g. use 3)"
        )
    return str(int(value))


def _seconds(value: str) -> int | None:
    """Seconds for a fail2ban duration (``1h``, ``30m``, ``4w``, ``3600``)."""
    match = re.fullmatch(r"(\d+)([smhdw]?)", value)
    if match is None:
        return None
    scale = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return int(match.group(1)) * scale[match.group(2)]


def _write_managed(path: Path, content: str) -> str:
    """Write a managed config, refusing the host's hand-maintained jail.local."""
    if Path(path) == LEGACY_JAIL_LOCAL:
        raise JailError(
            "refusing to write /etc/fail2ban/jail.local: lhm only writes the "
            "jail.d/99-lhm.local drop-in and never touches the host's jail.local"
        )
    return write_dropin(path, content)


def desired_conf(
    *,
    bantime: str = SSHD_BANTIME,
    findtime: str = SSHD_FINDTIME,
    maxretry: str = SSHD_MAXRETRY,
    caddy: bool = False,
    caddy_maxretry: str = CADDY_MAXRETRY,
    hostname: str = "",
) -> str:
    return render_template(
        TEMPLATE,
        bantime=_time_value("bantime", bantime),
        findtime=_time_value("findtime", findtime),
        maxretry=_retry_value("maxretry", maxretry),
        caddy_enabled="true" if caddy else "false",
        caddy_maxretry=_retry_value("caddy_maxretry", caddy_maxretry),
        ssh_port=str(SSH_PORT),
        hostname=hostname or socket.gethostname(),
    )


def desired_caddy_filter() -> str:
    return render_template(CADDY_TEMPLATE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def dbfile_path(runner: Runner) -> tuple[Path, bool]:
    """Effective dbfile and whether it exists (packaging default as fallback).

    ``bantime.increment`` is silently inert without a dbfile, so the path the
    daemon actually uses matters, not just the hardcoded Debian default.
    """
    result = runner.run(["fail2ban-client", "-d"], check=False)
    if result.ok:
        match = re.search(r"\['set', 'dbfile', '([^']+)'\]", result.stdout)
        if match:
            path = Path(match.group(1))
            return path, path.exists()
    return DBFILE, DBFILE.exists()


def caddy_unit_present(runner: Runner) -> bool | None:
    """Whether ``caddy.service`` exists; None when it cannot be probed."""
    result = runner.run(["systemctl", "list-unit-files", CADDY_UNIT], check=False)
    if not result.ok:
        return None
    return any(
        line.split() and line.split()[0] == CADDY_UNIT
        for line in result.stdout.splitlines()
    )


def jail_setting(runner: Runner, jail: str, key: str) -> str | None:
    """Effective value from the running daemon, or None when unprobeable."""
    result = runner.run(["fail2ban-client", "get", jail, key], check=False)
    if not result.ok:
        return None
    return result.stdout.strip()


def jail_increment_active(runner: Runner, jail: str) -> bool | None:
    """Whether ``bantime.increment`` is effective, read from ``fail2ban-client -d``."""
    result = runner.run(["fail2ban-client", "-d"], check=False)
    if not result.ok:
        return None
    pattern = re.compile(rf"\['set', '{re.escape(jail)}', 'bantime\.increment', True\]")
    return pattern.search(result.stdout) is not None


def _client_missing(result: object) -> bool:
    """True when the probe failed because fail2ban-client itself is unavailable."""
    return getattr(result, "returncode", 0) in {126, 127, 124}


def _verify(runner: Runner, *, caddy: bool, bantime: str = SSHD_BANTIME) -> list[StepResult]:
    results: list[StepResult] = []
    status = runner.run(["fail2ban-client", "status", "sshd"], check=False)
    if _client_missing(status):
        return [
            StepResult(
                "verify sshd jail",
                Status.SKIPPED,
                f"fail2ban-client unavailable (rc={status.returncode})",
            )
        ]
    if not status.ok or "sshd" not in status.stdout:
        detail = f"fail2ban-client status sshd rc={status.returncode}"
        if status.stderr.strip():
            detail += f": {status.stderr.strip()}"
        results.append(StepResult("verify sshd jail", Status.FAIL, detail))
        return results
    match = re.search(r"Currently banned:\s*(\d+)", status.stdout)
    banned = match.group(1) if match else "?"
    results.append(
        StepResult("verify sshd jail", Status.OK, f"active, currently banned: {banned}")
    )

    effective = jail_setting(runner, "sshd", "bantime")
    want = _seconds(bantime)
    if effective is None:
        results.append(
            StepResult(
                "verify bantime", Status.SKIPPED, "fail2ban-client get unavailable (needs root?)"
            )
        )
    elif effective.isdigit() and _seconds(effective) == want:
        results.append(StepResult("verify bantime", Status.OK, f"{bantime} effective"))
    else:
        results.append(
            StepResult("verify bantime", Status.FAIL, f"effective {effective}s, want {want}s")
        )

    increment = jail_increment_active(runner, "sshd")
    if increment is None:
        results.append(
            StepResult("verify bantime.increment", Status.SKIPPED, "fail2ban-client -d unavailable")
        )
    elif increment:
        results.append(
            StepResult("verify bantime.increment", Status.OK, "incrementing bans active")
        )
    else:
        results.append(
            StepResult(
                "verify bantime.increment", Status.FAIL, "bantime.increment not set for sshd"
            )
        )

    if not caddy:
        results.append(
            StepResult("verify caddy jail", Status.SKIPPED, "caddy jail disabled (pass --caddy)")
        )
        return results
    caddy_status = runner.run(["fail2ban-client", "status", "caddy"], check=False)
    if caddy_status.ok and "caddy" in caddy_status.stdout:
        results.append(StepResult("verify caddy jail", Status.OK, "caddy jail active"))
    else:
        detail = f"fail2ban-client status caddy rc={caddy_status.returncode}"
        if caddy_status.stderr.strip():
            detail += f": {caddy_status.stderr.strip().splitlines()[-1]}"
        results.append(StepResult("verify caddy jail", Status.FAIL, detail))
    return results


def _service_active(runner: Runner) -> bool:
    return runner.run(["systemctl", "is-active", "fail2ban"], check=False).ok


def _activate(runner: Runner, *, was_active: bool) -> tuple[str, Status]:
    """Restart the jails when the daemon runs, enable --now when it does not.

    A plain ``systemctl reload`` (SIGHUP -> ``fail2ban-client reload``) breaks
    the banaction: fail2ban 1.0.2's reload never runs the action's
    ``actionstart``, and when ``banaction`` resolves to a new action name the
    reload deletes both the old and the freshly added action, leaving the jail
    with none (``fail2ban-client get sshd actions`` -> "No actions for jail
    sshd"). Bans then only reach the DB: ``set <jail> banip`` reports OK while
    the nftables table is never created and nothing is blocked.
    ``reload --restart`` stops and restarts the affected jails, so
    ``actionstart`` runs and recreates the table, while the server (and its
    socket) stays up; existing bans are kept (no ``--unban``).
    """
    if was_active:
        runner.run(["fail2ban-client", "reload", "--restart"])
        return "reload --restart fail2ban", Status.CHANGED
    runner.run(["systemctl", "enable", "--now", "fail2ban"])
    return "enable --now fail2ban", Status.CHANGED


def apply_fail2ban(
    runner: Runner,
    *,
    bantime: str = SSHD_BANTIME,
    findtime: str = SSHD_FINDTIME,
    maxretry: str = SSHD_MAXRETRY,
    caddy: bool = False,
    caddy_maxretry: str = CADDY_MAXRETRY,
) -> list[StepResult]:
    try:
        desired = desired_conf(
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            caddy=caddy,
            caddy_maxretry=caddy_maxretry,
        )
        caddy_filter = desired_caddy_filter() if caddy else ""
    except (JailError, ValueError) as exc:
        return [StepResult("fail2ban", Status.FAIL, str(exc))]

    backend = AptBackend(runner)
    installed = [p for p in PACKAGES if not runner.dry_run and backend.pkg_installed(p)]
    missing = [p for p in PACKAGES if p not in installed]
    jail_needed = _read(JAIL_DROPIN) != desired
    filter_needed = bool(caddy) and _read(CADDY_FILTER) != caddy_filter
    # Dry-run executes nothing (not even read-only probes), so the activation
    # branch and the caddy unit check are only known at apply time.
    was_active: bool | None = None if runner.dry_run else _service_active(runner)
    unit_present = None if runner.dry_run else caddy_unit_present(runner)

    plan = ["Plan (fail2ban):"]
    if missing:
        plan.append(f"  - install {' '.join(missing)}")
    else:
        plan.append(f"  - {' '.join(PACKAGES)} already installed")
    plan.append(
        f"  - write {JAIL_DROPIN} (sshd jail: port {SSH_PORT}, mode aggressive, "
        f"maxretry {maxretry}, findtime {findtime}, bantime {bantime}, "
        f"bantime.increment 2^n factor 3 maxtime 4w)"
        if jail_needed
        else f"  - {JAIL_DROPIN} already current (skip)"
    )
    if caddy:
        plan.append(
            f"  - write {CADDY_FILTER} (caddy jail: port {CADDY_PORTS}, "
            f"maxretry {caddy_maxretry}, findtime 10m, bantime 1h)"
            if filter_needed
            else f"  - {CADDY_FILTER} already current (skip)"
        )
        plan.append(f"  - caddy jail enabled in the drop-in (journald unit {CADDY_UNIT})")
        if unit_present is False:
            plan.append(
                f"  - WARNING: {CADDY_UNIT} does not exist; fail2ban will fail to start "
                "until Caddy is installed (install caddy, then re-run)"
            )
        elif unit_present is None:
            plan.append(f"  - WARNING: cannot confirm {CADDY_UNIT} in dry-run")
    else:
        plan.append(
            f"  - caddy jail disabled (pass --caddy to enable it and write {CADDY_FILTER})"
        )
    if was_active is None:
        plan.append(
            "  - reload --restart fail2ban if active (a plain reload leaves the jail "
            "with no action, see _activate), else enable --now"
        )
    elif was_active:
        plan.append(
            "  - fail2ban-client reload --restart (restarts the jails so actionstart "
            "runs; the server and its bans stay up)"
        )
    else:
        plan.append("  - systemctl enable --now fail2ban")
    plan.append(
        f"  - note: a legacy {LEGACY_JAIL_LOCAL} is preserved untouched; "
        "jail.d/*.local wins over it"
    )
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
                f"write {JAIL_DROPIN}",
                Status.PLANNED if jail_needed else Status.SKIPPED,
                "" if jail_needed else "already current",
            )
        )
        if caddy:
            results.append(
                StepResult(
                    f"write {CADDY_FILTER}",
                    Status.PLANNED if filter_needed else Status.SKIPPED,
                    "" if filter_needed else "already current",
                )
            )
        runner.run(["systemctl", "enable", "--now", "fail2ban"])
        results.append(StepResult("enable --now fail2ban", Status.PLANNED))
        return results

    if not jail_needed and not filter_needed and not missing and was_active:
        results = [
            StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"),
            StepResult(f"write {JAIL_DROPIN}", Status.SKIPPED, "already current"),
        ]
        if caddy:
            results.append(StepResult(f"write {CADDY_FILTER}", Status.SKIPPED, "already current"))
        results.append(StepResult("reload --restart fail2ban", Status.SKIPPED, "already active"))
        results.extend(_verify(runner, caddy=caddy, bantime=bantime))
        return results

    if not confirm_once(plan):
        return [StepResult("fail2ban", Status.ABORTED, "aborted; no changes made")]

    results = []
    try:
        if missing:
            backend.install(missing)
            results.append(StepResult(f"install {' '.join(missing)}", Status.CHANGED))
        else:
            results.append(StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"))
        if jail_needed:
            outcome = _write_managed(JAIL_DROPIN, desired)
            results.append(
                StepResult(
                    f"write {JAIL_DROPIN}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {JAIL_DROPIN}", Status.SKIPPED, "already current"))
        if caddy:
            outcome = _write_managed(CADDY_FILTER, caddy_filter)
            results.append(
                StepResult(
                    f"write {CADDY_FILTER}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        name, status = _activate(runner, was_active=bool(was_active))
        results.append(StepResult(name, status))
    except (CommandError, OSError) as exc:
        results.append(StepResult("fail2ban", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {JAIL_DROPIN}", flush=True)
        return results

    results.extend(_verify(runner, caddy=caddy, bantime=bantime))
    return results


def _caddy_enabled_in_dropin() -> bool | None:
    text = _read(JAIL_DROPIN)
    if text is None:
        return None
    in_caddy = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_caddy = stripped == "[caddy]"
        elif in_caddy and stripped.startswith("enabled"):
            return stripped.partition("=")[2].strip().lower() == "true"
    return None


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    try:
        installed = AptBackend(runner).pkg_installed("fail2ban") if probe_package else None
    except DistroError:
        installed = None
    active = runner.run(["systemctl", "is-active", "fail2ban"], check=False)
    caddy_enabled = _caddy_enabled_in_dropin()
    dbfile, dbfile_present = dbfile_path(runner)
    return {
        "package": "fail2ban",
        "nftables_dependency": "explicitly installed by lhm",
        "installed": installed,
        "active": active.ok,
        "jail_dropin": str(JAIL_DROPIN),
        "jail_current": _read(JAIL_DROPIN) == desired_conf(),
        "caddy_filter": str(CADDY_FILTER),
        "caddy_filter_present": CADDY_FILTER.is_file(),
        "caddy_enabled": caddy_enabled,
        "legacy_jail_local": str(LEGACY_JAIL_LOCAL),
        "legacy_jail_local_present": LEGACY_JAIL_LOCAL.is_file(),
        "dbfile": str(dbfile),
        "dbfile_present": dbfile_present,
    }


class Fail2banModule:
    name = "fail2ban"
    description = "Install fail2ban and write the jail.d drop-in for sshd (+caddy)"
    implemented = True

    def apply(
        self,
        runner: Runner,
        *,
        bantime: str = SSHD_BANTIME,
        findtime: str = SSHD_FINDTIME,
        maxretry: str = SSHD_MAXRETRY,
        caddy: bool = False,
        caddy_maxretry: str = CADDY_MAXRETRY,
    ) -> list[StepResult]:
        return apply_fail2ban(
            runner,
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            caddy=caddy,
            caddy_maxretry=caddy_maxretry,
        )
