"""Services module: review listening ports and enabled units, per-item selection."""

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatch

from lhm.core import checks
from lhm.core.report import Status, StepResult, render_table
from lhm.core.runner import CommandError, Runner

PROTECTED_PATTERNS = (
    "ssh",
    "sshd",
    "ufw",
    "fail2ban",
    "auditd",
    "systemd-*",
    "dbus",
    "dbus-*",
    "cron",
    "rsyslog",
    "unattended-upgrades",
    "getty@*",
    "lhm-*",
    "network*",
    "resolved",
    "systemd-resolved",
    "logind",
    "systemd-logind",
    "journald",
    "systemd-journald",
    "udisks2",
    "polkit",
    "polkitd",
    "sudo",
)


class SelectionError(ValueError):
    """Raised when the interactive selection cannot be interpreted."""


@dataclass(frozen=True)
class ServiceItem:
    unit: str
    package: str


def is_protected(unit: str) -> bool:
    """True when ``unit`` is essential and must never be offered for disabling."""
    name = unit.removesuffix(".service").removesuffix(".timer")
    return any(name == pattern or fnmatch(name, pattern) for pattern in PROTECTED_PATTERNS)


def parse_selection(answer: str, count: int) -> list[int]:
    """Parse ``1 3``, ``all`` or ``none`` into sorted 0-based indices."""
    text = answer.strip().lower()
    if text in {"", "none"}:
        return []
    if text == "all":
        return list(range(count))
    indices: list[int] = []
    for token in text.replace(",", " ").split():
        if not token.isdigit():
            raise SelectionError(f"not a number: {token!r}")
        index = int(token) - 1
        if not 0 <= index < count:
            raise SelectionError(f"out of range: {token} (choose 1..{count})")
        if index not in indices:
            indices.append(index)
    return sorted(indices)


def enabled_units(runner: Runner) -> list[str]:
    result = runner.run(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--type=timer",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
        check=False,
    )
    if not result.ok:
        return []
    units = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts:
            units.append(parts[0])
    return units


def candidates(runner: Runner) -> list[ServiceItem]:
    """Enabled services/timers that are not on the protected list."""
    return [
        ServiceItem(unit=unit, package=package_of(runner, unit))
        for unit in enabled_units(runner)
        if not is_protected(unit)
    ]


def package_of(runner: Runner, unit: str) -> str:
    owner = runner.run(["systemctl", "show", "-p", "FragmentPath", "--value", unit], check=False)
    path = owner.stdout.strip()
    if not path:
        return "-"
    result = runner.run(["dpkg-query", "-S", path], check=False)
    if not result.ok or ":" not in result.stdout:
        return "-"
    return result.stdout.split(":", 1)[0].strip() or "-"


def listing(runner: Runner) -> tuple[str, list[ServiceItem]]:
    """Return a ports table plus the selectable, non-protected enabled units."""
    ports = checks.listening_ports(runner)
    rows = [
        [record.proto, f"{record.address}:{record.port or ''}", record.process or "-"]
        for record in ports
    ]
    ports_text = (
        render_table(["proto", "address", "process"], rows) if rows else "(no listening ports)"
    )
    return ports_text, candidates(runner)


def _final_confirm(plan: Sequence[str]) -> bool:
    """Ask for one confirmation after collecting the unit selection."""
    if not sys.stdin.isatty():
        print(
            "lhm: refusing to continue: stdin is not a TTY "
            "(re-run interactively or use --dry-run)",
            file=sys.stderr,
        )
        return False
    for line in plan:
        print(line)
    try:
        answer = input("Disable these units now? type 'y' to continue: ")
    except EOFError:
        print("lhm: aborted: no input available.", file=sys.stderr)
        return False
    if answer != "y":
        print("lhm: aborted, nothing further was changed.", file=sys.stderr)
        return False
    return True


def apply_cleanup_services(runner: Runner, *, select: str = "") -> list[StepResult]:
    if runner.dry_run:
        print("Plan (cleanup-services):")
        print("  - ss -tulpn: show listening ports")
        print("  - systemctl list-unit-files --state=enabled: offer non-protected units")
        print("  - interactive selection, then systemctl disable --now per chosen unit")
        print("  - packages stay installed (no autoremove)")
        return [StepResult("cleanup-services", Status.PLANNED, "interactive selection, dry-run")]

    ports_text, items = listing(runner)

    if not items:
        print(ports_text)
        return [StepResult("cleanup-services", Status.SKIPPED, "no non-protected enabled units")]

    print(ports_text)
    print()
    rows = [
        [str(index), item.unit, item.package] for index, item in enumerate(items, start=1)
    ]
    print(render_table(["#", "unit", "package"], rows))
    print("Select units to disable (numbers, 'all', or 'none'); packages stay installed.")

    if select:
        answer = select
    else:
        try:
            answer = input("selection: ")
        except EOFError:
            print("lhm: aborted: no input available.", file=sys.stderr)
            return [StepResult("cleanup-services", Status.ABORTED, "aborted; no input available")]
    try:
        chosen = parse_selection(answer, len(items))
    except SelectionError as exc:
        return [StepResult("cleanup-services", Status.FAIL, str(exc))]

    if not chosen:
        return [StepResult("cleanup-services", Status.SKIPPED, "nothing selected")]

    plan = ["Plan (cleanup-services):"]
    for index in chosen:
        item = items[index]
        plan.append(f"  - systemctl disable --now {item.unit} (package {item.package} kept)")
    plan.append("  - no packages are removed or purged")
    if not _final_confirm(plan):
        return [StepResult("cleanup-services", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        for index in chosen:
            item = items[index]
            runner.run(["systemctl", "disable", "--now", item.unit])
            results.append(
                StepResult(f"disable --now {item.unit}", Status.CHANGED, f"package {item.package}")
            )
    except (CommandError, OSError) as exc:
        results.append(StepResult("cleanup-services", Status.FAIL, str(exc)))
        return results

    remaining = {item.unit for item in candidates(runner)}
    still = [items[index].unit for index in chosen if items[index].unit in remaining]
    if still:
        return [*results, StepResult("verify", Status.FAIL, "still enabled: " + ", ".join(still))]
    return [*results, StepResult("verify", Status.OK, "selected units disabled")]


def inspect(runner: Runner) -> dict[str, object]:
    _, items = listing(runner)
    return {
        "candidates": [{"unit": item.unit, "package": item.package} for item in items],
        "protected_patterns": list(PROTECTED_PATTERNS),
    }


class ServicesModule:
    name = "services"
    description = "Review listening ports and enabled units, per-item selection"
    implemented = True

    def apply(self, runner: Runner, *, select: str = "") -> list[StepResult]:
        return apply_cleanup_services(runner, select=select)
