"""Firewall module: ufw, always allowing the SSH port before default deny."""

from collections.abc import Sequence

from lhm.core import checks
from lhm.core.confirm import confirm_twice
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

SSH_PORT = 22345
SSH_RULE = f"{SSH_PORT}/tcp"


class RuleError(ValueError):
    """Raised when an ``--allow`` value is not PORT/PROTO."""


def parse_allow(value: str) -> str:
    port_text, _, proto = value.partition("/")
    proto = proto.lower() or "tcp"
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise RuleError(f"invalid allow rule {value!r}: expected PORT/PROTO")
    if proto not in {"tcp", "udp"}:
        raise RuleError(f"invalid protocol in {value!r}: expected tcp or udp")
    return f"{int(port_text)}/{proto}"


def _to_ports(to: str) -> set[str]:
    return {part.strip() for part in to.split(",") if part.strip()}


def _rule_present(status: checks.UfwStatus | None, rule: str) -> bool:
    if status is None:
        return False
    for existing in status.rules:
        to = existing.to.replace(" (v6)", "")
        if existing.action.startswith("ALLOW") and rule in _to_ports(to):
            return True
    return False


def apply_firewall(runner: Runner, *, allow: Sequence[str] = ()) -> list[StepResult]:
    try:
        extra = [parse_allow(value) for value in allow]
    except RuleError as exc:
        return [StepResult("firewall", Status.FAIL, str(exc))]

    # Probe the ports sshd listens on RIGHT NOW: a server still on 22 must not
    # lose its listener when ufw flips to default deny incoming.
    current = [] if runner.dry_run else checks.current_ssh_ports(runner)
    if not runner.dry_run and not current:
        print(
            "lhm: warning: no current SSH listener detected via ss/sshd -T; "
            "make sure --allow covers the port you are connected to",
            flush=True,
        )
    current_rules = [f"{port}/tcp" for port in current if port != SSH_PORT]

    rules = list(dict.fromkeys([SSH_RULE, *current_rules, *extra]))
    # Like the updates module, dry-run assumes nothing is configured yet so the
    # plan shows the full order and records no command.
    status = None if runner.dry_run else checks.ufw_status(runner)
    missing = [rule for rule in rules if not _rule_present(status, rule)]
    enabled = status is not None and status.active
    deny_default = status is not None and status.default_incoming == "deny"
    outgoing_default = status is not None and status.default_outgoing == "allow"

    plan = ["Plan (firewall):"]
    if runner.dry_run:
        plan.append("  - probe current SSH listen port(s): ss -tlnp, fallback sshd -T")
        plan.append("  - allow the probed current SSH port(s)/tcp before enabling ufw")
    else:
        ports = ", ".join(f"{p}/tcp" for p in current) or "none detected"
        plan.append(f"  - current SSH port(s): {ports}")
    for rule in rules:
        plan.append(
            f"  - allow {rule}" if rule in missing else f"  - allow {rule} (already present, skip)"
        )
    plan.append(
        "  - default deny incoming (already set, skip)"
        if deny_default
        else "  - default deny incoming"
    )
    plan.append(
        "  - default allow outgoing (already set, skip)"
        if outgoing_default
        else "  - default allow outgoing"
    )
    plan.append(
        "  - enable ufw (already active, skip)" if enabled else "  - enable ufw --force"
    )
    plan.append(
        f"  - order: {' + '.join(rules)} allowed before default deny incoming (anti-lockout)"
    )

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        for rule in rules:
            if rule in missing:
                runner.run(["ufw", "allow", rule])
                results.append(StepResult(f"allow {rule}", Status.PLANNED))
            else:
                results.append(StepResult(f"allow {rule}", Status.SKIPPED, "already present"))
        if not deny_default:
            runner.run(["ufw", "default", "deny", "incoming"])
            results.append(StepResult("default deny incoming", Status.PLANNED))
        else:
            results.append(StepResult("default deny incoming", Status.SKIPPED, "already set"))
        if not outgoing_default:
            runner.run(["ufw", "default", "allow", "outgoing"])
            results.append(StepResult("default allow outgoing", Status.PLANNED))
        else:
            results.append(StepResult("default allow outgoing", Status.SKIPPED, "already set"))
        if not enabled:
            runner.run(["ufw", "--force", "enable"])
            results.append(StepResult("enable ufw", Status.PLANNED))
        else:
            results.append(StepResult("enable ufw", Status.SKIPPED, "already active"))
        return results

    if not missing and enabled and deny_default and outgoing_default:
        return [StepResult("firewall", Status.SKIPPED, "rules and defaults already in place")]

    if not confirm_twice(plan):
        return [StepResult("firewall", Status.SKIPPED, "aborted; no changes made")]

    results = []
    try:
        for rule in rules:
            if rule in missing:
                runner.run(["ufw", "allow", rule])
                results.append(StepResult(f"allow {rule}", Status.CHANGED))
            else:
                results.append(StepResult(f"allow {rule}", Status.SKIPPED, "already present"))
        if not deny_default:
            runner.run(["ufw", "default", "deny", "incoming"])
            results.append(StepResult("default deny incoming", Status.CHANGED))
        else:
            results.append(StepResult("default deny incoming", Status.SKIPPED, "already set"))
        if not outgoing_default:
            runner.run(["ufw", "default", "allow", "outgoing"])
            results.append(StepResult("default allow outgoing", Status.CHANGED))
        else:
            results.append(StepResult("default allow outgoing", Status.SKIPPED, "already set"))
        if not enabled:
            runner.run(["ufw", "--force", "enable"])
            results.append(StepResult("enable ufw", Status.CHANGED))
        else:
            results.append(StepResult("enable ufw", Status.SKIPPED, "already active"))
    except (CommandError, OSError) as exc:
        results.append(StepResult("firewall", Status.FAIL, str(exc)))
        print("lhm: rollback hint: ufw disable (only if it locked you out)", flush=True)
        return results

    results.append(_verify(runner, rules))
    return results


def _verify(runner: Runner, rules: Sequence[str] = (SSH_RULE,)) -> StepResult:
    status = checks.ufw_status(runner)
    if status is None:
        return StepResult("verify", Status.FAIL, "ufw status unavailable")
    problems: list[str] = []
    if not status.active:
        problems.append("ufw not active")
    if status.default_incoming != "deny":
        problems.append(f"default incoming {status.default_incoming or 'unknown'}")
    for rule in rules:
        if not _rule_present(status, rule):
            problems.append(f"{rule} not allowed")
    if problems:
        return StepResult("verify", Status.FAIL, "; ".join(problems))
    return StepResult(
        "verify", Status.OK, f"active, default deny incoming, {' + '.join(rules)} allowed"
    )


def inspect(runner: Runner) -> dict[str, object]:
    status = checks.ufw_status(runner)
    return {
        "available": status is not None,
        "active": None if status is None else status.active,
        "default_incoming": "" if status is None else status.default_incoming,
        "default_outgoing": "" if status is None else status.default_outgoing,
        "ssh_allowed": _rule_present(status, SSH_RULE),
    }


class FirewallModule:
    name = "firewall"
    description = "ufw: allow 22345/tcp first, then default deny incoming"
    implemented = True

    def apply(self, runner: Runner, *, allow: Sequence[str] = ()) -> list[StepResult]:
        return apply_firewall(runner, allow=allow)
