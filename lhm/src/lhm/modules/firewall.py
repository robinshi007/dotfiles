"""Firewall module: ufw, always allowing the SSH port before default deny."""

import re
from collections.abc import Sequence
from contextlib import ExitStack, nullcontext
from pathlib import Path

from lhm.core import checks, network
from lhm.core.confirm import confirm_once
from lhm.core.files import locked_target
from lhm.core.network import Family
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner
from lhm.modules import caddy, firewall_ufw, ssh, ssh_watchdog

SSH_PORT = 22345
SSH_RULE = f"{SSH_PORT}/tcp"
CADDY_INGRESS = ("80/tcp", "443/tcp")
UFW_LOCK_TARGET = Path(firewall_ufw.UFW_CONFIG)


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


INBOUND_ALLOW_ACTIONS = frozenset({"ALLOW", "ALLOW IN"})
INBOUND_BLOCK_ACTIONS = frozenset({"DENY", "DENY IN", "REJECT", "REJECT IN", "LIMIT", "LIMIT IN"})


def _rule_covers(existing: checks.UfwRule, rule: str, family: Family) -> bool:
    suffix = " (v6)" if family == 6 else ""
    # A scoped source, destination, or interface is not an unrestricted rule.
    source = existing.source.partition(" #")[0].strip()
    if source not in {
        f"Anywhere{suffix}",
        f"Anywhere{suffix} (log)",
        f"Anywhere{suffix} (log-all)",
    }:
        return False
    to = existing.to
    if to.endswith(" (v6)") != (family == 6):
        return False
    to = to.removesuffix(suffix)
    match = re.fullmatch(r"([0-9,:]+)(?:/(tcp|udp))?", to)
    if match is None:
        return False
    wanted_port, wanted_proto = rule.split("/")
    ports, proto = match.groups()
    if proto is not None and proto != wanted_proto:
        return False
    for entry in ports.split(","):
        start, _, end = entry.partition(":")
        if start.isdigit() and (not end or end.isdigit()):
            if int(start) <= int(wanted_port) <= int(end or start):
                return True
    return False


def _rule_decision(status: checks.UfwStatus | None, rule: str, family: Family) -> bool | None:
    for existing in status.rules if status is not None else ():
        if existing.action in INBOUND_BLOCK_ACTIONS and _block_may_intersect(
            existing, rule, family
        ):
            return False
        if existing.action in INBOUND_ALLOW_ACTIONS and _rule_covers(existing, rule, family):
            return True
    return None


def _block_may_intersect(existing: checks.UfwRule, rule: str, family: Family) -> bool:
    if family == 4 and (" (v6)" in existing.to or " (v6)" in existing.source):
        return False
    port, proto = rule.split("/")
    target = existing.to.partition(" on ")[0].removesuffix(" (v6)")
    match = re.search(r"(?:^|\s)(Anywhere|[0-9,:]+)(?:/(tcp|udp))?$", target)
    if match is None:
        return True  # An app profile or otherwise unknown scope cannot prove a disjoint block.
    ports, protocol = match.groups()
    if protocol and proto != protocol:
        return False
    if ports == "Anywhere" or not re.fullmatch(
        r"[0-9]{1,5}(?::[0-9]{1,5})?(?:,[0-9]{1,5}(?::[0-9]{1,5})?)*", ports
    ):
        return True
    return firewall_ufw.ports_match(ports, int(port))


def _rule_present(status: checks.UfwStatus | None, rule: str, family: Family = 4) -> bool:
    return _rule_decision(status, rule, family) is True


def _local_ipv6_capability() -> network.Capability:
    return network.local_ipv6_capability()


def _ufw_status(runner: Runner) -> checks.UfwStatus | None:
    text = firewall_ufw.read(runner, "ufw", "status", "verbose")
    lines = text.strip().splitlines() if text is not None else []
    if text is None or not lines or lines[0] not in {"Status: active", "Status: inactive"}:
        return None
    return checks.parse_ufw_status(text)


def _rule_plan(
    status: checks.UfwStatus | None,
    rules: Sequence[str],
    families: Sequence[Family],
    *,
    ufw_ipv6: bool,
) -> list[tuple[str, list[str] | None]]:
    plan: list[tuple[str, list[str] | None]] = []
    for rule in rules:
        missing = [family for family in families if not _rule_present(status, rule, family)]
        if not missing:
            plan.append((f"allow {rule}", None))
        elif len(missing) == 2 or not ufw_ipv6:
            plan.append((f"allow {rule}", ["ufw", "allow", rule]))
        else:
            family = missing[0]
            source = "0.0.0.0/0" if family == 4 else "::/0"
            port, proto = rule.split("/")
            command = ["ufw", "allow", "proto", proto, "from", source, "to", "any", "port", port]
            plan.append((f"allow {rule} (IPv{family})", command))
    return plan


def _caddy_ingress_identity(runner: Runner) -> str | None:
    # No disk-only, service-only or socket-only evidence authorizes public ingress.
    probe = getattr(caddy, "firewall_ingress_identity", None)
    if runner.dry_run or not callable(probe):
        return None
    try:
        identity = probe(runner)
    except CommandError, OSError, ValueError:
        return None
    return identity if isinstance(identity, str) and identity else None


def caddy_ingress(runner: Runner) -> tuple[str, ...]:
    return CADDY_INGRESS if _caddy_ingress_identity(runner) else ()


def _ordering_problem(
    runner: Runner,
    status: checks.UfwStatus | None,
    rules: list[str],
    families: Sequence[Family],
    *,
    active: bool,
) -> str | None:
    if not active and any(
        firewall_ufw.read(runner, "test", "!", "-x", f"/etc/ufw/{hook}.init") is None
        for hook in ("before", "after")
    ):
        return "UFW startup hooks could not be ruled out"
    for family in families:
        visible = {rule for rule in rules if _rule_present(status, rule, family)}
        saved = firewall_ufw.saved_coverage(runner, family, rules, fresh=not active)
        live = firewall_ufw.runtime_coverage(runner, family, rules, active=active)
        if saved != visible or live != visible:
            return f"IPv{family} saved and runtime SSH/rule ordering is unsafe or unknown"
    return None


def _first_enable_problem(runner: Runner, settings: firewall_ufw.Settings) -> str | None:
    if settings.manage_builtins is not False:
        return "MANAGE_BUILTINS=no could not be verified"
    if not firewall_ufw.startup_sysctl_safe(settings.ipt_sysctl):
        return "UFW startup IPT_SYSCTL is untrusted or has unrecognized directives"
    if not settings.ipv6 and not firewall_ufw.ipv6_filter_unavailable(runner):
        return "IPV6=no can still rewrite IPv6 chains; inability to use ip6tables unverified"
    return None


def _ssh_pending_problem() -> str | None:
    try:
        pending = ssh_watchdog.current()
    except OSError, ssh_watchdog.WatchdogError:
        return "SSH transaction state could not be verified"
    if pending is not None:
        return f"SSH watchdog transaction {pending.id} is still pending ({pending.phase})"
    return None


def apply_firewall(runner: Runner, *, allow: Sequence[str] = ()) -> list[StepResult]:
    try:
        extra = [parse_allow(value) for value in allow]
    except RuleError as exc:
        return [StepResult("firewall", Status.FAIL, str(exc))]
    if not runner.dry_run and (problem := _ssh_pending_problem()):
        return [StepResult("firewall", Status.FAIL, f"{problem}; no changes made")]

    # Probe the ports sshd listens on RIGHT NOW: a server still on 22 must not
    # lose its listener when ufw flips to default deny incoming.
    current = [] if runner.dry_run else checks.current_ssh_ports(runner)
    if current is None:
        return [
            StepResult(
                "firewall",
                Status.FAIL,
                "could not determine SSH socket state, verify all listener ports "
                "for an active SSH socket, or verify a standalone port via "
                "`ss -tlnp` and fallback `sshd -T`; no ufw commands run. "
                "From the local console, check `systemctl is-active ssh.socket sshd.socket` "
                "and compare `systemctl show --property=Listen ssh.socket sshd.socket` "
                "with `sudo ss -tlnp`. If neither socket is active, verify that "
                "`sudo sshd -T` succeeds and reports valid Port values, then retry",
            )
        ]
    if not runner.dry_run and not current and not extra:
        # Fail closed: with no probed listener and no --allow, default deny can
        # only lock the operator out. Nothing is run (not even `ufw status`).
        return [
            StepResult(
                "firewall",
                Status.FAIL,
                "no live SSH listener detected: refusing default deny incoming; "
                "from the local console, verify the port you need to keep open, "
                "then re-run with --allow PORT/tcp",
            )
        ]
    if not runner.dry_run and not current:
        print(
            "lhm: warning: no current SSH listener detected via ss/sshd -T; "
            "only the explicitly allowed ports will stay open",
            flush=True,
        )
    current_rules = [f"{port}/tcp" for port in current if port != SSH_PORT]

    caddy_identity = _caddy_ingress_identity(runner)
    auto_ingress = CADDY_INGRESS if caddy_identity else ()
    rules = list(dict.fromkeys([SSH_RULE, *current_rules, *extra, *auto_ingress]))
    families: tuple[Family, ...] = (4, 6)
    status = None
    ufw_ipv6 = True
    settings = None
    if not runner.dry_run:
        ipv6 = _local_ipv6_capability()
        if ipv6 == "unknown":
            return [
                StepResult(
                    "firewall", Status.FAIL, "local IPv6 capability unknown; no changes made"
                )
            ]
        settings = firewall_ufw.settings(runner)
        if settings is None:
            return [
                StepResult(
                    "firewall", Status.FAIL, "UFW IPv6 or enabled setting unknown; no changes made"
                )
            ]
        ufw_ipv6, configured_active = settings.ipv6, settings.enabled
        if ipv6 == "enabled" and not ufw_ipv6:
            return [
                StepResult(
                    "firewall",
                    Status.FAIL,
                    "usable IPv6 is not managed by UFW (IPV6=no); no changes made. "
                    "Use a local console with a recovery path to configure IPv6 in UFW",
                )
            ]
        if ipv6 == "disabled":
            families = (4,)
            if ufw_ipv6:
                return [
                    StepResult(
                        "firewall",
                        Status.FAIL,
                        "local IPv6 is disabled but UFW has IPV6=yes; no changes made. "
                        "Review both UFW configs from a local console",
                    )
                ]
        status = _ufw_status(runner)
        if status is None or status.active != configured_active:
            return [
                StepResult(
                    "firewall",
                    Status.FAIL,
                    "UFW runtime and enabled state could not be verified; no changes made. "
                    "Check UFW from a local console",
                )
            ]
        if not configured_active and (problem := _first_enable_problem(runner, settings)):
            return [StepResult("firewall", Status.FAIL, f"{problem}; no changes made")]
    rule_plan = _rule_plan(status, rules, families, ufw_ipv6=ufw_ipv6)
    enabled = status is not None and status.active
    deny_default = status is not None and status.default_incoming == "deny"
    outgoing_default = status is not None and status.default_outgoing == "allow"
    # `ufw default` stops and starts an enabled firewall. Confirmation does not
    # establish a usable console recovery path; leave that operation to one.
    if enabled and not (deny_default and outgoing_default):
        return [
            StepResult(
                "firewall",
                Status.FAIL,
                "changing the active UFW defaults would restart the firewall; no changes made. "
                "Use a local console with a recovery path and verify SSH rules first",
            )
        ]
    if enabled:
        for rule in rules:
            for family in families:
                if _rule_decision(status, rule, family) is False:
                    return [
                        StepResult(
                            "firewall",
                            Status.FAIL,
                            f"an existing IPv{family} rule blocks or limits {rule}; "
                            "no changes made. Review the rule order from a local console",
                        )
                    ]
    if not runner.dry_run:
        problem = _ordering_problem(runner, status, rules, families, active=enabled)
        if problem:
            return [
                StepResult(
                    "firewall",
                    Status.FAIL,
                    f"{problem}; no changes made. Check UFW from a local console",
                )
            ]

    plan = ["Plan (firewall):"]
    if runner.dry_run:
        plan.append("  - probe current SSH listen port(s): ss -tlnp, fallback sshd -T")
        plan.append("  - verify local IPv6 and UFW state before making changes")
        plan.append("  - allow the probed current SSH port(s)/tcp before enabling ufw")
        plan.append("  - allow 80/tcp and 443/tcp only if live managed Caddy routing is verified")
    else:
        ports = ", ".join(f"{p}/tcp" for p in current) or "none detected"
        plan.append(f"  - current SSH port(s): {ports}")
        family_label = "IPv4 and IPv6" if 6 in families else "IPv4 only (local IPv6 disabled)"
        plan.append(f"  - rule families: {family_label}")
        if auto_ingress:
            plan.append("  - managed Caddy verified: HTTP redirect 80/tcp, HTTPS 443/tcp")
        plan.append("  - existing ingress rules are retained even if Caddy is later removed")
    for label, command in rule_plan:
        plan.append(f"  - {label}" if command else f"  - {label} (already present, skip)")
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
    plan.append("  - enable ufw (already active, skip)" if enabled else "  - enable ufw --force")
    plan.append(
        f"  - order: {' + '.join(rules)} allowed before default deny incoming (anti-lockout)"
    )

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        for label, command in rule_plan:
            if command:
                runner.run(command)
                results.append(StepResult(label, Status.PLANNED))
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

    if enabled and not any(command for _, command in rule_plan):
        coverage = "IPv4 and IPv6" if 6 in families else "IPv4; local IPv6 disabled"
        return [
            StepResult(
                "firewall", Status.SKIPPED, f"rules and defaults already in place ({coverage})"
            )
        ]

    if not confirm_once(plan):
        return [StepResult("firewall", Status.ABORTED, "aborted; no changes made")]
    lock = locked_target(caddy.CADDYFILE.parent) if caddy_identity else nullcontext()
    try:
        # All cooperating writers take locks in SSH -> Caddy -> UFW order.
        with locked_target(ssh.SSHD_DROPIN), ExitStack() as held:
            if problem := _ssh_pending_problem():
                return [StepResult("firewall", Status.FAIL, f"{problem}; no changes made")]
            held.enter_context(lock)
            held.enter_context(locked_target(UFW_LOCK_TARGET))
            if caddy_identity and _caddy_ingress_identity(runner) != caddy_identity:
                return [
                    StepResult(
                        "firewall", Status.FAIL, "live managed Caddy changed; no changes made"
                    )
                ]
            current_under_lock = checks.current_ssh_ports(runner)
            if current_under_lock is None or set(current_under_lock) != set(current):
                return [
                    StepResult(
                        "firewall", Status.FAIL, "SSH listener ports changed; no changes made"
                    )
                ]
            if (
                settings is None
                or firewall_ufw.settings(runner) != settings
                or _local_ipv6_capability() != ("enabled" if 6 in families else "disabled")
                or (not enabled and _first_enable_problem(runner, settings))
                or _ordering_problem(runner, status, rules, families, active=enabled)
            ):
                return [
                    StepResult("firewall", Status.FAIL, "UFW evidence changed; no changes made")
                ]
            return _apply_confirmed(runner, rule_plan, rules, families, enabled=enabled)
    except OSError as exc:
        return [
            StepResult("firewall", Status.FAIL, f"SSH, Caddy, or firewall lock unavailable: {exc}")
        ]


def _apply_confirmed(
    runner: Runner,
    rule_plan: list[tuple[str, list[str] | None]],
    rules: list[str],
    families: Sequence[Family],
    *,
    enabled: bool,
) -> list[StepResult]:
    results = []
    try:
        for label, command in rule_plan:
            if command:
                runner.run(command)
                results.append(StepResult(label, Status.CHANGED))
            else:
                results.append(StepResult(label, Status.SKIPPED, "already present"))
        if not enabled and any(
            firewall_ufw.saved_coverage(runner, family, rules, fresh=False) != set(rules)
            for family in families
        ):
            results.append(
                StepResult(
                    "firewall", Status.FAIL, "staged SSH/rule ordering unverified; UFW not enabled"
                )
            )
            return results
        if not enabled:
            runner.run(["ufw", "default", "deny", "incoming"])
            results.append(StepResult("default deny incoming", Status.CHANGED))
            runner.run(["ufw", "default", "allow", "outgoing"])
            results.append(StepResult("default allow outgoing", Status.CHANGED))
            runner.run(["ufw", "--force", "enable"])
            results.append(StepResult("enable ufw", Status.CHANGED))
        else:
            results.append(StepResult("default deny incoming", Status.SKIPPED, "already set"))
            results.append(StepResult("default allow outgoing", Status.SKIPPED, "already set"))
            results.append(StepResult("enable ufw", Status.SKIPPED, "already active"))
    except (CommandError, OSError) as exc:
        results.append(StepResult("firewall", Status.FAIL, str(exc)))
        print("lhm: check UFW and SSH from a local console before attempting recovery", flush=True)
        return results

    results.append(_verify(runner, rules, families))
    return results


def _verify(runner: Runner, rules: list[str], families: Sequence[Family]) -> StepResult:
    status = _ufw_status(runner)
    if status is None:
        return StepResult("verify", Status.FAIL, "ufw status unavailable")
    problems: list[str] = []
    if not status.active:
        problems.append("ufw not active")
    if status.default_incoming != "deny":
        problems.append(f"default incoming {status.default_incoming or 'unknown'}")
    if status.default_outgoing != "allow":
        problems.append(f"default outgoing {status.default_outgoing or 'unknown'}")
    settings = firewall_ufw.settings(runner)
    if settings is None or not settings.enabled or settings.ipv6 != (6 in families):
        problems.append("effective UFW configuration unverified")
    for rule in rules:
        for family in families:
            if not _rule_present(status, rule, family):
                problems.append(f"{rule} not allowed on IPv{family}")
    for family in families:
        if firewall_ufw.runtime_coverage(runner, family, rules, active=True) != set(rules):
            problems.append(f"IPv{family} runtime rules or policy unverified")
    if problems:
        return StepResult("verify", Status.FAIL, "; ".join(problems))
    coverage = "IPv4 and IPv6" if 6 in families else "IPv4; local IPv6 disabled"
    return StepResult(
        "verify", Status.OK, f"active, default deny incoming, rules present ({coverage})"
    )


def inspect(runner: Runner) -> dict[str, object]:
    status = _ufw_status(runner)
    ipv6 = _local_ipv6_capability()
    settings = firewall_ufw.settings(runner) if status is not None and status.active else None
    families: tuple[Family, ...] = (4, 6) if ipv6 == "enabled" else (4,)
    live = (
        {
            family: firewall_ufw.runtime_coverage(runner, family, [SSH_RULE], active=True)
            for family in families
        }
        if ipv6 != "unknown" and settings and settings.enabled and settings.ipv6 == (6 in families)
        else {}
    )
    return {
        "available": status is not None,
        "active": None if status is None else status.active,
        "default_incoming": "" if status is None else status.default_incoming,
        "default_outgoing": "" if status is None else status.default_outgoing,
        "ipv6": ipv6,
        "ipv6_managed": (
            False
            if settings and not settings.ipv6 and ipv6 == "enabled"
            else True
            if live.get(6) is not None
            else None
        ),
        "ssh_allowed": all(
            live.get(family) == {SSH_RULE} and _rule_present(status, SSH_RULE, family)
            for family in families
        ),
    }


class FirewallModule:
    name = "firewall"
    description = "ufw: allow 22345/tcp first, then default deny incoming"
    implemented = True

    def apply(self, runner: Runner, *, allow: Sequence[str] = ()) -> list[StepResult]:
        return apply_firewall(runner, allow=allow)
