"""argparse assembly and exit codes for the ``lhm`` CLI."""

import argparse
import json
import logging
import os
import platform
import socket
import sys
from contextlib import nullcontext, redirect_stdout
from pathlib import Path
from typing import Any, Callable

from lhm.core import checks, colors
from lhm.core.backup import backup_file, newest_backup, rollback_file
from lhm.core.colors import Color
from lhm.core.confirm import confirm_once, is_root
from lhm.core.distro import DistroError
from lhm.core.files import locked_target
from lhm.core.mutations import mutation_mode, mutations_allowed
from lhm.core.report import RowColor, Status, StepResult, print_json, print_steps, print_table
from lhm.core.runner import CommandError, Runner
from lhm.modules import APPLY_ALL_ORDER, MODULES, resolve, ssh_watchdog
from lhm.modules import alert as alert_module
from lhm.modules import audit as audit_module
from lhm.modules import backup as backup_module
from lhm.modules import fail2ban as fail2ban_module
from lhm.modules import firewall as firewall_module
from lhm.modules import logging as logging_module
from lhm.modules import sandbox as sandbox_module
from lhm.modules import services as services_module
from lhm.modules import ssh as ssh_module
from lhm.modules import sysctl as sysctl_module
from lhm.modules import updates as updates_module

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
# Nothing was applied because the user (or a non-TTY stdin) refused the
# confirmation. Distinct from 0 (automation must not read "hardened") and from
# 1 (nothing failed; there is nothing to roll back).
EXIT_ABORT = 3

_SSH_CONFIRM_HINT = "Run only after an independent, non-multiplexed SSH key login."

QueryTable = tuple[list[str], list[list[str]], dict[str, Any], list[RowColor]]

QUERY_TARGETS = (
    "system",
    "ssh",
    "firewall",
    "fail2ban",
    "services",
    "ports",
    "sysctl",
    "audit",
    "updates",
    "all",
)


def _add_global_flags(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else False
    parser.add_argument(
        "--dry-run", action="store_true", default=default, help="plan only, no writes or commands"
    )
    parser.add_argument(
        "--json", action="store_true", default=default, help="machine-readable output"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=default,
        help="log every command and show full change content",
    )
    parser.add_argument(
        "--color",
        choices=colors.MODES,
        default=argparse.SUPPRESS if suppress else "auto",
        help="colorize output: auto (TTY only), always, never (NO_COLOR=1 disables auto)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lhm", description="Linux hardening and management")
    _add_global_flags(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    query = commands.add_parser("query", help="inspect current system state (unprivileged)")
    query_targets = query.add_subparsers(dest="target", required=True)
    for target in QUERY_TARGETS:
        leaf = query_targets.add_parser(target)
        _add_global_flags(leaf, suppress=True)

    check_parser = commands.add_parser("check", help="idempotency audit: OK / needs-change")
    _add_global_flags(check_parser, suppress=True)

    rollback = commands.add_parser(
        "rollback", help="restore a backup of an lhm-managed system file"
    )
    rollback.add_argument("file")
    _add_global_flags(rollback, suppress=True)

    ssh_confirm = commands.add_parser(
        "ssh-confirm",
        help="confirm an SSH watchdog transaction (root only)",
        description=_SSH_CONFIRM_HINT,
    )
    ssh_confirm.add_argument("txid", metavar="ID", help="SSH watchdog transaction ID")
    _add_global_flags(ssh_confirm, suppress=True)

    apply_parser = commands.add_parser("apply", help="apply one module or all of them")
    apply_targets = apply_parser.add_subparsers(dest="module", required=True)
    for module in MODULES:
        if module.name == "ssh":
            user_leaf = apply_targets.add_parser(
                "ssh-user", help="create admin user and install its authorized key"
            )
            _add_global_flags(user_leaf, suppress=True)
            user_leaf.add_argument("user", help="account name to create or update")
            user_leaf.add_argument("--key", required=True, help="public key file to install")
            user_leaf.add_argument(
                "--sudo", action="store_true", help="add the user to the sudo group"
            )
            hardening_leaf = apply_targets.add_parser(
                "ssh-hardening", help="write the sshd drop-in and reload sshd"
            )
            _add_global_flags(hardening_leaf, suppress=True)
            hardening_leaf.add_argument(
                "--port", type=int, default=ssh_module.DEFAULT_PORT, help="SSH port (default 22345)"
            )
            hardening_leaf.add_argument(
                "--allow-user",
                action="append",
                default=[],
                help="add a user to the lhm-managed SSH allowlist (repeatable)",
            )
            continue
        apply_name = "cleanup-services" if module.name == "services" else module.name
        leaf = apply_targets.add_parser(apply_name, help=module.description)
        _add_global_flags(leaf, suppress=True)
        if module.name == "updates":
            leaf.add_argument(
                "--security-only",
                action="store_true",
                help="apply security upgrades only (unattended-upgrade)",
            )
        elif module.name == "firewall":
            leaf.add_argument(
                "--allow",
                action="append",
                default=[],
                metavar="PORT/PROTO",
                help="extra inbound rule (repeatable); 22345/tcp is always allowed first",
            )
        elif module.name == "fail2ban":
            leaf.add_argument("--bantime", default=fail2ban_module.SSHD_BANTIME)
            leaf.add_argument("--findtime", default="30m")
            leaf.add_argument("--maxretry", default="3")
            leaf.add_argument(
                "--caddy",
                action="store_true",
                help="also enable the caddy jail and install the caddy-lhm filter",
            )
            leaf.add_argument(
                "--caddy-maxretry",
                default=fail2ban_module.CADDY_MAXRETRY,
                help="caddy jail maxretry (default 5)",
            )
        elif module.name == "sandbox":
            leaf.add_argument(
                "services",
                nargs="*",
                metavar="SERVICE",
                help="whitelist subset (ssh, nginx, fail2ban); default: all of them",
            )
        elif module.name == "alert":
            leaf.add_argument(
                "--webhook",
                required=True,
                metavar="URL",
                help="https:// webhook that receives alerts",
            )
        elif module.name == "backup":
            leaf.add_argument(
                "--target", required=True, metavar="PATH", help="absolute backup directory"
            )
            leaf.add_argument(
                "--keep", type=int, default=backup_module.DEFAULT_KEEP, help="archives to keep"
            )
    all_parser = apply_targets.add_parser(
        "all",
        help=(
            "apply every non-interactive module in DESIGN.md order "
            "(updates, ssh, firewall, fail2ban, sysctl, sandbox, logging, audit, "
            "alert, backup); cleanup-services is excluded because it is interactive; "
            "ssh is skipped unless --ssh-user and --key are given"
        ),
    )
    _add_global_flags(all_parser, suppress=True)
    all_parser.add_argument("--ssh-user", default="", metavar="NAME", help="admin account")
    all_parser.add_argument("--key", default="", metavar="FILE", help="public key file")
    all_parser.add_argument("--sudo", action="store_true", help="add the SSH user to sudo")
    all_parser.add_argument(
        "--security-only", action="store_true", help="apply security upgrades only"
    )
    all_parser.add_argument(
        "--allow", action="append", default=[], metavar="PORT/PROTO", help="extra ufw rule"
    )
    all_parser.add_argument("--bantime", default=fail2ban_module.SSHD_BANTIME)
    all_parser.add_argument("--findtime", default="30m")
    all_parser.add_argument("--maxretry", default="3")
    all_parser.add_argument(
        "--caddy",
        action="store_true",
        help="also enable the caddy jail and install the caddy-lhm filter",
    )
    all_parser.add_argument("--caddy-maxretry", default=fail2ban_module.CADDY_MAXRETRY)
    all_parser.add_argument(
        "--webhook",
        default="",
        metavar="URL",
        help="https:// URL for the alert timer (required for apply all)",
    )
    all_parser.add_argument(
        "--target",
        default="",
        metavar="PATH",
        help="backup directory (required for apply all)",
    )
    all_parser.add_argument(
        "--keep", type=int, default=backup_module.DEFAULT_KEEP, help="backup archives to keep"
    )
    return parser


def _flag(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _judge(ok: bool | None) -> Color:
    """Green when the target is met, red when it is not, yellow when unprobeable."""
    if ok is None:
        return Color.YELLOW
    return Color.GREEN if ok else Color.RED


# sshd setting -> callable deciding whether the effective value meets the target.
SSHD_TARGETS: dict[str, Callable[[str], bool | None]] = {
    "port": lambda value: value == "22345",
    "permitrootlogin": lambda value: value == "no",
    "passwordauthentication": lambda value: value == "no",
    "kbdinteractiveauthentication": lambda value: value == "no",
    "pubkeyauthentication": lambda value: value == "yes",
    "x11forwarding": lambda value: value == "no",
    "maxauthtries": lambda value: value.isdigit() and int(value) <= 3,
}

# Judged sysctl keys and their targets: every key the module's template sets.
def _sysctl_targets() -> dict[str, str]:
    targets: dict[str, str] = {}
    for line in sysctl_module.desired_conf().splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.lstrip().startswith("#"):
            targets[key.strip()] = value.strip()
    return targets


SYSCTL_TARGETS = _sysctl_targets()


def _query_system() -> QueryTable:
    release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                release[key] = value.strip().strip('"')
    except OSError:
        pass
    info = {
        "hostname": socket.gethostname(),
        "distro": release.get("PRETTY_NAME", "unknown"),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
        "root": is_root(),
    }
    rows = [[key, str(value)] for key, value in info.items()]
    return ["key", "value"], rows, info, []


def _query_ssh(runner: Runner) -> QueryTable:
    state = ssh_module.inspect(runner)
    config = checks.sshd_effective_config(runner)
    keys = (
        "port",
        "permitrootlogin",
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "pubkeyauthentication",
        "x11forwarding",
        "maxauthtries",
    )
    dropin_color: RowColor = [
        None,
        Color.GREEN if state["dropin_current"] else Color.RED,
    ]
    names, unlisted = state["authorized_users"], state["unlisted_key_holders"]
    user_fields = {"authorized_users": names, "unlisted_key_holders": unlisted}
    if names is None:
        dropin_status, names_text, unlisted_text = "unknown", "unknown", "unknown"
    else:
        dropin_status = "current" if state["dropin_current"] else "differs"
        if not state["dropin_present"]:
            dropin_status = "missing"
        names_text = " ".join(names) or "-"
        unlisted_text = "not probed" if unlisted is None else " ".join(unlisted) or "-"
    user_rows = [
        ["lhm-managed authorized users", names_text],
        ["unlisted key holders", unlisted_text],
    ]
    if not config:
        # sshd -T reads every included file and fails without root when any of
        # them is root-only (e.g. 50-cloud-init.conf). Distinguish "cannot
        # probe" from "not configured" instead of silently printing unavailable.
        payload: dict[str, Any] = {
            "available": False,
            "note": "sshd -T failed (try: sudo lhm query ssh)",
            **user_fields,
        }
        rows = [[key, "unavailable (needs root)"] for key in keys]
        row_colors: list[RowColor] = [[None, Color.YELLOW] for _ in keys]
        rows.append(["99-lhm drop-in", dropin_status])
        row_colors.append(dropin_color)
        rows.extend(user_rows)
        row_colors.extend([None, None])
        rows.append(["hint", "run: sudo lhm query ssh"])
        row_colors.append(None)
        return ["setting", "effective value"], rows, payload, row_colors
    payload = {key: config.get(key, "unavailable") for key in keys}
    payload["dropin"] = state["dropin"]
    payload["dropin_current"] = state["dropin_current"]
    payload.update(user_fields)
    rows = [[key, payload[key]] for key in keys]
    row_colors = []
    for key in keys:
        value = payload[key]
        ok = None if value == "unavailable" else SSHD_TARGETS[key](value)
        row_colors.append([None, _judge(ok)])
    rows.append(["99-lhm drop-in", dropin_status])
    row_colors.append(dropin_color)
    rows.extend(user_rows)
    row_colors.extend([None, None])
    return ["setting", "effective value"], rows, payload, row_colors


def _query_firewall(
    runner: Runner,
) -> QueryTable:
    status = checks.ufw_status(runner)
    if status is None:
        payload: dict[str, Any] = {"available": False, "note": "not configured by lhm"}
        return ["key", "value"], [["status", "unavailable"]], payload, [[None, Color.YELLOW]]
    payload = {
        "available": True,
        "active": status.active,
        "default_incoming": status.default_incoming,
        "default_outgoing": status.default_outgoing,
        "rules": [[rule.to, rule.action, rule.source] for rule in status.rules],
    }
    rows = [
        ["active", str(status.active)],
        ["default incoming", status.default_incoming or "-"],
        ["default outgoing", status.default_outgoing or "-"],
    ]
    row_colors: list[RowColor] = [
        [None, Color.GREEN if status.active else Color.RED],
        [None, Color.GREEN if status.default_incoming == "deny" else Color.RED],
        None,
    ]
    for rule in status.rules:
        rows.append([f"rule {rule.to}", f"{rule.action} from {rule.source or 'anywhere'}"])
        row_colors.append(None)
    return ["key", "value"], rows, payload, row_colors


def _query_fail2ban(runner: Runner) -> QueryTable:
    state = fail2ban_module.inspect(runner)
    installed = state["installed"]
    caddy_enabled = state["caddy_enabled"]
    payload: dict[str, Any] = {
        "installed": installed,
        "active": state["active"],
        "jail_dropin": state["jail_dropin"],
        "jail_current": state["jail_current"],
        "caddy_filter": state["caddy_filter"],
        "caddy_filter_present": state["caddy_filter_present"],
        "caddy_enabled": caddy_enabled,
        "legacy_jail_local": state["legacy_jail_local"],
        "legacy_jail_local_present": state["legacy_jail_local_present"],
        "dbfile": state["dbfile"],
        "dbfile_present": state["dbfile_present"],
    }
    rows: list[list[str]] = [
        ["package installed", _flag(installed)],
        ["service active", _flag(bool(state["active"]))],
        [
            "99-lhm.local drop-in",
            "current" if state["jail_current"] else "missing or differs",
        ],
        ["dbfile present", _flag(bool(state["dbfile_present"]))],
    ]
    row_colors: list[RowColor] = [
        [None, _judge(None if installed is None else bool(installed))],
        [None, _judge(bool(state["active"]))],
        [None, Color.GREEN if state["jail_current"] else Color.RED],
        # bantime.increment silently does nothing without a dbfile.
        [None, _judge(bool(state["dbfile_present"]))],
    ]

    sshd_targets = (
        ("bantime", "14400"),
        ("maxretry", "3"),
        ("findtime", "1800"),
    )
    for key, want in sshd_targets:
        value = fail2ban_module.jail_setting(runner, "sshd", key)
        rows.append([f"sshd {key}", value if value is not None else "unavailable"])
        row_colors.append([None, _judge(None if value is None else value == want)])
        payload[f"sshd_{key}"] = value

    increment = fail2ban_module.jail_increment_active(runner, "sshd")
    rows.append(["sshd bantime.increment", _flag(increment)])
    row_colors.append([None, _judge(increment)])
    payload["sshd_bantime_increment"] = increment

    if caddy_enabled is None:
        rows.append(["caddy jail", "not configured"])
        row_colors.append(None)
    else:
        rows.append(["caddy jail enabled", _flag(caddy_enabled)])
        row_colors.append([None, Color.GREEN if caddy_enabled else None])
        if caddy_enabled:
            filter_ok = bool(state["caddy_filter_present"])
            rows.append(["caddy-lhm filter", "present" if filter_ok else "missing"])
            row_colors.append([None, _judge(filter_ok)])
            caddy_status = runner.run(["fail2ban-client", "status", "caddy"], check=False)
            caddy_live = caddy_status.ok and "caddy" in caddy_status.stdout
            rows.append(["caddy jail live", _flag(caddy_live)])
            row_colors.append([None, _judge(caddy_live)])
    if state["legacy_jail_local_present"]:
        rows.append(["legacy jail.local", "present (preserved, overridden by the drop-in)"])
        row_colors.append(None)
    return ["key", "value"], rows, payload, row_colors


def _query_services(
    runner: Runner,
) -> QueryTable:
    states = [checks.probe_service(runner, name) for name in checks.SERVICES]
    listing = services_module.inspect(runner)
    essential = [
        {"name": s.name, "active": s.active, "enabled": s.enabled, "installed": s.installed}
        for s in states
    ]
    rows = [
        [s.name, _flag(s.active), _flag(s.enabled), "yes" if s.installed else "no"]
        for s in states
    ]
    for item in listing["candidates"]:
        rows.append([item["unit"], "review", "-", item["package"]])
    payload: dict[str, Any] = {
        "essential": essential,
        "cleanup_candidates": listing["candidates"],
    }
    return ["service", "active", "enabled", "present"], rows, payload, []


def _query_ports(runner: Runner) -> QueryTable:
    records = checks.listening_ports(runner)
    payload = [
        {
            "proto": r.proto,
            "address": r.address,
            "port": r.port,
            "state": r.state,
            "process": r.process,
        }
        for r in records
    ]
    rows = [[r.proto, r.address, str(r.port or ""), r.state, r.process or "-"] for r in records]
    return ["proto", "address", "port", "state", "process"], rows, payload, []


def _query_sysctl() -> QueryTable:
    payload = {key: checks.sysctl_value(key) for key in checks.SYSCTL_KEYS}
    rows = [[key, value if value is not None else "unavailable"] for key, value in payload.items()]
    row_colors: list[RowColor] = []
    for key, value in payload.items():
        want = SYSCTL_TARGETS.get(key)
        if want is None:
            row_colors.append(None)
            continue
        row_colors.append([None, _judge(None if value is None else value == want)])
    spot = sysctl_module.inspect()
    rows.append(["99-lhm drop-in", "current" if spot["dropin_current"] else "differs"])
    row_colors.append([None, Color.GREEN if spot["dropin_current"] else Color.RED])
    payload["dropin_current"] = spot["dropin_current"]
    return ["key", "value"], rows, payload, row_colors


def _query_audit(runner: Runner) -> QueryTable:
    state = audit_module.inspect(runner)
    payload = {
        "auditd_active": state["active"],
        "installed": state["installed"],
        "lhm_rules": state["rules_current"],
        "immutable": state["immutable"],
        "auditctl_status": state["auditctl_status"],
    }
    rows = [
        ["auditd active", _flag(bool(state["active"]))],
        ["auditd installed", _flag(state["installed"])],
        ["99-lhm rules current", "yes" if state["rules_current"] else "no"],
        ["rules immutable (-e 2)", _flag(bool(state["immutable"]))],
    ]
    row_colors: list[RowColor] = [
        [None, _judge(None if state["active"] is None else bool(state["active"]))],
        [None, _judge(None if state["installed"] is None else bool(state["installed"]))],
        [None, _judge(bool(state["rules_current"]))],
        None,
    ]
    for line in str(state["auditctl_status"]).splitlines():
        key, _, value = line.partition(" ")
        rows.append([f"auditctl {key}", value.strip() or "-"])
        row_colors.append(None)
    if not state["auditctl_status"]:
        rows.append(["auditctl -s", "unavailable"])
        row_colors.append([None, Color.YELLOW])
    return ["key", "value"], rows, payload, row_colors


def _query_updates(
    runner: Runner,
) -> QueryTable:
    try:
        payload = updates_module.inspect(runner)
    except DistroError as exc:
        payload = {"package": updates_module.PACKAGE, "installed": None, "error": str(exc)}
        return (
            ["key", "value"],
            [["status", "unavailable"], ["reason", str(exc)]],
            payload,
            [[None, Color.YELLOW], None],
        )
    active = checks.probe_service(runner, updates_module.PACKAGE).active
    installed = payload["installed"]
    conf_current = bool(payload["apt_conf_current"])
    rows = [
        ["unattended-upgrades installed", _flag(installed)],
        ["unattended-upgrades active", _flag(active)],
        ["51-lhm current", "yes" if conf_current else "no"],
        ["51-lhm path", str(payload["apt_conf"])],
    ]
    row_colors: list[RowColor] = [
        [None, _judge(None if installed is None else bool(installed))],
        [None, _judge(active)],
        [None, Color.GREEN if conf_current else Color.RED],
        None,
    ]
    return ["key", "value"], rows, payload, row_colors


def _handle_query(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    builders: dict[
        str, Callable[[], QueryTable]
    ] = {
        "system": _query_system,
        "ssh": lambda: _query_ssh(runner),
        "firewall": lambda: _query_firewall(runner),
        "fail2ban": lambda: _query_fail2ban(runner),
        "services": lambda: _query_services(runner),
        "ports": lambda: _query_ports(runner),
        "sysctl": _query_sysctl,
        "audit": lambda: _query_audit(runner),
        "updates": lambda: _query_updates(runner),
    }
    if args.target == "all":
        return _query_all(runner, builders, as_json)
    headers, rows, payload, row_colors = builders[args.target]()
    print_table(headers, rows, as_json=as_json, payload=payload, row_colors=row_colors)
    return EXIT_OK


def _query_all(
    runner: Runner,
    builders: dict[
        str, Callable[[], QueryTable]
    ],
    as_json: bool,
) -> int:
    """Print every query section in order, separated by == name == headers."""
    sections: dict[str, object] = {}
    if as_json:
        for name, build in builders.items():
            _headers, _rows, payload, _row_colors = build()
            sections[name] = payload
        print(json.dumps(sections, indent=2, sort_keys=True))
        return EXIT_OK
    first = True
    for name, build in builders.items():
        if not first:
            print()
        first = False
        print(f"== {name} ==")
        headers, rows, payload, row_colors = build()
        print_table(headers, rows, as_json=False, row_colors=row_colors)
    return EXIT_OK


def _check_updates(runner: Runner) -> tuple[bool, str]:
    try:
        state = updates_module.inspect(runner)
    except DistroError as exc:
        return False, f"cannot probe: {exc}"
    problems = []
    if not state["installed"]:
        problems.append("package missing")
    if not state["apt_conf_current"]:
        problems.append("51-lhm content differs")
    return not problems, ", ".join(problems) if problems else "security-only unattended upgrades"


def _check_ssh(runner: Runner) -> tuple[bool, str]:
    state = ssh_module.inspect(runner)
    problems = []
    names = state["authorized_users"]
    unverified = state["unverified_managed_keys"]
    if names is None:
        problems.append("99-lhm drop-in unreadable or unrecognized")
    else:
        if not names:
            problems.append("no lhm-managed authorized users")
        elif unverified is None:
            problems.append("managed SSH keys not probed")
        elif unverified:
            problems.append("unverified managed SSH keys: " + ", ".join(unverified))
        if not state["dropin_present"]:
            problems.append("99-lhm drop-in missing")
        elif not state["dropin_current"]:
            problems.append("99-lhm drop-in differs")
    effective = state["effective"]
    if effective["port"] != str(ssh_module.DEFAULT_PORT):
        problems.append(f"effective port {effective['port']}")
    if effective["permitrootlogin"] != "no":
        problems.append(f"permitrootlogin {effective['permitrootlogin']}")
    if effective["passwordauthentication"] != "no":
        problems.append(f"passwordauthentication {effective['passwordauthentication']}")
    return not problems, ", ".join(problems) if problems else "key-only ssh on port 22345"


def _check_firewall(runner: Runner) -> tuple[bool, str]:
    state = firewall_module.inspect(runner)
    problems = []
    if not state["available"]:
        problems.append("ufw unavailable")
    if not state["active"]:
        problems.append("ufw inactive")
    if state["default_incoming"] != "deny":
        problems.append(f"default incoming {state['default_incoming'] or 'unknown'}")
    if not state["ssh_allowed"]:
        problems.append(f"{firewall_module.SSH_RULE} not allowed")
    return not problems, ", ".join(problems) if problems else "active, deny incoming, ssh allowed"


def _check_fail2ban(runner: Runner) -> tuple[bool, str]:
    state = fail2ban_module.inspect(runner)
    problems = []
    if not state["installed"]:
        problems.append("package missing")
    if not state["jail_current"]:
        problems.append("jail.d/99-lhm.local missing or differs")
    if state["caddy_enabled"] and not state["caddy_filter_present"]:
        problems.append("caddy jail enabled but filter.d/caddy-lhm.conf missing")
    if state["installed"] and not state["dbfile_present"]:
        # bantime.increment is silently inert without a dbfile.
        problems.append(f"no dbfile at {state['dbfile']} (bantime.increment inert)")
    if not state["active"]:
        problems.append("fail2ban not active")
    return not problems, ", ".join(problems) if problems else "sshd jail configured and active"


def _check_sysctl() -> tuple[bool, str]:
    state = sysctl_module.inspect()
    problems = []
    if not state["dropin_current"]:
        problems.append("99-lhm.conf missing or differs")
    for key, spec in state["spot_checks"].items():
        if spec["current"] != spec["want"]:
            problems.append(f"{key}={spec['current'] or 'unavailable'}")
    return not problems, ", ".join(problems) if problems else "drop-in current, spot checks match"


def _check_sandbox() -> tuple[bool, str]:
    state = sandbox_module.inspect()
    problems = [service for service, spec in state.items() if not spec["current"]]
    if len(problems) == len(state):
        return False, "no sandbox drop-ins present"
    return not problems, (
        "sandbox drop-ins current"
        if not problems
        else "differs: " + ", ".join(problems)
    )


def _check_logging() -> tuple[bool, str]:
    state = logging_module.inspect()
    problems = []
    if not state["journald_current"]:
        problems.append("journald drop-in missing or differs")
    if not state["journal_persistent"]:
        problems.append("/var/log/journal missing")
    if not state["logrotate_current"]:
        problems.append("logrotate config missing or differs")
    return not problems, ", ".join(problems) if problems else "persistent journal, logrotate set"


def _check_audit(runner: Runner) -> tuple[bool, str]:
    state = audit_module.inspect(runner)
    problems = []
    if not state["installed"]:
        problems.append("package missing")
    if not state["active"]:
        problems.append("auditd not active")
    if not state["rules_current"]:
        problems.append("99-lhm.rules missing or differs")
    return not problems, ", ".join(problems) if problems else "auditd active, rules current"


def _check_alert(runner: Runner) -> tuple[bool, str]:
    state = alert_module.inspect(runner)
    problems = []
    if not state["script_present"]:
        problems.append("alert script missing")
    if not (state["timer_present"] and state["service_present"]):
        problems.append("systemd units missing")
    if not state["active"]:
        problems.append("timer not active")
    return not problems, ", ".join(problems) if problems else "alert timer active"


def _check_backup(runner: Runner) -> tuple[bool, str]:
    state = backup_module.inspect(runner)
    problems = []
    if not state["script_present"]:
        problems.append("backup script missing")
    if not (state["timer_present"] and state["service_present"]):
        problems.append("systemd units missing")
    if not state["active"]:
        problems.append("timer not active")
    return not problems, ", ".join(problems) if problems else "backup timer active"


CHECKERS = {
    "updates": _check_updates,
    "ssh": _check_ssh,
    "firewall": _check_firewall,
    "fail2ban": _check_fail2ban,
    "sysctl": lambda _runner: _check_sysctl(),
    "sandbox": lambda _runner: _check_sandbox(),
    "logging": lambda _runner: _check_logging(),
    "audit": _check_audit,
    "alert": _check_alert,
    "backup": _check_backup,
}


def _handle_check(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    rows = []
    row_colors: list[RowColor] = []
    for module in MODULES:
        checker = CHECKERS.get(module.name)
        if checker is None:
            if module.name == "services":
                rows.append([module.name, "manual", "interactive: apply cleanup-services"])
                row_colors.append(None)
            else:
                rows.append([module.name, "UNKNOWN", "not implemented"])
                row_colors.append([None, Color.YELLOW])
            continue
        ok, detail = checker(runner)
        rows.append([module.name, "OK" if ok else "needs-change", detail])
        row_colors.append([None, Color.GREEN if ok else Color.RED])
    if as_json:
        print_json([{"area": a, "state": s, "detail": d} for a, s, d in rows])
    else:
        print_table(["area", "state", "detail"], rows, row_colors=row_colors)
    return EXIT_OK


def _managed_rollback_path(value: str) -> Path:
    path = Path(value)
    managed = {
        alert_module.SCRIPT,
        alert_module.SERVICE_UNIT,
        alert_module.TIMER_UNIT,
        audit_module.RULES_DROPIN,
        backup_module.SCRIPT,
        backup_module.SERVICE_UNIT,
        backup_module.TIMER_UNIT,
        fail2ban_module.JAIL_DROPIN,
        fail2ban_module.CADDY_FILTER,
        logging_module.JOURNALD_DROPIN,
        logging_module.LOGROTATE_CONF,
        ssh_module.SSHD_DROPIN,
        sysctl_module.SYSCTL_DROPIN,
        updates_module.APT_CONF,
        *(sandbox_module.dropin_path(name) for name in sandbox_module.WHITELIST),
    }
    if path not in managed or value != str(path):
        raise ValueError("rollback accepts only exact lhm-managed system paths")
    if path.resolve(strict=False) != path or any(
        part.is_symlink() for part in (path, *path.parents)
    ):
        raise ValueError(f"refusing a symlink in rollback path: {path}")
    return path


def _handle_rollback(args: argparse.Namespace, runner: Runner) -> int:
    try:
        path = _managed_rollback_path(args.file)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"lhm: rollback usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if runner.dry_run:
        print(f"would restore newest backup of {path}")
        return EXIT_OK
    if not is_root():
        print("lhm: rollback requires root (refusing)", file=sys.stderr)
        return EXIT_FAIL
    try:
        backup = newest_backup(path)
    except ValueError as exc:
        print(f"lhm: rollback usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if backup is None:
        print(f"lhm: rollback failed: no backup found for {path}", file=sys.stderr)
        return EXIT_FAIL
    plan = [
        f"Plan (rollback): restore {path} from {backup}",
        f"  - back up the current {path} first (so this rollback can itself be undone)",
        "  - risk: unsaved/target state is overwritten",
    ]
    # Restoring a file is not idempotent: require confirmation as for apply.
    if not confirm_once(plan):
        return EXIT_ABORT
    try:
        _managed_rollback_path(args.file)
        with locked_target(path):
            if path == ssh_module.SSHD_DROPIN:
                try:
                    pending = ssh_watchdog.current()
                except (ssh_watchdog.WatchdogError, OSError) as exc:
                    print(
                        f"lhm: rollback failed: unreadable SSH watchdog state: {exc}",
                        file=sys.stderr,
                    )
                    return EXIT_FAIL
                if pending is not None:
                    print(
                        "lhm: rollback refused: an SSH watchdog transaction exists",
                        file=sys.stderr,
                    )
                    return EXIT_FAIL
            if newest_backup(path) != backup:
                print("lhm: rollback backup changed; re-run to review it", file=sys.stderr)
                return EXIT_FAIL
            if path.exists() or path.is_symlink():
                backup_file(path)
            used = rollback_file(path, backup=backup)
    except ValueError as exc:
        print(f"lhm: rollback usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (FileNotFoundError, OSError) as exc:
        print(f"lhm: rollback failed: {exc}", file=sys.stderr)
        return EXIT_FAIL
    print(f"restored {path} from {used} (previous content backed up)")
    return EXIT_OK


def _handle_ssh_confirm(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    name = "ssh-confirm"
    action = f"disarm SSH watchdog transaction {args.txid!r}"
    if runner.dry_run:
        results = [StepResult(name, Status.PLANNED, f"Would {action}. {_SSH_CONFIRM_HINT}")]
    elif not is_root():
        results = [StepResult(name, Status.FAIL, "ssh-confirm requires root")]
    else:
        plan = [f"Plan (ssh-confirm): {action}", f"  - {_SSH_CONFIRM_HINT}"]
        with redirect_stdout(sys.stderr) if as_json else nullcontext():
            confirmed = confirm_once(plan, allow_bypass=False)
        if not confirmed:
            results = [StepResult(name, Status.ABORTED, "confirmation not granted")]
        else:
            try:
                results = ssh_module.confirm_watchdog(runner, args.txid)
            except (ssh_watchdog.WatchdogError, ssh_module.SshError, CommandError, OSError) as exc:
                results = [StepResult(name, Status.FAIL, str(exc))]
    print_steps(results, as_json=as_json)
    if any(result.status is Status.ABORTED for result in results):
        return EXIT_ABORT
    return EXIT_FAIL if any(result.status is Status.FAIL for result in results) else EXIT_OK


def _run_module(name: str, runner: Runner, as_json: bool, **options: Any) -> int:
    module = resolve(name)
    if module is None:
        print(f"lhm: unknown module: {name}", file=sys.stderr)
        return EXIT_USAGE
    if not module.implemented:
        print(f"lhm: module '{name}' not yet implemented", file=sys.stderr)
        return EXIT_USAGE
    if not runner.dry_run and not is_root():
        print("lhm: apply requires root (refusing; use --dry-run to plan)", file=sys.stderr)
        return EXIT_FAIL
    if runner.dry_run:
        print("dry-run: no changes will be made")
    results = module.apply(runner, **options)
    print_steps(results, as_json=as_json)
    if any(r.status is Status.ABORTED for r in results):
        return EXIT_ABORT
    return EXIT_FAIL if any(r.status is Status.FAIL for r in results) else EXIT_OK


def _apply_all_options(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    """Per-module options for ``apply all`` (DESIGN.md order, ssh conditional)."""
    options: dict[str, dict[str, Any]] = {
        "updates": {"security_only": bool(args.security_only)},
        "firewall": {"allow": list(args.allow)},
        "fail2ban": {
            "bantime": args.bantime,
            "findtime": args.findtime,
            "maxretry": args.maxretry,
            "caddy": bool(args.caddy),
            "caddy_maxretry": args.caddy_maxretry,
        },
        "alert": {"webhook": args.webhook},
        "backup": {"target": args.target, "keep": args.keep},
    }
    if args.ssh_user:
        options["ssh"] = {
            "command": "ssh-user",
            "user": args.ssh_user,
            "key": args.key,
            "sudo": bool(args.sudo),
        }
    return options


def _handle_apply_all(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    if not args.webhook or not args.target:
        print(
            "lhm: apply all needs --webhook URL and --target PATH "
            "(refusing to skip the alert/backup gates)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if bool(args.ssh_user) != bool(args.key):
        print(
            "lhm: --ssh-user and --key must be passed together (apply all)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    options = _apply_all_options(args)
    if not runner.dry_run and not is_root():
        print("lhm: apply requires root (refusing; use --dry-run to plan)", file=sys.stderr)
        return EXIT_FAIL
    if runner.dry_run:
        print("dry-run: no changes will be made")
    if "ssh" not in options:
        print(
            "lhm: ssh skipped: pass --ssh-user NAME --key FILE to include it "
            "(ssh-hardening is never run without a key)",
            file=sys.stderr,
        )
    for name in APPLY_ALL_ORDER:
        module = resolve(name)
        if module is None:
            print(f"lhm: unknown module: {name}", file=sys.stderr)
            return EXIT_USAGE
        if name == "ssh" and name not in options:
            continue
        print(f"== {name} ==", flush=True)
        results = module.apply(runner, **options.get(name, {}))
        print_steps(results, as_json=as_json)
        if any(result.status is Status.ABORTED for result in results):
            print(
                f"lhm: apply all aborted at '{name}' (nothing changed there; "
                "earlier modules were already applied); exit 3",
                file=sys.stderr,
            )
            return EXIT_ABORT
        if any(result.status is Status.FAIL for result in results):
            print(
                f"lhm: apply all stopped at '{name}' (FAIL); "
                "inspect the failed step and use 'lhm rollback FILE' where a path is named",
                file=sys.stderr,
            )
            return EXIT_FAIL
    return EXIT_OK


def _handle_apply(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    if args.module == "all":
        return _handle_apply_all(args, runner, as_json)
    options: dict[str, Any] = {}
    name = args.module
    if name == "ssh-user":
        options["command"] = "ssh-user"
        options["user"] = args.user
        options["key"] = args.key
        options["sudo"] = args.sudo
        name = "ssh"
    elif name == "ssh-hardening":
        options["command"] = "ssh-hardening"
        options["port"] = args.port
        options["allow_users"] = list(args.allow_user)
        name = "ssh"
    elif name == "cleanup-services":
        options["select"] = getattr(args, "select", "")
        name = "services"
    elif name == "updates":
        options["security_only"] = getattr(args, "security_only", False)
    elif name == "firewall":
        options["allow"] = list(args.allow)
    elif name == "fail2ban":
        options["bantime"] = args.bantime
        options["findtime"] = args.findtime
        options["maxretry"] = args.maxretry
        options["caddy"] = bool(args.caddy)
        options["caddy_maxretry"] = args.caddy_maxretry
    elif name == "sandbox":
        options["services"] = list(args.services)
    elif name == "alert":
        options["webhook"] = args.webhook
    elif name == "backup":
        options["target"] = args.target
        options["keep"] = args.keep
    return _run_module(name, runner, as_json, **options)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    as_json = bool(args.json)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # --json stays machine-readable: no command echo or change lines mixed in.
    colors.configure(
        getattr(args, "color", "auto"), verbose=bool(args.verbose), quiet=as_json
    )
    try:
        with mutation_mode(dry_run=bool(args.dry_run)):
            runner = Runner(dry_run=not mutations_allowed(), verbose=bool(args.verbose))
            if args.command == "query":
                return _handle_query(args, runner, as_json)
            if args.command == "check":
                return _handle_check(args, runner, as_json)
            if args.command == "rollback":
                return _handle_rollback(args, runner)
            if args.command == "ssh-confirm":
                return _handle_ssh_confirm(args, runner, as_json)
            return _handle_apply(args, runner, as_json)
    except NotImplementedError as exc:
        print(f"lhm: module '{exc}' not yet implemented", file=sys.stderr)
        return EXIT_USAGE
    except CommandError as exc:
        print(f"lhm: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except DistroError as exc:
        print(f"lhm: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except KeyboardInterrupt:
        print("lhm: interrupted", file=sys.stderr)
        return 130
