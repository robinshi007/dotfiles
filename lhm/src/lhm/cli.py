"""argparse assembly and exit codes for the ``lhm`` CLI."""

import argparse
import logging
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from lhm.core import checks
from lhm.core.backup import backup_file, newest_backup, rollback_file
from lhm.core.confirm import confirm_twice, is_root
from lhm.core.distro import DistroError
from lhm.core.report import Status, print_json, print_steps, print_table
from lhm.core.runner import CommandError, Runner
from lhm.modules import APPLY_ALL_ORDER, MODULES, resolve
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

QUERY_TARGETS = ("system", "ssh", "firewall", "services", "ports", "sysctl", "audit", "updates")


def _add_global_flags(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else False
    parser.add_argument(
        "--dry-run", action="store_true", default=default, help="plan only, no writes or commands"
    )
    parser.add_argument(
        "--json", action="store_true", default=default, help="machine-readable output"
    )
    parser.add_argument(
        "--verbose", action="store_true", default=default, help="log every command"
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

    rollback = commands.add_parser("rollback", help="restore the newest backup of FILE")
    rollback.add_argument("file")
    _add_global_flags(rollback, suppress=True)

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
                "--allow-user", action="append", default=[], help="allowed SSH user (repeatable)"
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
            leaf.add_argument("--bantime", default="1h")
            leaf.add_argument("--findtime", default="10m")
            leaf.add_argument("--maxretry", default="5")
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
    all_parser.add_argument("--bantime", default="1h")
    all_parser.add_argument("--findtime", default="10m")
    all_parser.add_argument("--maxretry", default="5")
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


def _query_system() -> tuple[list[str], list[list[str]], dict[str, Any]]:
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
    return ["key", "value"], rows, info


def _query_ssh(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
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
    if not config:
        # sshd -T reads every included file and fails without root when any of
        # them is root-only (e.g. 50-cloud-init.conf). Distinguish "cannot
        # probe" from "not configured" instead of silently printing unavailable.
        payload: dict[str, Any] = {
            "available": False,
            "note": "sshd -T failed (try: sudo lhm query ssh)",
        }
        rows = [[key, "unavailable (needs root)"] for key in keys]
        rows.append(["99-lhm drop-in", "current" if state["dropin_current"] else "differs"])
        rows.append(["authorized users", " ".join(state["authorized_users"]) or "-"])
        rows.append(["hint", "run: sudo lhm query ssh"])
        return ["setting", "effective value"], rows, payload
    payload = {key: config.get(key, "unavailable") for key in keys}
    payload["dropin"] = state["dropin"]
    payload["dropin_current"] = state["dropin_current"]
    payload["authorized_users"] = state["authorized_users"]
    rows = [[key, payload[key]] for key in keys]
    rows.append(["99-lhm drop-in", "current" if state["dropin_current"] else "differs"])
    rows.append(["authorized users", " ".join(state["authorized_users"]) or "-"])
    return ["setting", "effective value"], rows, payload


def _query_firewall(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
    status = checks.ufw_status(runner)
    if status is None:
        payload: dict[str, Any] = {"available": False, "note": "not configured by lhm"}
        return ["key", "value"], [["status", "unavailable"]], payload
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
    for rule in status.rules:
        rows.append([f"rule {rule.to}", f"{rule.action} from {rule.source or 'anywhere'}"])
    return ["key", "value"], rows, payload


def _query_services(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
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
    return ["service", "active", "enabled", "present"], rows, payload


def _query_ports(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
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
    return ["proto", "address", "port", "state", "process"], rows, payload


def _query_sysctl() -> tuple[list[str], list[list[str]], dict[str, Any]]:
    payload = {key: checks.sysctl_value(key) for key in checks.SYSCTL_KEYS}
    rows = [[key, value if value is not None else "unavailable"] for key, value in payload.items()]
    spot = sysctl_module.inspect()
    rows.append(["99-lhm drop-in", "current" if spot["dropin_current"] else "differs"])
    payload["dropin_current"] = spot["dropin_current"]
    return ["key", "value"], rows, payload


def _query_audit(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
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
    for line in str(state["auditctl_status"]).splitlines():
        key, _, value = line.partition(" ")
        rows.append([f"auditctl {key}", value.strip() or "-"])
    if not state["auditctl_status"]:
        rows.append(["auditctl -s", "unavailable"])
    return ["key", "value"], rows, payload


def _query_updates(runner: Runner) -> tuple[list[str], list[list[str]], dict[str, Any]]:
    try:
        payload = updates_module.inspect(runner)
    except DistroError as exc:
        payload = {"package": updates_module.PACKAGE, "installed": None, "error": str(exc)}
        return ["key", "value"], [["status", "unavailable"], ["reason", str(exc)]], payload
    rows = [
        ["unattended-upgrades installed", _flag(payload["installed"])],
        ["51-lhm current", "yes" if payload["apt_conf_current"] else "no"],
        ["51-lhm path", str(payload["apt_conf"])],
    ]
    return ["key", "value"], rows, payload


def _handle_query(args: argparse.Namespace, runner: Runner, as_json: bool) -> int:
    builders = {
        "system": _query_system,
        "ssh": lambda: _query_ssh(runner),
        "firewall": lambda: _query_firewall(runner),
        "services": lambda: _query_services(runner),
        "ports": lambda: _query_ports(runner),
        "sysctl": _query_sysctl,
        "audit": lambda: _query_audit(runner),
        "updates": lambda: _query_updates(runner),
    }
    headers, rows, payload = builders[args.target]()
    print_table(headers, rows, as_json=as_json, payload=payload)
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
    if not state["authorized_users"]:
        problems.append("no authorized_keys under /home")
    if not state["dropin_current"]:
        problems.append("99-lhm drop-in missing or differs")
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
        problems.append("jail.local missing or differs")
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
    for module in MODULES:
        checker = CHECKERS.get(module.name)
        if checker is None:
            if module.name == "services":
                rows.append([module.name, "manual", "interactive: apply cleanup-services"])
            else:
                rows.append([module.name, "UNKNOWN", "not implemented"])
            continue
        ok, detail = checker(runner)
        rows.append([module.name, "OK" if ok else "needs-change", detail])
    if as_json:
        print_json([{"area": a, "state": s, "detail": d} for a, s, d in rows])
    else:
        print_table(["area", "state", "detail"], rows)
    return EXIT_OK


def _handle_rollback(args: argparse.Namespace, runner: Runner) -> int:
    path = Path(args.file)
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
    # Restoring a file is not idempotent: same TTY + double-y gate as any apply.
    if not confirm_twice(plan):
        return EXIT_FAIL
    try:
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
    runner = Runner(dry_run=bool(args.dry_run), verbose=bool(args.verbose))
    try:
        if args.command == "query":
            return _handle_query(args, runner, as_json)
        if args.command == "check":
            return _handle_check(args, runner, as_json)
        if args.command == "rollback":
            return _handle_rollback(args, runner)
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
