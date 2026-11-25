"""Conservative evidence for the standard UFW filter paths."""

import errno
import os
import re
import socket
import stat
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from lhm.core.network import Family
from lhm.core.runner import Runner

UFW_DEFAULTS = "/etc/default/ufw"
UFW_CONFIG = "/etc/ufw/ufw.conf"
_DISTRO_SYSCTL = "/etc/ufw/sysctl.conf"
_DISTRO_SYSCTL_BASELINE = tuple(
    """\
net/ipv4/conf/default/rp_filter=1
net/ipv4/conf/all/rp_filter=1
net/ipv4/conf/default/accept_source_route=0
net/ipv4/conf/all/accept_source_route=0
net/ipv6/conf/default/accept_source_route=0
net/ipv6/conf/all/accept_source_route=0
net/ipv4/conf/default/accept_redirects=0
net/ipv4/conf/all/accept_redirects=0
net/ipv6/conf/default/accept_redirects=0
net/ipv6/conf/all/accept_redirects=0
net/ipv4/icmp_echo_ignore_broadcasts=1
net/ipv4/icmp_ignore_bogus_error_responses=1
net/ipv4/icmp_echo_ignore_all=0
net/ipv4/conf/default/log_martians=0
net/ipv4/conf/all/log_martians=0
net/ipv4/tcp_sack=1""".splitlines()
)
_SYSCTL_MAX_BYTES = 64 * 1024


def read(runner: Runner, *command: str, preserve_newlines: bool = False) -> str | None:
    try:
        result = runner.run(command, timeout=5, check=False, preserve_newlines=preserve_newlines)
    except OSError, UnicodeError:
        return None
    return result.stdout if result.ok and not result.stderr.strip() else None


@dataclass(frozen=True)
class Settings:
    ipv6: bool
    enabled: bool
    manage_builtins: bool | None
    ipt_sysctl: str


def settings(runner: Runner) -> Settings | None:
    """Read UFW's effective flags only for unambiguous literal configs."""
    flags: dict[str, bool] = {}
    ipt_sysctl: str | None = None
    for path in (UFW_DEFAULTS, UFW_CONFIG):
        text = read(runner, "cat", path, preserve_newlines=True)
        if text is None:
            return None
        seen: set[str] = set()
        for line in text.split("\n"):
            if not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
                continue
            # UFW reads literal assignments in Python and sources these files at startup.
            match = re.fullmatch(r'([A-Z_][A-Z_0-9]*)=(?:"([A-Za-z0-9_./ -]*)"|([\w./-]*))', line)
            if match is None:
                return None
            key, quoted, bare = match.groups()
            if key in seen or key == "IFS":
                return None
            seen.add(key)
            value = quoted if quoted is not None else bare
            if key == "IPT_SYSCTL":
                if ipt_sysctl is not None and ipt_sysctl != value:
                    return None
                ipt_sysctl = value
                continue
            if key not in {"IPV6", "ENABLED", "MANAGE_BUILTINS"}:
                continue
            if value not in {"yes", "no", "YES", "NO"}:
                return None
            flag = value.lower() == "yes"
            if key in flags and flags[key] != flag:
                return None
            flags[key] = flag
    if "IPV6" not in flags or "ENABLED" not in flags:
        return None
    if ipt_sysctl is None:
        # The startup shell inherits this variable when neither file assigns it.
        ipt_sysctl = os.environ.get("IPT_SYSCTL", "")
    return Settings(flags["IPV6"], flags["ENABLED"], flags.get("MANAGE_BUILTINS"), ipt_sysctl)


def _read_trusted_sysctl(path: Path) -> str | None:
    """Open a small regular file through root-owned, nonsymlink path components."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with ExitStack() as opened:
            parent = os.open("/", flags | os.O_DIRECTORY)
            opened.callback(os.close, parent)
            for part in path.parts[1:-1]:
                info = os.fstat(parent)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    return None
                parent = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                opened.callback(os.close, parent)
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022:
                return None
            fd = os.open(path.name, flags | os.O_NONBLOCK, dir_fd=parent)
            opened.callback(os.close, fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return None
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(_SYSCTL_MAX_BYTES + 1)
            if len(raw) <= _SYSCTL_MAX_BYTES:
                return raw.decode("utf-8")
    except OSError, UnicodeError:
        pass
    return None


def startup_sysctl_safe(value: str) -> bool:
    if not value:
        return True
    # UFW expands IPT_SYSCTL unquoted; require one canonical absolute path.
    if not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+", value, re.ASCII):
        return False
    if any(part in {".", ".."} for part in value.split("/")):
        return False
    text = _read_trusted_sysctl(Path(value))
    if text is None or "\0" in text:
        return False
    directives = tuple(
        stripped
        for line in text.split("\n")
        if (stripped := line.strip(" \t\r")) and not stripped.startswith(("#", ";"))
    )
    # Only the exact packaged 0.36.2 directives are recognized at the distro path.
    return not directives or (value == _DISTRO_SYSCTL and directives == _DISTRO_SYSCTL_BASELINE)


def ipv6_filter_unavailable(runner: Runner) -> bool:
    """Require positive evidence that UFW's IPV6=no DROP branch cannot run."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM):
            return False
    except OSError as exc:
        if exc.errno != errno.EAFNOSUPPORT:
            return False
    try:
        result = runner.run(["ip6tables", "-w", "2", "-L", "INPUT", "-n"], timeout=5, check=False)
    except OSError, UnicodeError:
        return False
    return result.returncode in {1, 2, 3, 4} and "Address family not supported by protocol" in (
        result.stderr
    )


def ports_match(ports: str, port: int) -> bool:
    return any(
        int(first) <= port <= int(last or first)
        for entry in ports.split(",")
        for first, _, last in (entry.partition(":"),)
    )


@dataclass
class Filter:
    policies: dict[str, str] = field(default_factory=dict)
    chains: dict[str, list[str]] = field(default_factory=dict)


_ESTABLISHED = {
    "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
}
_ROUTING_HEADER_DROP = "-m rt --rt-type 0 -j DROP"
_LOGGING_CHAIN = re.compile(
    r"ufw6?-(?:(?:before|user|after)-logging-(?:input|output|forward)|logging-(?:allow|deny))"
)
_LOG_LIMIT = r"-m limit --limit 3/(?:min|minute)(?: --limit-burst 10)?"
_LOG = r'-j LOG --log-prefix "\[UFW (?:BLOCK|ALLOW|AUDIT|AUDIT INVALID|LIMIT BLOCK)\] "'


def _logging_safe(rule: str) -> bool:
    return (
        rule == "-j RETURN"
        or re.fullmatch(
            rf"(?:-m conntrack --ctstate (?:INVALID|NEW) )?(?:{_LOG_LIMIT} )?"
            rf"(?:{_LOG}|-j RETURN)(?: {_LOG_LIMIT})?",
            rule,
        )
        is not None
    )


def _filter(text: str, *, saved: bool = False) -> Filter | None:
    """Read only declarative rules, in order, for a single filter table."""
    lines = [
        " ".join(line.split())
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if saved:
        if not lines or lines[0] != "*filter" or lines[-1] != "COMMIT":
            return None
        lines = lines[1:-1]
    table = Filter()
    for line in lines:
        command, _, rest = line.partition(" ")
        chain, _, rule = rest.partition(" ")
        if not saved and command in {"-P", "-N"} and chain not in table.chains:
            table.chains[chain] = []
            if command == "-P":
                table.policies[chain] = rule
        elif saved and command.startswith(":") and rest == "- [0:0]":
            name = command[1:]
            if name in table.chains:
                return None
            table.chains[name] = []
        elif command == "-A" and chain in table.chains and rule:
            table.chains[chain].append(rule)
        elif (
            saved
            and command == "-I"
            and chain in table.chains
            and _LOGGING_CHAIN.fullmatch(chain)
            and _logging_safe(rule)
        ):
            table.chains[chain].insert(0, rule)
        else:
            return None
    return table


def _before_safe(table: Filter, prefix: str, rules: list[str]) -> bool:
    known = {
        "-i lo -j ACCEPT",
        *_ESTABLISHED,
        "-m conntrack --ctstate INVALID -j DROP",
        f"-m conntrack --ctstate INVALID -j {prefix}-logging-deny",
    }
    if prefix == "ufw6":
        known.add(_ROUTING_HEADER_DROP)
    elif table.chains.get("ufw-not-local", [])[:1] == ["-m addrtype --dst-type LOCAL -j RETURN"]:
        known.add("-j ufw-not-local")
    # Standard UFW ICMP and local multicast/DHCP exceptions. They cannot block SSH.
    return all(
        rule in known
        or re.fullmatch(r"-p (?:icmp|icmpv6|ipv6-icmp|udp) [^!]+ -j ACCEPT", rule) is not None
        or re.fullmatch(r"-(?:s|d) \S+ -p (?:icmpv6|ipv6-icmp|udp) [^!]+ -j ACCEPT", rule)
        is not None
        or re.fullmatch(r"-s \S+ -d \S+ -p udp [^!]+ -j ACCEPT", rule) is not None
        for rule in rules
    )


def _reply_allowed(prefix: str, before_output: list[str]) -> bool:
    harmless = {"-o lo -j ACCEPT"}
    if prefix == "ufw6":
        harmless.add(_ROUTING_HEADER_DROP)
    for rule in before_output:
        if rule in _ESTABLISHED:
            return True
        if rule not in harmless:
            return False
    return False


_PORTS = r"[0-9]{1,5}(?::[0-9]{1,5})?(?:,[0-9]{1,5}(?::[0-9]{1,5})?)*"
_USER_RULE = re.compile(
    rf"((?:-(?:i|s|d) \S+ )*)-p (tcp|udp) (?:-m (?:tcp|udp|multiport) )?"
    rf"--dports? ({_PORTS}) -j (ACCEPT|DROP|REJECT)(?: --reject-with [\w-]+)?"
)


def user_coverage(entries: list[str], desired: list[str]) -> set[str] | None:
    """Prove full accepts in order; stop at an unknown or intersecting blocker."""
    todo = {rule: (int(port), proto) for rule in desired for port, proto in [rule.split("/")]}
    covered: set[str] = set()
    for entry in entries:
        if not todo:
            break
        match = _USER_RULE.fullmatch(entry)
        if match is None:
            return None
        scope, proto, ports, action = match.groups()
        applies = {
            rule
            for rule, (port, protocol) in todo.items()
            if proto == protocol and ports_match(ports, port)
        }
        if applies and action != "ACCEPT":
            return None
        if not scope and action == "ACCEPT":
            covered.update(applies)
            for rule in applies:
                del todo[rule]
    return covered


def runtime_coverage(
    runner: Runner, family: Family, desired: list[str], *, active: bool
) -> set[str] | None:
    exe = "iptables" if family == 4 else "ip6tables"
    text = read(runner, exe, "-w", "2", "-S")
    table = None if text is None else _filter(text)
    if table is None:
        return None
    if not active:
        # No unseen rules may precede the hooks installed on first enable.
        if all(
            table.policies.get(direction) == "ACCEPT" and table.chains.get(direction) == []
            for direction in ("INPUT", "OUTPUT")
        ):
            return set()
        return None
    prefix = "ufw" if family == 4 else "ufw6"
    hooks = ["before-logging", "before", "after", "after-logging", "reject", "track"]
    before = table.chains.get(f"{prefix}-before-input", [])
    user = table.chains.get(f"{prefix}-user-input")
    if (
        table.policies.get("INPUT") != "DROP"
        or table.policies.get("OUTPUT") != "ACCEPT"
        or any(
            table.chains.get(direction.upper())
            != [f"-j {prefix}-{hook}-{direction}" for hook in hooks]
            or f"{prefix}-before-logging-{direction}" not in table.chains
            or not all(
                _logging_safe(rule) for rule in table.chains[f"{prefix}-before-logging-{direction}"]
            )
            for direction in ("input", "output")
        )
        or not _reply_allowed(prefix, table.chains.get(f"{prefix}-before-output", []))
        or before[-1:] != [f"-j {prefix}-user-input"]
        or not _before_safe(table, prefix, before[:-1])
        or user is None
    ):
        return None
    return user_coverage(user, desired)


def saved_coverage(
    runner: Runner, family: Family, desired: list[str], *, fresh: bool
) -> set[str] | None:
    prefix, suffix = ("ufw", "") if family == 4 else ("ufw6", "6")
    for stage in ("before", "after", "user"):
        text = read(runner, "cat", f"/etc/ufw/{stage}{suffix}.rules")
        table = None if text is None else _filter(text, saved=True)
        if table is None or text is None:
            return None
        directions = {
            f"{prefix}-{stage}-{direction}" for direction in ("input", "output", "forward")
        }
        log_chains = {
            f"{prefix}-{where}-logging-{direction}"
            for where in ("before", "user", "after")
            for direction in ("input", "output", "forward")
        } | {f"{prefix}-logging-allow", f"{prefix}-logging-deny"}
        limit_chain, accept_chain = f"{prefix}-user-limit", f"{prefix}-user-limit-accept"
        extra = {
            "before": {"ufw-not-local"} if family == 4 else set(),
            "after": set(),
            "user": log_chains | {limit_chain, accept_chain},
        }[stage]
        if not directions <= table.chains.keys() <= directions | extra:
            return None
        entries = table.chains[f"{prefix}-{stage}-input"]
        if stage == "before" and (
            not _before_safe(table, prefix, entries)
            or not _reply_allowed(prefix, table.chains[f"{prefix}-before-output"])
        ):
            return None
        if stage == "user":
            if (
                any(
                    not _logging_safe(rule)
                    for chain in log_chains
                    for rule in table.chains.get(chain, [])
                )
                or any(
                    rule != "-j REJECT" and not _logging_safe(rule)
                    for rule in table.chains.get(limit_chain, [])
                )
                or any(rule != "-j ACCEPT" for rule in table.chains.get(accept_chain, []))
            ):
                return None
            if fresh and (
                any(table.chains[chain] for chain in directions)
                or any(line.lstrip().startswith("### tuple") for line in text.splitlines())
            ):
                return None
            if any(table.chains[chain] for chain in directions - {f"{prefix}-user-input"}):
                return None
            return user_coverage(entries, desired)
    return None
