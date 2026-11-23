"""Read-only state probes used by ``query``, ``check`` and module verification."""

import re
from dataclasses import dataclass, field

from lhm.core.runner import Runner

_DEFAULT_TIMEOUT = 15.0

SERVICES = ("ssh", "ufw", "unattended-upgrades", "fail2ban", "auditd")

SYSCTL_KEYS = (
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.unprivileged_bpf_disabled",
)


@dataclass(frozen=True)
class ServiceState:
    name: str
    active: bool | None
    enabled: bool | None

    @property
    def installed(self) -> bool:
        return self.active is not None or self.enabled is not None


@dataclass(frozen=True)
class PortRecord:
    proto: str
    state: str
    address: str
    port: int | None
    peer: str
    process: str | None


@dataclass(frozen=True)
class UfwRule:
    to: str
    action: str
    source: str


@dataclass(frozen=True)
class UfwStatus:
    active: bool
    default_incoming: str = ""
    default_outgoing: str = ""
    rules: list[UfwRule] = field(default_factory=list)


def _probe(runner: Runner, cmd: list[str]) -> tuple[bool, str]:
    result = runner.run(cmd, timeout=_DEFAULT_TIMEOUT, check=False)
    return result.ok, result.stdout


def probe_service(runner: Runner, name: str) -> ServiceState:
    active_ok, active_out = _probe(runner, ["systemctl", "is-active", name])
    enabled_ok, enabled_out = _probe(runner, ["systemctl", "is-enabled", name])

    active: bool | None = None
    if active_ok or active_out.strip() in {"inactive", "failed", "unknown"}:
        active = active_out.strip() == "active"
    enabled: bool | None = None
    if enabled_ok:
        # rc=0 also covers static/enabled-runtime/indirect units.
        enabled = True
    elif enabled_out.strip() in {"disabled", "masked", "not-found"}:
        enabled = False
    return ServiceState(name=name, active=active, enabled=enabled)


def parse_ss(text: str) -> list[PortRecord]:
    """Parse ``ss -tulpn``/``ss -tlnp`` output (header tolerated, IPv4 and IPv6).

    With a single protocol (``ss -tlnp``) the Netid column is omitted; those
    lines are treated as TCP.
    """
    records: list[PortRecord] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Netid") or stripped.startswith("State"):
            continue
        parts = stripped.split(maxsplit=6)
        if len(parts) < 6:
            continue
        if parts[0] not in {"tcp", "udp"}:
            parts = ["tcp", *parts]
        proto, state, _recv, _send, local, peer = parts[:6]
        process = parts[6] if len(parts) > 6 else None
        address, _, port_text = local.rpartition(":")
        if not address:
            address, port_text = local, ""
        records.append(
            PortRecord(
                proto=proto,
                state=state,
                address=address,
                port=int(port_text) if port_text.isdigit() else None,
                peer=peer,
                process=process,
            )
        )
    return records


def listening_ports(runner: Runner) -> list[PortRecord]:
    ok, out = _probe(runner, ["ss", "-tulpn"])
    return parse_ss(out) if ok else []


def _tcp_listeners(runner: Runner) -> list[PortRecord] | None:
    """TCP LISTEN sockets from ``ss -tlnp``, or None when ``ss`` is unavailable."""
    ok, out = _probe(runner, ["ss", "-tlnp"])
    if not ok:
        return None
    return [
        record
        for record in parse_ss(out)
        if record.proto == "tcp" and record.state == "LISTEN" and record.port is not None
    ]


def listening_tcp_ports(runner: Runner) -> list[int]:
    """Ports actually listening on TCP right now (no config fallback)."""
    records = _tcp_listeners(runner)
    if records is None:
        return []
    return sorted({record.port for record in records if record.port is not None})


def current_ssh_ports(runner: Runner) -> list[int]:
    """Ports sshd listens on before a firewall change (anti-lockout probe).

    Prefers ``ss -tlnp`` (the listener that is really up); falls back to the
    effective ``sshd -T`` port when no sshd-owned socket is visible.
    """
    records = _tcp_listeners(runner) or []
    ports = {
        record.port
        for record in records
        if record.port is not None and record.process and "sshd" in record.process
    }
    if not ports:
        # ss could not attribute the listener (unprivileged run): fall back to
        # the effective sshd port, which is still the port we must keep open.
        port = sshd_effective_config(runner).get("port", "")
        if port.isdigit():
            ports.add(int(port))
    return sorted(ports)


def parse_sshd_config(text: str) -> dict[str, str]:
    """Parse ``sshd -T`` output into a lower-cased keyword mapping."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        keyword, _, value = stripped.partition(" ")
        config[keyword.lower()] = value.strip()
    return config


def sshd_effective_config(runner: Runner) -> dict[str, str]:
    ok, out = _probe(runner, ["sshd", "-T"])
    return parse_sshd_config(out) if ok else {}


def parse_ufw_status(text: str) -> UfwStatus:
    active = False
    incoming = ""
    outgoing = ""
    rules: list[UfwRule] = []
    in_rules = False

    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.lower().startswith("status:"):
            active = stripped.split(":", 1)[1].strip().lower() == "active"
        elif stripped.lower().startswith("default:"):
            incoming = _default_policy(stripped, "incoming")
            outgoing = _default_policy(stripped, "outgoing")
        elif stripped.startswith("--"):
            in_rules = True
        elif in_rules and stripped.strip():
            parts = re.split(r"\s{2,}", stripped.strip())
            if len(parts) >= 2:
                rules.append(
                    UfwRule(
                        to=parts[0],
                        action=parts[1],
                        source=parts[2] if len(parts) > 2 else "",
                    )
                )
    return UfwStatus(
        active=active,
        default_incoming=incoming,
        default_outgoing=outgoing,
        rules=rules,
    )


def _default_policy(line: str, direction: str) -> str:
    match = re.search(rf"(\w+) \({direction}\)", line)
    return match.group(1) if match else ""


def ufw_status(runner: Runner) -> UfwStatus | None:
    ok, out = _probe(runner, ["ufw", "status", "verbose"])
    if not ok and "Status:" not in out:
        return None
    return parse_ufw_status(out)


def sysctl_value(name: str) -> str | None:
    path = "/proc/sys/" + name.replace(".", "/")
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None
