"""Read-only state probes used by ``query``, ``check`` and module verification."""

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from lhm.core.runner import Runner

_DEFAULT_TIMEOUT = 15.0
type SshEndpoint = tuple[str, int]

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
        record for record in parse_ss(out) if record.proto == "tcp" and record.state == "LISTEN"
    ]


_SS_OWNER = re.compile(r'\("([^"]+)",pid=(\d+),fd=\d+\)')


def _numeric_bind_address(address: str) -> str | None:
    if "%" in address:
        return None  # A scoped or interface-bound endpoint cannot be compared here.
    try:
        if address.startswith("[") and address.endswith("]"):
            return str(IPv6Address(address[1:-1]))
        return str(IPv4Address(address))
    except ValueError:
        return None


def socket_listen_endpoints(runner: Runner, socket_unit: str) -> set[SshEndpoint] | None:
    """Return exact TCP bindings cached by systemd, or None when not understood."""
    ok, output = _probe(runner, ["systemctl", "show", "--property=Listen", "--value", socket_unit])
    fields = output.split()
    if not ok or not fields or len(fields) % 2:
        return None
    endpoints: set[SshEndpoint] = set()
    for address, kind in zip(fields[::2], fields[1::2]):
        host, _, port = address.rpartition(":")
        normalized = _numeric_bind_address(host)
        if (
            kind != "(Stream)"
            or normalized is None
            or not re.fullmatch(r"[0-9]{1,5}", port)
            or not 1 <= int(port) <= 65535
        ):
            return None
        endpoints.add((normalized, int(port)))

    ok, output = _probe(
        runner,
        ["systemctl", "show", "--property=BindToDevice", "--property=BindIPv6Only", socket_unit],
    )
    props = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if not ok or props.get("BindToDevice") != "":
        return None
    if any(address == "::" for address, _ in endpoints):
        mode = props.get("BindIPv6Only")
        if mode == "default":
            ok, value = _probe(runner, ["sysctl", "-n", "net.ipv6.bindv6only"])
            if not ok or value.strip() not in {"0", "1"}:
                return None
            mode = "both" if value.strip() == "0" else "ipv6-only"
        if mode == "both":
            # iproute2's ss renders a dual-stack wildcard as "*", not "[::]".
            endpoints = {("*" if address == "::" else address, port) for address, port in endpoints}
        elif mode != "ipv6-only":
            return None
    return endpoints


def live_ssh_endpoints(
    runner: Runner, *, socket_unit: str | None = None
) -> set[SshEndpoint] | None:
    """Probe address and port for sshd, or verify every binding of an SSH socket."""
    records = _tcp_listeners(runner)
    if records is None:
        return None
    endpoints: set[SshEndpoint] = set()
    for record in records:
        owners = _SS_OWNER.findall(record.process or "")
        if socket_unit is None:
            owned = any(name == "sshd" for name, _ in owners)
        else:
            owned = ("systemd", "1") in owners
        if not owned:
            continue
        address = "*" if record.address == "*" else _numeric_bind_address(record.address)
        if address is None or record.port is None or not 1 <= record.port <= 65535:
            if socket_unit is None:
                return None
            continue  # PID 1 owns unrelated sockets; only configured exact matches count.
        endpoints.add((address, record.port))
    if socket_unit is None:
        return endpoints
    configured = socket_listen_endpoints(runner, socket_unit)
    return configured if configured and configured <= endpoints else None


def _verified_socket_ports(
    runner: Runner, socket_unit: str, systemd_ports: set[int]
) -> tuple[set[int], bool]:
    """Return verified TCP ports and whether all Listen entries were verified."""
    if not systemd_ports:
        return set(), False
    ok, output = _probe(runner, ["systemctl", "show", "--property=Listen", "--value", socket_unit])
    if not ok:
        return set(), False
    fields = output.split()
    complete = len(fields) % 2 == 0
    ports: set[int] = set()
    for address, kind in zip(fields[::2], fields[1::2]):
        host, sep, port = address.rpartition(":")
        if (
            kind != "(Stream)"
            or not re.fullmatch(r"[0-9]{1,5}", port)
            or not 1 <= int(port) <= 65535
            or (sep and not host)
        ):
            complete = False
            continue
        if host and host != "*":
            try:
                if host.startswith("[") and host.endswith("]"):
                    IPv6Address(host[1:-1])
                else:
                    IPv4Address(host)
            except ValueError:
                complete = False
                continue
        ports.add(int(port))
    return ports & systemd_ports, complete and bool(ports) and ports <= systemd_ports


def _tcp_owner_ports(runner: Runner) -> tuple[set[int], set[int]] | None:
    records = _tcp_listeners(runner)
    if records is None:
        return None
    owners_by_port = [
        (record.port, _SS_OWNER.findall(record.process or ""))
        for record in records
        if record.port is not None
    ]
    sshd_ports = {
        port for port, owners in owners_by_port if any(name == "sshd" for name, _ in owners)
    }
    systemd_ports = {port for port, owners in owners_by_port if ("systemd", "1") in owners}
    return sshd_ports, systemd_ports


def _active_ssh_socket_ports(runner: Runner, systemd_ports: set[int]) -> tuple[set[int], bool]:
    """Return verified ports and whether all socket states and active ports were verified."""
    complete = True
    verified: set[int] = set()
    for unit in ("ssh.socket", "sshd.socket"):
        result = runner.run(["systemctl", "is-active", unit], timeout=_DEFAULT_TIMEOUT, check=False)
        state = result.stdout.strip()
        if result.ok and state == "active":
            ports, unit_complete = _verified_socket_ports(runner, unit, systemd_ports)
            verified.update(ports)
            complete = complete and unit_complete
        elif result.returncode == 3 and state in {"inactive", "failed"}:
            continue
        elif result.returncode == 4 and state == "inactive":
            # An absent unit reports inactive with LSB exit status 4.
            continue
        else:
            complete = False
    return verified, complete


def live_ssh_ports(runner: Runner, *, socket_unit: str | None = None) -> list[int] | None:
    """List live SSH ports, or require attribution to the given active socket.

    None means the required listener evidence is unavailable or incomplete.
    """
    owners = _tcp_owner_ports(runner)
    if owners is None:
        return None
    sshd_ports, systemd_ports = owners
    if socket_unit is not None:
        ports, complete = _verified_socket_ports(runner, socket_unit, systemd_ports)
        return sorted(ports) if complete else None
    if systemd_ports:
        ports, _ = _active_ssh_socket_ports(runner, systemd_ports)
        sshd_ports.update(ports)
    return sorted(sshd_ports)


def current_ssh_ports(runner: Runner) -> list[int] | None:
    """Find SSH listener ports before a firewall change (anti-lockout probe).

    None means a socket state is unknown or an active socket could not be fully
    verified, or no live SSH port was found and the standalone ``sshd -T``
    fallback failed or reported an invalid port. An empty list means the
    fallback succeeded but reported no Port entries.
    """
    sshd_ports, systemd_ports = _tcp_owner_ports(runner) or (set(), set())
    socket_ports, complete = _active_ssh_socket_ports(runner, systemd_ports)
    if not complete:
        return None
    if sshd_ports or socket_ports:
        return sorted(sshd_ports | socket_ports)
    try:
        ok, out = _probe(runner, ["sshd", "-T"])
    except OSError:
        return None
    if not ok:
        return None

    ports: set[int] = set()
    for line in out.splitlines():
        fields = line.split(maxsplit=1)
        if not fields or fields[0].lower() != "port":
            continue
        if len(fields) != 2 or not re.fullmatch(r"[0-9]{1,5}", fields[1].strip()):
            return None
        port = int(fields[1])
        if not 1 <= port <= 65535:
            return None
        ports.add(port)
    return sorted(ports)


def parse_sshd_config(text: str) -> dict[str, str]:
    """Parse ``sshd -T`` output into a lower-cased keyword mapping."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        keyword, _, value = stripped.partition(" ")
        option = keyword.lower()
        value = value.strip()
        if option == "allowusers" and option in config:
            value = f"{config[option]} {value}"
        config[option] = value
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
