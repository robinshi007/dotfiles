"""Read-only Linux network observations, independent of external reachability."""

import errno
import json
import socket
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

from lhm.core.runner import Runner

IPV4_CONF = Path("/proc/sys/net/ipv4/conf/all")
IPV6_CONF = Path("/proc/sys/net/ipv6/conf")
IPV6_MODULE_DISABLE = Path("/sys/module/ipv6/parameters/disable")
PUBLIC_IP_URL = "https://api64.ipify.org"
PUBLIC_IP_TIMEOUT = 3.0
LOCAL_TIMEOUT = 2.0

Capability = Literal["enabled", "disabled", "unknown"]
Family = Literal[4, 6]


class Interface(TypedDict):
    name: str
    ipv4: list[str]
    ipv6: list[str]


class DefaultRoute(TypedDict):
    device: str | None
    gateway: str | None
    metric: int | None
    type: NotRequired[str]


class NetworkState(TypedDict):
    capabilities: dict[str, Capability]
    ipv6_current_interfaces: Capability
    interfaces: list[Interface] | None
    default_routes: dict[str, list[DefaultRoute] | None]
    default_routes_incomplete: NotRequired[list[str]]
    public_ip: NotRequired[dict[str, str | None]]


def _read_flag(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError, UnicodeError:
        return ""


def _read_ipv6_state() -> tuple[Capability, Capability]:
    """Return namespace capability and current interface state, respectively."""
    if _read_flag(IPV6_MODULE_DISABLE) in {"1", "Y"}:
        return "disabled", "disabled"

    # Reading conf/all/disable_ipv6 alone is not authoritative: a later
    # per-interface override can re-enable IPv6. Also consider future interfaces
    # via the default, so callers don't mistake a restrictive snapshot for disablement.
    try:
        flags = [
            _read_flag(entry / "disable_ipv6")
            for entry in IPV6_CONF.iterdir()
            if entry.name not in {"all", "default"}
        ]
    except OSError:
        return "unknown", "unknown"
    if "0" in flags:
        return "enabled", "enabled"
    current: Capability = "disabled" if flags and all(flag == "1" for flag in flags) else "unknown"
    default = _read_flag(IPV6_CONF / "default" / "disable_ipv6")
    if default == "0":
        return "enabled", current
    all_flag = _read_flag(IPV6_CONF / "all" / "disable_ipv6")
    if all_flag == default == "1" and current == "disabled":
        return "disabled", current
    return "unknown", current


def read_ipv6_capability() -> Capability:
    """Classify IPv6 for policy: an enabled future interface default needs IPv6 rules."""
    return _read_ipv6_state()[0]


def local_ipv6_capability() -> Capability:
    """Firewall policy fallback when procfs is absent on an IPv4-only kernel."""
    capability = read_ipv6_capability()
    if capability != "unknown":
        return capability
    # Missing sysctls alone do not prove IPv6 is unsupported.
    try:
        IPV6_CONF.stat()
    except FileNotFoundError:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM):
                pass
        except OSError as exc:
            if exc.errno == errno.EAFNOSUPPORT:
                return "disabled"
    except OSError:
        pass
    return "unknown"


def _ip_json(runner: Runner, *args: str) -> list[object] | None:
    try:
        result = runner.run(["ip", "-j", *args], timeout=LOCAL_TIMEOUT, check=False)
        if result.ok:
            records = json.loads(result.stdout)
            if isinstance(records, list):
                return records
    except OSError, ValueError, RecursionError:
        pass
    return None


def _interfaces(runner: Runner) -> list[Interface] | None:
    records = _ip_json(runner, "address", "show")
    if records is None:
        return None
    interfaces: list[Interface] = []
    for record in records:
        if not isinstance(record, dict):
            return None
        name, addresses = record.get("ifname"), record.get("addr_info")
        if not isinstance(name, str) or not isinstance(addresses, list):
            return None
        interface: Interface = {"name": name, "ipv4": [], "ipv6": []}
        for address in addresses:
            if not isinstance(address, dict):
                return None
            family = address.get("family")
            if family not in ("inet", "inet6"):
                continue
            local, prefix = address.get("local"), address.get("prefixlen")
            if not isinstance(local, str) or type(prefix) is not int:
                return None
            try:
                parsed = ip_interface(f"{local}/{prefix}")
            except ValueError:
                return None
            if parsed.version != (4 if family == "inet" else 6):
                return None
            interface["ipv4" if family == "inet" else "ipv6"].append(str(parsed))
        interfaces.append(interface)
    return interfaces


def _route_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _parse_route(record: object) -> list[DefaultRoute] | None:
    if not isinstance(record, dict):
        return None
    kind = record.get("type", "unicast")
    if not isinstance(kind, str):
        return None
    metric = record.get("metric")
    if metric is not None and type(metric) is not int:
        return None
    nexthops = record.get("nexthops", [record])
    if not isinstance(nexthops, list) or not nexthops:
        return None

    routes: list[DefaultRoute] = []
    for hop in nexthops:
        if not isinstance(hop, dict):
            return None
        device, raw_gateway = hop.get("dev"), hop.get("gateway")
        if not isinstance(device, str) and (device is not None or kind == "unicast"):
            return None
        gateway = _route_ip(raw_gateway)
        if raw_gateway is None and "via" in hop:
            via = hop["via"]
            if isinstance(via, dict):
                gateway = _route_ip(via.get("host")) or _route_ip(via.get("addr"))
        if gateway is None and (raw_gateway is not None or "via" in hop):
            return None
        route: DefaultRoute = {"device": device, "gateway": gateway, "metric": metric}
        if kind != "unicast":
            route["type"] = kind
        routes.append(route)
    return routes


def _default_routes(runner: Runner, family: Family) -> tuple[list[DefaultRoute] | None, bool]:
    records = _ip_json(runner, f"-{family}", "route", "show", "default")
    if records is None:
        return None, False
    routes: list[DefaultRoute] = []
    incomplete = False
    for record in records:
        parsed = _parse_route(record)
        if parsed is None:
            incomplete = True
        else:
            routes.extend(parsed)
    if incomplete and not routes:
        return None, False
    return routes, incomplete


def _public_ip(runner: Runner, family: Family) -> str | None:
    try:
        result = runner.run(
            [
                "curl",
                "--disable",
                "--noproxy",
                "*",
                "--proto",
                "=https",
                f"--ipv{family}",
                "--silent",
                "--fail",
                "--max-time",
                str(PUBLIC_IP_TIMEOUT),
                "--max-filesize",
                "128",
                "--limit-rate",
                "1K",
                PUBLIC_IP_URL,
            ],
            timeout=PUBLIC_IP_TIMEOUT,
            check=False,
        )
        if not result.ok or len(result.stdout) > 128 or "%" in result.stdout:
            return None
        address = ip_address(result.stdout.strip())
    except OSError, ValueError:
        return None
    if (
        address.version == family
        and address.is_global
        and not address.is_multicast
        and not address.is_reserved
    ):
        return str(address)
    return None


def inspect(runner: Runner, *, public_ip: bool = False) -> NetworkState:
    """Collect local state and, only on request, probe each HTTPS address family."""
    ipv6, current_ipv6 = _read_ipv6_state()
    interfaces = _interfaces(runner)
    ipv4_routes, ipv4_incomplete = _default_routes(runner, 4)
    ipv6_routes, ipv6_incomplete = _default_routes(runner, 6)
    state: NetworkState = {
        "capabilities": {
            "ipv4": "enabled" if IPV4_CONF.is_dir() else "unknown",
            "ipv6": ipv6,
        },
        "ipv6_current_interfaces": current_ipv6,
        "interfaces": interfaces,
        "default_routes": {"ipv4": ipv4_routes, "ipv6": ipv6_routes},
    }
    incomplete = [
        key for key, partial in (("ipv4", ipv4_incomplete), ("ipv6", ipv6_incomplete)) if partial
    ]
    if incomplete:
        state["default_routes_incomplete"] = incomplete
    if public_ip and not runner.dry_run:
        state["public_ip"] = {"ipv4": _public_ip(runner, 4), "ipv6": _public_ip(runner, 6)}
    return state
