"""Read-only system identity, network and clock query."""

import os
import platform
import re
import socket
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from lhm.core import network
from lhm.core.confirm import is_root
from lhm.core.report import RowColor
from lhm.core.runner import Runner

OS_RELEASE = Path("/etc/os-release")
TIME_TIMEOUT = 2.0


class ClockState(TypedDict):
    utc: str
    local: str
    timezone: str
    ntp_synchronized: bool | None
    sync_source: str | None


def _command_output(runner: Runner, argv: Sequence[str]) -> str:
    try:
        result = runner.run(argv, timeout=TIME_TIMEOUT, check=False)
    except OSError, UnicodeError:
        return ""
    return result.stdout if result.ok else ""


def _properties(stdout: str, separator: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition(separator)
        if sep:
            properties[key.strip()] = value.strip()
    return properties


def _inspect_clock(runner: Runner) -> ClockState:
    now = datetime.now(UTC)
    settings = _properties(
        _command_output(
            runner, ["timedatectl", "show", "--property=Timezone", "--property=NTPSynchronized"]
        ),
        "=",
    )
    local = now.astimezone()
    zone = settings.get("Timezone") or None
    if zone is not None:
        try:
            local = now.astimezone(ZoneInfo(zone))
        except ValueError, ZoneInfoNotFoundError:
            zone = None

    synced = {"yes": True, "no": False}.get(settings.get("NTPSynchronized", ""))
    source = "timedatectl" if synced is not None else None
    if synced is None:
        chrony = _properties(_command_output(runner, ["chronyc", "-n", "tracking"]), ":")
        leap = chrony.get("Leap status")
        if leap == "Not synchronised":
            synced = False
        elif leap in {"Normal", "Insert second", "Delete second"}:
            reference = re.fullmatch(
                r"([0-9A-Fa-f]{8})(?:\s+\([^)]*\))?", chrony.get("Reference ID", "")
            )
            if reference is not None and reference[1] != "00000000":
                synced = reference[1].upper() != "7F7F0101"
        if synced is not None:
            source = "chrony"
    return {
        "utc": now.isoformat(timespec="seconds"),
        "local": local.isoformat(timespec="seconds"),
        "timezone": zone or local.tzname() or "unknown",
        "ntp_synchronized": synced,
        "sync_source": source,
    }


def query(
    runner: Runner, *, public_ip: bool = False
) -> tuple[list[str], list[list[str]], dict[str, object], list[RowColor]]:
    try:
        release = _properties(OS_RELEASE.read_text(encoding="utf-8"), "=")
    except OSError, UnicodeError:
        release = {}
    identity = {
        "hostname": socket.gethostname(),
        "distro": release.get("PRETTY_NAME", "unknown").strip('"'),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
        "root": is_root(),
    }
    rows = [[key, str(value)] for key, value in identity.items()]
    net = network.inspect(runner, public_ip=public_ip)
    interfaces = net["interfaces"]
    for family in ("ipv4", "ipv6"):
        rows.append([f"{family} capability", net["capabilities"][family]])
        if family == "ipv6":
            rows.append(["ipv6 current interfaces", net["ipv6_current_interfaces"]])
        if interfaces is None:
            rows.append([f"{family} addresses", "unknown"])
        else:
            addresses = [
                f"{interface['name']}: {', '.join(interface[family])}"
                for interface in interfaces
                if interface[family]
            ]
            rows.append([f"{family} addresses", "; ".join(addresses) or "none"])
        routes = net["default_routes"][family]
        if routes is None:
            rows.append([f"{family} default routes", "unknown"])
        elif not routes:
            rows.append([f"{family} default routes", "none"])
        else:
            if family in net.get("default_routes_incomplete", []):
                rows.append([f"{family} default routes", "incomplete"])
            for route in routes:
                parts = [route["type"]] if "type" in route else []
                if route["gateway"] is not None:
                    parts.append(f"via {route['gateway']}")
                if route["device"] is not None:
                    parts.append(f"dev {route['device']}")
                if route["metric"] is not None:
                    parts.append(f"metric {route['metric']}")
                rows.append([f"{family} default route", " ".join(parts)])
        if "public_ip" in net:
            rows.append([f"{family} public IP", net["public_ip"][family] or "unavailable"])
    clock = _inspect_clock(runner)
    synced = {True: "yes", False: "no", None: "unknown"}[clock["ntp_synchronized"]]
    if clock["sync_source"] is not None:
        synced += f" ({clock['sync_source']})"
    rows.extend(
        [
            ["utc", clock["utc"]],
            ["local time", clock["local"]],
            ["timezone", clock["timezone"]],
            ["NTP synchronized", synced],
        ]
    )
    return ["key", "value"], rows, {**identity, "network": net, "time": clock}, []
