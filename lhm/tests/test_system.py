import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from conftest import FakeExec

from lhm.core import network
from lhm.core.runner import Runner
from lhm.modules import system


@pytest.fixture(autouse=True)
def _isolate_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network, "IPV4_CONF", tmp_path / "ipv4" / "all")
    monkeypatch.setattr(network, "IPV6_CONF", tmp_path / "ipv6")
    monkeypatch.setattr(network, "IPV6_MODULE_DISABLE", tmp_path / "ipv6-module-disable")
    monkeypatch.setattr(system, "OS_RELEASE", tmp_path / "os-release")


def _ipv6_flag(name: str, value: str) -> None:
    path = network.IPV6_CONF / name / "disable_ipv6"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="ascii")


@pytest.mark.parametrize(
    ("all_flag", "default", "lo", "eth", "expected"),
    [
        ("1", "1", "1", "1", "disabled"),
        ("1", "1", "1", "0", "enabled"),
        ("1", "1", "1", None, "unknown"),
        ("1", "0", "1", "1", "enabled"),
        ("0", "1", "1", "1", "unknown"),
    ],
)
def test_ipv6_capability_requires_authoritative_evidence(
    all_flag: str, default: str, lo: str, eth: str | None, expected: str
) -> None:
    for name, flag in (("all", all_flag), ("default", default), ("lo", lo), ("eth0", eth)):
        if flag is not None:
            _ipv6_flag(name, flag)
        else:
            (network.IPV6_CONF / name).mkdir()
    assert network.read_ipv6_capability() == expected


def test_ipv6_module_disable_and_missing_procfs() -> None:
    assert network.read_ipv6_capability() == "unknown"
    network.IPV6_MODULE_DISABLE.write_text("Y\n", encoding="ascii")
    assert network.read_ipv6_capability() == "disabled"


def test_ipv6_enabled_without_addresses_or_default_routes() -> None:
    _ipv6_flag("default", "0")
    fake = FakeExec([("ip -j", 0, "[]", "")])
    state = network.inspect(Runner(exec_fn=fake))
    assert state["capabilities"]["ipv6"] == "enabled"
    assert state["interfaces"] == []
    assert state["default_routes"]["ipv6"] == []


def test_ipv6_disabled_on_current_interfaces_still_requires_firewall_coverage() -> None:
    for name, flag in (("all", "1"), ("default", "0"), ("lo", "1"), ("eth0", "1")):
        _ipv6_flag(name, flag)
    fake = FakeExec([("ip -j", 0, "[]", "")])
    _, rows, payload, _ = system.query(Runner(exec_fn=fake))
    data = json.loads(json.dumps(payload))

    assert data["network"]["capabilities"]["ipv6"] == "enabled"
    assert data["network"]["ipv6_current_interfaces"] == "disabled"
    assert ["ipv6 current interfaces", "disabled"] in rows
    assert network.read_ipv6_capability() == "enabled"


def test_system_query_preserves_identity_and_reports_local_network_time() -> None:
    system.OS_RELEASE.write_text('PRETTY_NAME="Test Linux"\n', encoding="utf-8")
    network.IPV4_CONF.mkdir(parents=True)
    _ipv6_flag("eth0", "0")
    addresses = [
        {
            "ifname": "eth0",
            "addr_info": [
                {"family": "inet", "local": "10.0.0.2", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::2", "prefixlen": 64},
                {"family": "inet6", "local": "2001:db8::2", "prefixlen": 64},
            ],
        },
        {"ifname": "eth1", "addr_info": []},
    ]
    ipv4_routes = [{"dev": "eth0", "gateway": "10.0.0.1", "metric": 100}]
    ipv6_routes = [
        {"metric": 200, "nexthops": [{"dev": "eth0", "gateway": "fe80::1"}, {"dev": "eth1"}]}
    ]
    fake = FakeExec(
        [
            ("ip -j address show", 0, json.dumps(addresses), ""),
            ("ip -j -4 route show default", 0, json.dumps(ipv4_routes), ""),
            ("ip -j -6 route show default", 0, json.dumps(ipv6_routes), ""),
            ("timedatectl show", 0, "Timezone=Asia/Tokyo\nNTPSynchronized=yes\n", ""),
        ]
    )

    headers, rows, payload, colors = system.query(Runner(exec_fn=fake))
    assert headers == ["key", "value"]
    assert [key for key, _ in rows[:7]] == [
        "hostname",
        "distro",
        "kernel",
        "arch",
        "python",
        "user",
        "root",
    ]
    assert not colors
    data = json.loads(json.dumps(payload))
    assert data["distro"] == "Test Linux"
    assert isinstance(data["root"], bool)
    assert data["network"] == {
        "capabilities": {"ipv4": "enabled", "ipv6": "enabled"},
        "ipv6_current_interfaces": "enabled",
        "interfaces": [
            {"name": "eth0", "ipv4": ["10.0.0.2/24"], "ipv6": ["fe80::2/64", "2001:db8::2/64"]},
            {"name": "eth1", "ipv4": [], "ipv6": []},
        ],
        "default_routes": {
            "ipv4": [{"device": "eth0", "gateway": "10.0.0.1", "metric": 100}],
            "ipv6": [
                {"device": "eth0", "gateway": "fe80::1", "metric": 200},
                {"device": "eth1", "gateway": None, "metric": 200},
            ],
        },
    }
    assert ["ipv6 addresses", "eth0: fe80::2/64, 2001:db8::2/64"] in rows
    assert ["ipv6 default route", "dev eth1 metric 200"] in rows
    assert data["time"]["timezone"] == "Asia/Tokyo"
    assert data["time"]["ntp_synchronized"] is True
    assert data["time"]["sync_source"] == "timedatectl"
    utc = datetime.fromisoformat(data["time"]["utc"])
    local = datetime.fromisoformat(data["time"]["local"])
    assert utc == local
    assert utc.utcoffset() == timedelta(0)
    assert local.utcoffset() == timedelta(hours=9)
    assert [call[0] for call in fake.calls] == ["ip", "ip", "ip", "timedatectl"]


def test_no_default_route_differs_from_unavailable_probe() -> None:
    fake = FakeExec(
        [
            ("ip -j address show", 0, "invalid JSON", ""),
            ("ip -j -4 route show default", 0, "[]", ""),
            ("ip -j -6 route show default", 124, "", "timed out"),
            ("timedatectl show", 127, "", ""),
            ("chronyc -n tracking", 1, "", ""),
        ]
    )
    _, rows, payload, _ = system.query(Runner(exec_fn=fake))
    data = json.loads(json.dumps(payload))
    assert data["network"] == {
        "capabilities": {"ipv4": "unknown", "ipv6": "unknown"},
        "ipv6_current_interfaces": "unknown",
        "interfaces": None,
        "default_routes": {"ipv4": [], "ipv6": None},
    }
    assert ["ipv4 default routes", "none"] in rows
    assert ["ipv6 default routes", "unknown"] in rows
    assert ["NTP synchronized", "unknown"] in rows
    assert data["time"]["ntp_synchronized"] is None
    assert data["time"]["sync_source"] is None


@pytest.mark.parametrize("via_key", ["host", "addr"])
def test_default_route_keeps_blackhole_and_cross_family_next_hop(via_key: str) -> None:
    routes = [
        {
            "dst": "default",
            "via": {"family": "inet6", via_key: "fe80::a"},
            "dev": "eth0",
            "metric": 100,
        },
        {"type": "blackhole", "dst": "default", "metric": 500},
    ]
    fake = FakeExec([("ip -j -4 route show default", 0, json.dumps(routes), "")])
    _, rows, payload, _ = system.query(Runner(exec_fn=fake))
    data = json.loads(json.dumps(payload))

    assert data["network"]["default_routes"]["ipv4"] == [
        {"device": "eth0", "gateway": "fe80::a", "metric": 100},
        {"type": "blackhole", "device": None, "gateway": None, "metric": 500},
    ]
    assert ["ipv4 default route", "via fe80::a dev eth0 metric 100"] in rows
    assert ["ipv4 default route", "blackhole metric 500"] in rows


@pytest.mark.parametrize("has_valid_routes", [True, False])
def test_unrecognized_route_keeps_other_routes_and_reports_uncertainty(
    has_valid_routes: bool,
) -> None:
    valid = [{"dev": "eth0", "gateway": "10.0.0.1"}, {"dev": "tun0"}] if has_valid_routes else []
    routes = [*valid[:1], {"dev": "eth1", "via": {"addr": "invalid"}}, *valid[1:]]
    fake = FakeExec([("ip -j -4 route show default", 0, json.dumps(routes), "")])
    _, rows, payload, _ = system.query(Runner(exec_fn=fake))
    net = json.loads(json.dumps(payload))["network"]

    if has_valid_routes:
        assert net["default_routes"]["ipv4"] == [
            {"device": "eth0", "gateway": "10.0.0.1", "metric": None},
            {"device": "tun0", "gateway": None, "metric": None},
        ]
        assert net["default_routes_incomplete"] == ["ipv4"]
        assert ["ipv4 default routes", "incomplete"] in rows
    else:
        assert net["default_routes"]["ipv4"] is None
        assert ["ipv4 default routes", "unknown"] in rows


@pytest.mark.parametrize(
    ("timedatectl", "tracking", "synced", "source"),
    [
        ("NTPSynchronized=no", "Leap status : Normal", False, "timedatectl"),
        ("", "Reference ID : CB00710F (203.0.113.15)\nLeap status : Normal", True, "chrony"),
        ("", "Reference ID : CB00710F\nLeap status : Insert second", True, "chrony"),
        ("", "Leap status : Normal", None, None),
        ("", "Reference ID : not-hex\nLeap status : Normal", None, None),
        ("", "Reference ID : 00000000 ()\nLeap status : Normal", None, None),
        ("", "Leap status : Not synchronised", False, "chrony"),
        ("", "Reference ID : 7F7F0101 ()\nLeap status : Normal", False, "chrony"),
    ],
)
def test_clock_sync_falls_back_to_chrony_only_if_needed(
    timedatectl: str, tracking: str, synced: bool | None, source: str | None
) -> None:
    fake = FakeExec(
        [("timedatectl show", 0, timedatectl, ""), ("chronyc -n tracking", 0, tracking, "")]
    )
    _, _, payload, _ = system.query(Runner(exec_fn=fake))
    data = json.loads(json.dumps(payload))
    assert data["time"]["ntp_synchronized"] is synced
    assert data["time"]["sync_source"] == source
    assert any(call[0] == "chronyc" for call in fake.calls) == (source != "timedatectl")


@pytest.mark.parametrize(
    ("rc", "ipv6_response", "ipv6"),
    [
        (0, "2001:4860::8888\n", "2001:4860::8888"),
        (124, "2001:4860::8888\n", None),
        (0, "8.8.4.4\n", None),
        (0, "fc00::2\n", None),
        (0, "ff0e::2\n", None),
        (0, "2001:4860::8888%eth0\n", None),
        (0, "2001:4860::8888 " + " " * 128, None),
    ],
)
def test_public_ip_opt_in_with_independent_bounded_family_probes(
    rc: int, ipv6_response: str, ipv6: str | None
) -> None:
    prefix = "curl --disable --noproxy * --proto =https"
    fake = FakeExec(
        [(f"{prefix} --ipv4", 0, "8.8.8.8\n", ""), (f"{prefix} --ipv6", rc, ipv6_response, "")]
    )
    _, rows, payload, _ = system.query(Runner(exec_fn=fake), public_ip=True)
    data = json.loads(json.dumps(payload))
    assert data["network"]["public_ip"] == {"ipv4": "8.8.8.8", "ipv6": ipv6}
    assert ["ipv6 public IP", ipv6 or "unavailable"] in rows
    calls = [
        (call, timeout)
        for call, timeout in zip(fake.calls, fake.timeouts, strict=True)
        if call[0] == "curl"
    ]
    assert len(calls) == 2
    for call, timeout in calls:
        assert call[-1] == network.PUBLIC_IP_URL
        assert timeout <= 3.0
        assert float(call[call.index("--max-time") + 1]) <= 3.0
        assert int(call[call.index("--max-filesize") + 1]) == 128


def test_dry_run_does_not_even_plan_external_probe() -> None:
    fake = FakeExec()
    runner = Runner(dry_run=True, exec_fn=fake)
    state = network.inspect(runner, public_ip=True)
    assert "public_ip" not in state
    assert not fake.calls
    assert all(call[0] != "curl" for call in runner.planned)


def test_public_ipv6_is_observed_even_if_ipv4_fails() -> None:
    fake = FakeExec(
        [
            ("curl --disable --noproxy * --proto =https --ipv6", 0, "2001:4860::8888", ""),
            ("curl", 124, "", "timed out"),
        ]
    )
    state = network.inspect(Runner(exec_fn=fake), public_ip=True)
    assert state["public_ip"] == {"ipv4": None, "ipv6": "2001:4860::8888"}
