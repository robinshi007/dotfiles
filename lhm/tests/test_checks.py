from typing import Any

from lhm.core import checks
from lhm.core.runner import Runner

SS_TULPN = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0          127.0.0.54:53       0.0.0.0:*     \
users:(("systemd-resolve",pid=700,fd=14))
tcp   LISTEN 0      4096    127.0.0.53:53       0.0.0.0:*
tcp   LISTEN 0      128         0.0.0.0:22345      0.0.0.0:*
tcp   LISTEN 0      128            [::]:22          [::]:*
"""

SSHD_T = """port 22345
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
x11forwarding no
maxauthtries 3
"""

UFW_VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22345/tcp                  ALLOW IN    Anywhere
22/tcp                     ALLOW IN    10.0.0.0/8
22345/tcp (v6)             ALLOW IN    Anywhere (v6)
"""

UFW_INACTIVE = "Status: inactive\n"


def test_parse_ss_handles_v4_v6_and_process() -> None:
    records = checks.parse_ss(SS_TULPN)
    assert len(records) == 4
    ports = {r.port for r in records}
    assert ports == {53, 22345, 22}
    tcp_v6 = next(r for r in records if r.port == 22)
    assert tcp_v6.proto == "tcp"
    assert tcp_v6.address == "[::]"
    assert tcp_v6.state == "LISTEN"
    first = records[0]
    assert first.proto == "udp"
    assert first.process is not None and "systemd-resolve" in first.process


def test_parse_ss_skips_noise() -> None:
    assert checks.parse_ss("") == []
    assert checks.parse_ss("garbage\n") == []


def test_parse_sshd_config() -> None:
    config = checks.parse_sshd_config(SSHD_T)
    assert config["port"] == "22345"
    assert config["permitrootlogin"] == "no"
    assert config["passwordauthentication"] == "no"
    assert config["maxauthtries"] == "3"


def test_parse_ufw_active() -> None:
    status = checks.parse_ufw_status(UFW_VERBOSE)
    assert status.active is True
    assert status.default_incoming == "deny"
    assert status.default_outgoing == "allow"
    assert [(r.to, r.action) for r in status.rules] == [
        ("22345/tcp", "ALLOW IN"),
        ("22/tcp", "ALLOW IN"),
        ("22345/tcp (v6)", "ALLOW IN"),
    ]
    assert status.rules[1].source == "10.0.0.0/8"


def test_parse_ufw_inactive() -> None:
    status = checks.parse_ufw_status(UFW_INACTIVE)
    assert status.active is False
    assert status.rules == []


def test_probe_service_active_and_enabled(fake_exec: Any) -> None:
    fake_exec.responses.extend(
        [
            ("systemctl is-active ssh", 0, "active\n", ""),
            ("systemctl is-enabled ssh", 0, "enabled\n", ""),
        ]
    )
    state = checks.probe_service(Runner(exec_fn=fake_exec), "ssh")
    assert state.active is True
    assert state.enabled is True
    assert state.installed


def test_probe_service_missing_unit_is_unknown(fake_exec: Any) -> None:
    fake_exec.responses.extend(
        [
            ("systemctl is-active nope", 3, "inactive\n", ""),
            ("systemctl is-enabled nope", 1, "", "Failed to get unit file state"),
        ]
    )
    state = checks.probe_service(Runner(exec_fn=fake_exec), "nope")
    assert state.active is False
    assert state.enabled is None


def test_sshd_effective_config_uses_sshd_t(fake_exec: Any) -> None:
    fake_exec.responses.append(("sshd -T", 0, SSHD_T, ""))
    config = checks.sshd_effective_config(Runner(exec_fn=fake_exec))
    assert config["port"] == "22345"


def test_ufw_status_unavailable_returns_none(fake_exec: Any) -> None:
    fake_exec.responses.append(("ufw status verbose", 1, "", "ERROR: not found"))
    assert checks.ufw_status(Runner(exec_fn=fake_exec)) is None
