import subprocess
from typing import Any

import pytest

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


def test_parse_sshd_config_accumulates_allowusers() -> None:
    config = checks.parse_sshd_config("allowusers robin\nAllowUsers deploy\n")
    assert config["allowusers"] == "robin deploy"


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


@pytest.mark.parametrize(
    ("rc", "listen", "expected"),
    [
        (0, "[::]:22 (Stream)\n", [22]),
        (1, "[::]:22 (Stream)\n", None),
        (0, "", None),
        (0, "[::]:bad (Stream)\n", None),
        (0, "garbage:22 (Stream)\n", None),
        (0, "[::]:22 (Stream) garbage\n", None),
        (0, "[::]:2200 (Stream)\n", None),
        (0, "[::]:22345 (Stream)\n", None),
        (0, "[::]:22 (Stream) [::]:2200 (Stream)\n", None),
    ],
)
def test_live_ssh_ports_requires_attribution_for_explicit_socket(
    fake_exec: Any, rc: int, listen: str, expected: list[int] | None
) -> None:
    fake_exec.responses.extend(
        [
            (
                "ss -tlnp",
                0,
                'LISTEN 0 128 [::]:22 [::]:* users:(("systemd",pid=1,fd=3))\n'
                'LISTEN 0 128 [::]:22345 [::]:* users:(("sshd",pid=50,fd=4))\n',
                "",
            ),
            ("systemctl show --property=Listen --value ssh.socket", rc, listen, ""),
        ]
    )
    assert checks.live_ssh_ports(Runner(exec_fn=fake_exec), socket_unit="ssh.socket") == expected


@pytest.mark.parametrize(
    ("listen", "local", "mode", "default_v6_only", "device", "expected"),
    [
        ("0.0.0.0:22", "0.0.0.0:22", "default", "", "", {("0.0.0.0", 22)}),
        ("127.0.0.1:22", "0.0.0.0:22", "default", "", "", None),
        ("0.0.0.0:22", "127.0.0.1:22", "default", "", "", None),
        ("[::]:22", "[::]:22", "ipv6-only", "", "", {("::", 22)}),
        ("[::]:22", "*:22", "both", "", "", {("*", 22)}),
        ("[::]:22", "*:22", "default", "0\n", "", {("*", 22)}),
        ("[::]:22", "[::]:22", "default", "0\n", "", None),
        ("[::]:22", "*:22", "default", "", "", None),
        ("[::]:22", "0.0.0.0:22", "both", "", "", None),
        ("[::]:22", "[::1]:22", "ipv6-only", "", "", None),
        ("[2001:0db8:0:0::1]:22", "[2001:db8::1]:22", "default", "", "", {("2001:db8::1", 22)}),
        ("[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "ipv6-only", "", "", None),
        ("0.0.0.0:22", "0.0.0.0:22", "default", "", "eth0", None),
        ("22", "*:22", "both", "", "", None),
    ],
)
def test_live_ssh_endpoints_requires_exact_understood_socket_binding(
    fake_exec: Any,
    listen: str,
    local: str,
    mode: str,
    default_v6_only: str,
    device: str,
    expected: set[checks.SshEndpoint] | None,
) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", 0, f'LISTEN 0 128 {local} *:* users:(("systemd",pid=1,fd=3))\n', ""),
            (
                "systemctl show --property=Listen --value ssh.socket",
                0,
                f"{listen} (Stream)\n",
                "",
            ),
            (
                "systemctl show --property=BindToDevice --property=BindIPv6Only ssh.socket",
                0,
                f"BindToDevice={device}\nBindIPv6Only={mode}\n",
                "",
            ),
            ("sysctl -n net.ipv6.bindv6only", 0, default_v6_only, ""),
        ]
    )
    runner = Runner(exec_fn=fake_exec)
    assert checks.live_ssh_endpoints(runner, socket_unit="ssh.socket") == expected


@pytest.mark.parametrize(
    ("listen", "other_listen", "expected"),
    [
        ("[::]:22 (Stream)\n", None, [22]),
        ("[::]:22 (Stream) [::]:443 (Stream)\n", None, [22, 443]),
        ("[::]:22 (Stream)\n", "[::]:443 (Stream)\n", [22, 443]),
        ("[::]:22 (Stream)\n", "", None),
    ],
)
def test_current_ssh_ports_prefers_attributed_systemd_listener(
    fake_exec: Any, listen: str, other_listen: str | None, expected: list[int] | None
) -> None:
    fake_exec.responses.extend(
        [
            (
                "ss -tlnp",
                0,
                'LISTEN 0 128 [::]:22 [::]:* users:(("systemd",pid=1,fd=3))\n'
                'LISTEN 0 128 [::]:443 [::]:* users:(("systemd",pid=1,fd=4))\n',
                "",
            ),
            ("systemctl is-active ssh.socket", 0, "active\n", ""),
            ("systemctl show --property=Listen --value ssh.socket", 0, listen, ""),
            (
                "systemctl is-active sshd.socket",
                0 if other_listen is not None else 3,
                "active\n" if other_listen is not None else "inactive\n",
                "",
            ),
            ("systemctl show --property=Listen --value sshd.socket", 0, other_listen or "", ""),
            ("sshd -T", 0, "port 22345\n", ""),
        ]
    )
    assert checks.current_ssh_ports(Runner(exec_fn=fake_exec)) == expected
    assert ["sshd", "-T"] not in fake_exec.calls


@pytest.mark.parametrize(
    ("ss_rc", "owner"),
    [(1, ""), (0, ""), (0, ' users:(("sshd",pid=50,fd=4))')],
)
def test_current_ssh_ports_does_not_fall_back_when_active_socket_is_unverified(
    fake_exec: Any, ss_rc: int, owner: str
) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", ss_rc, f"LISTEN 0 128 [::]:2200 [::]:*{owner}\n", ""),
            ("systemctl is-active ssh.socket", 0, "active\n", ""),
            ("systemctl show --property=Listen --value ssh.socket", 0, "[::]:22 (Stream)\n", ""),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
            ("sshd -T", 0, "port 22345\n", ""),
        ]
    )
    assert checks.current_ssh_ports(Runner(exec_fn=fake_exec)) is None
    assert ["sshd", "-T"] not in fake_exec.calls


@pytest.mark.parametrize("state", ["inactive", "failed"])
def test_current_ssh_ports_falls_back_without_active_socket(fake_exec: Any, state: str) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", 127, "", "ss: not found"),
            ("systemctl is-active ssh.socket", 3, f"{state}\n", ""),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
            ("sshd -T", 0, SSHD_T, ""),
        ]
    )
    assert checks.current_ssh_ports(Runner(exec_fn=fake_exec)) == [22345]


@pytest.mark.parametrize("ss_rc", [0, 127], ids=["empty-listeners", "ss-unavailable"])
@pytest.mark.parametrize(
    ("fallback_rc", "fallback_out", "expected"),
    [
        (127, "", None),
        (124, "port 22\n", None),
        (0, "", []),
        (0, "permitrootlogin no\n", []),
        (0, "port\n", None),
        (0, "port\tbad\n", None),
        (0, "port ²\n", None),
        (0, "port 0\n", None),
        (0, "port 65536\n", None),
        (0, "port 0\nport 22\n", None),
        (0, "port 65535\nport 22\nport 22\n", [22, 65535]),
    ],
)
def test_current_ssh_ports_distinguishes_unverified_from_empty_fallback(
    fake_exec: Any,
    ss_rc: int,
    fallback_rc: int,
    fallback_out: str,
    expected: list[int] | None,
) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", ss_rc, "", ""),
            ("systemctl is-active ssh.socket", 4, "inactive\n", ""),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
            ("sshd -T", fallback_rc, fallback_out, ""),
        ]
    )
    assert checks.current_ssh_ports(Runner(exec_fn=fake_exec)) == expected


def test_current_ssh_ports_refuses_when_sshd_t_cannot_start(fake_exec: Any) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", 0, "", ""),
            ("systemctl is-active ssh.socket", 4, "inactive\n", ""),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
        ]
    )

    def exec_fn(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["sshd", "-T"]:
            raise PermissionError("cannot execute sshd")
        return fake_exec(cmd, timeout)

    assert checks.current_ssh_ports(Runner(exec_fn=exec_fn)) is None


@pytest.mark.parametrize(
    "ss_output", ["", 'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=5,fd=3))\n']
)
@pytest.mark.parametrize(
    ("rc", "state", "stderr"),
    [
        (1, "", "Failed to connect to bus: No such file or directory"),
        (124, "", "systemctl: timed out after 15.0s"),
        (0, "inactive\n", ""),
        (3, "active\n", ""),
        (3, "activating\n", ""),
        (4, "failed\n", ""),
        (4, "unknown\n", ""),
    ],
)
def test_current_ssh_ports_refuses_unknown_socket_state(
    fake_exec: Any, ss_output: str, rc: int, state: str, stderr: str
) -> None:
    fake_exec.responses.extend(
        [
            ("ss -tlnp", 0, ss_output, ""),
            ("systemctl is-active ssh.socket", 4, "inactive\n", ""),
            ("systemctl is-active sshd.socket", rc, state, stderr),
            ("sshd -T", 0, SSHD_T, ""),
        ]
    )
    assert checks.current_ssh_ports(Runner(exec_fn=fake_exec)) is None
    assert ["sshd", "-T"] not in fake_exec.calls


def test_ufw_status_unavailable_returns_none(fake_exec: Any) -> None:
    fake_exec.responses.append(("ufw status verbose", 1, "", "ERROR: not found"))
    assert checks.ufw_status(Runner(exec_fn=fake_exec)) is None
