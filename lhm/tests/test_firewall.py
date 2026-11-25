import errno
import subprocess
from pathlib import Path
from typing import Any

import pytest

from lhm import cli
from lhm.core import checks, network
from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import caddy, firewall, firewall_ufw, ssh, ssh_watchdog

UFW_ENABLED_CLEAN = """Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22345/tcp                  ALLOW IN    Anywhere
"""

ABSENT_SOCKETS = (
    ("systemctl is-active ssh.socket", 4, "inactive\n", ""),
    ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
)
_IPV6_FILTER_UNAVAILABLE = firewall_ufw.ipv6_filter_unavailable
_UFW_0362_USER_RULES = Path(__file__).parent / "fixtures" / "ufw-0.36.2-user.rules"


@pytest.fixture(autouse=True)
def _fake_local_firewall(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("IPT_SYSCTL", raising=False)
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "disabled")
    monkeypatch.setattr(firewall_ufw, "ipv6_filter_unavailable", lambda runner: True)
    monkeypatch.setattr(firewall, "UFW_LOCK_TARGET", tmp_path / "ufw.conf")
    monkeypatch.setattr(ssh, "SSHD_DROPIN", tmp_path / "ssh-hardening.conf")
    monkeypatch.setattr(ssh_watchdog, "current", lambda: None)
    monkeypatch.setattr(caddy, "firewall_ingress_identity", lambda runner: None, raising=False)


def test_parse_allow() -> None:
    assert firewall.parse_allow("80/tcp") == "80/tcp"
    assert firewall.parse_allow("53/udp") == "53/udp"
    assert firewall.parse_allow("443") == "443/tcp"
    with pytest.raises(firewall.RuleError):
        firewall.parse_allow("http/tcp")
    with pytest.raises(firewall.RuleError):
        firewall.parse_allow("80/sctp")


def test_dry_run_orders_ssh_allow_before_default_deny(
    fake_exec: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = firewall.apply_firewall(runner, allow=["80/tcp"])
    planned = [" ".join(cmd) for cmd in runner.planned]
    # The probe itself is a read; dry-run only records it in the plan text.
    assert planned[0] == "ufw allow 22345/tcp"
    assert planned[1] == "ufw allow 80/tcp"
    deny = planned.index("ufw default deny incoming")
    assert 0 < deny
    assert planned[deny + 1] == "ufw default allow outgoing"
    assert planned[-1] == "ufw --force enable"
    assert fake_exec.calls == []
    assert "probe current SSH listen port(s)" in capsys.readouterr().out
    assert all(r.status is Status.PLANNED for r in results)


def test_invalid_allow_is_refused_without_commands(fake_exec: Any) -> None:
    runner = Runner(exec_fn=fake_exec)
    results = firewall.apply_firewall(runner, allow=["bogus"])
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []


class UfwSequenceExec:
    """Model preflight and final UFW status independently of the runner commands."""

    def __init__(
        self,
        final: str = UFW_ENABLED_CLEAN,
        *,
        initial: str = "Status: inactive\n",
        ipv6: str = "no",
        configured: str | None = None,
        initial_rc: int = 0,
        config_suffix: str = "",
        builtins: str = "MANAGE_BUILTINS=no\n",
    ) -> None:
        self.calls: list[list[str]] = []
        self.status_calls = 0
        self.final = final
        self.initial = initial
        self.ipv6 = ipv6
        self.configured = configured or ("yes" if "Status: active" in initial else "no")
        self.initial_rc = initial_rc
        self.config_suffix = config_suffix
        self.builtins = builtins
        self.active = "Status: active" in initial
        self.saved: dict[str, list[str]] = {"": [], "6": []}
        for rule in checks.parse_ufw_status(initial).rules:
            if rule.action not in {"ALLOW", "ALLOW IN"}:
                continue
            family = "6" if rule.to.endswith(" (v6)") else ""
            port, proto = rule.to.removesuffix(" (v6)").split("/")
            self.saved[family].append(f"-p {proto} -m {proto} --dport {port} -j ACCEPT")
        self.live_override: dict[str, list[str]] = {}
        self.detach: set[str] = set()
        self.skip_stage = False
        self.user_files: dict[str, str] = {}
        self.before_reply: list[str] = ["-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]
        self.live_before_reply: list[str] | None = None

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(cmd, 4, "inactive\n", "")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, "port 22345\n", "")
        if cmd == ["cat", "/etc/default/ufw"]:
            return subprocess.CompletedProcess(cmd, 0, f"IPV6={self.ipv6}\n{self.builtins}", "")
        if cmd == ["cat", "/etc/ufw/ufw.conf"]:
            out = f"ENABLED={self.configured}\n{self.config_suffix}"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if cmd[0] == "cat" and cmd[1].endswith(".rules"):
            name = cmd[1].rsplit("/", 1)[1].removesuffix(".rules")
            stage, family = name.removesuffix("6"), ("6" if name.endswith("6") else "")
            if stage == "user" and self.saved[family] and family in self.user_files:
                return subprocess.CompletedProcess(cmd, 0, self.user_files[family], "")
            prefix = f"ufw{family}-{stage}"
            entries = self.saved[family] if stage == "user" else []
            lines = [
                "*filter",
                *(f":{prefix}-{direct} - [0:0]" for direct in ("input", "output", "forward")),
                *(f"-A {prefix}-input {entry}" for entry in entries),
                *(
                    f"-A {prefix}-output {entry}"
                    for entry in self.before_reply
                    if stage == "before"
                ),
                "COMMIT",
            ]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(lines), "")
        if cmd[0] in {"iptables", "ip6tables"}:
            family = "6" if cmd[0] == "ip6tables" else ""
            if not self.active:
                return subprocess.CompletedProcess(
                    cmd, 0, "-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n", ""
                )
            prefix = f"ufw{family}"
            hooks = [
                "before-logging",
                "before",
                "after",
                "after-logging",
                "reject",
                "track",
            ]
            entries = self.live_override.get(family, self.saved[family])
            lines = [
                "-P INPUT DROP",
                "-P OUTPUT ACCEPT",
                *(
                    f"-N {prefix}-{hook}-{direction}"
                    for direction in ("input", "output")
                    for hook in hooks
                ),
                f"-N {prefix}-user-input",
                *(
                    f"-A {direction.upper()} -j {prefix}-{hook}-{direction}"
                    for direction in ("input", "output")
                    for hook in hooks
                    if family not in self.detach
                ),
                f"-A {prefix}-before-input -i lo -j ACCEPT",
                f"-A {prefix}-before-input -j {prefix}-user-input",
                *(
                    f"-A {prefix}-before-output {entry}"
                    for entry in (
                        self.before_reply
                        if self.live_before_reply is None
                        else self.live_before_reply
                    )
                ),
                *(f"-A {prefix}-user-input {entry}" for entry in entries),
            ]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(lines), "")
        if cmd[:3] == ["ufw", "status", "verbose"]:
            self.status_calls += 1
            if self.status_calls == 1:
                return subprocess.CompletedProcess(cmd, self.initial_rc, self.initial, "")
            return subprocess.CompletedProcess(cmd, 0, self.final, "")
        if cmd[:2] == ["ufw", "allow"] and not self.skip_stage:
            if len(cmd) == 3:
                port, proto = cmd[2].split("/")
                families = ("", "6") if self.ipv6 == "yes" else ("",)
            else:
                port, proto = cmd[-1], cmd[3]
                families = ("6",) if cmd[5] == "::/0" else ("",)
            for family in families:
                self.saved[family].append(f"-p {proto} -m {proto} --dport {port} -j ACCEPT")
        if cmd == ["ufw", "--force", "enable"]:
            self.active = True
            self.configured = "yes"
        return subprocess.CompletedProcess(cmd, 0, "", "")


UFW_ENABLED_WITH_80 = UFW_ENABLED_CLEAN + "80/tcp                     ALLOW IN    Anywhere\n"


def test_apply_order_and_skip_existing_ssh_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec(UFW_ENABLED_WITH_80)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["80/tcp"])
    mutating = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert mutating == [["ufw", "allow", "22345/tcp"], ["ufw", "allow", "80/tcp"]]
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22345/tcp") < order.index("ufw default deny incoming")
    assert order.index("ufw allow 80/tcp") < order.index("ufw default deny incoming")
    assert order.index("ufw --force enable") > order.index("ufw default allow outgoing")
    assert results[-1].status is Status.OK


def test_already_configured_is_a_noop() -> None:
    exec_fn = UfwSequenceExec(initial=UFW_ENABLED_CLEAN)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    assert results[0].status is Status.SKIPPED
    ufw_calls = [call for call in exec_fn.calls if call[:1] == ["ufw"]]
    assert [call[:2] for call in ufw_calls] == [["ufw", "status"]]


def test_existing_rules_are_not_reapplied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec(UFW_ENABLED_WITH_80, initial=UFW_ENABLED_CLEAN)
    firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["80/tcp"])
    mutating = [
        " ".join(call) for call in exec_fn.calls if call[:1] == ["ufw"] and "status" not in call
    ]
    assert "ufw allow 22345/tcp" not in mutating
    assert "ufw allow 80/tcp" in mutating


def test_verify_fails_when_ufw_inactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec("Status: inactive\n")
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    assert results[-1].status is Status.FAIL
    assert "not active" in results[-1].detail


class TimeoutAwareExec:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.timeouts.append(timeout)
        if cmd[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(cmd, 4, "inactive\n", "")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, "port 22345\n", "")
        if cmd == ["cat", "/etc/default/ufw"]:
            return subprocess.CompletedProcess(cmd, 0, "IPV6=no\n", "")
        if cmd == ["cat", "/etc/ufw/ufw.conf"]:
            return subprocess.CompletedProcess(cmd, 0, "ENABLED=yes\n", "")
        if cmd[:3] == ["ufw", "status", "verbose"]:
            return subprocess.CompletedProcess(cmd, 0, UFW_ENABLED_CLEAN, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_every_command_has_a_timeout() -> None:
    exec_fn = TimeoutAwareExec()
    firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["80/tcp"])
    assert exec_fn.timeouts and all(value > 0 for value in exec_fn.timeouts)


SS_TLN_PORT_22 = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=900,fd=3))
LISTEN 0      128             [::]:22            [::]:*     users:(("sshd",pid=900,fd=4))
"""


class CurrentPortExec(UfwSequenceExec):
    """Firewall state sequence with configurable SSH probe output."""

    def __init__(self, ss_out: str = "", sshd_t_out: str = "") -> None:
        super().__init__(UFW_ENABLED_CLEAN + "22/tcp  ALLOW IN  Anywhere\n")
        self.ss_out = ss_out
        self.sshd_t_out = sshd_t_out

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["ss", "-tlnp"]:
            self.calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, self.ss_out, "")
        if cmd == ["sshd", "-T"]:
            self.calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, self.sshd_t_out, "")
        return super().__call__(cmd, timeout)


def test_current_ssh_port_is_allowed_before_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server still on port 22 must keep 22/tcp open before default deny."""
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = CurrentPortExec(SS_TLN_PORT_22)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert allows == [["ufw", "allow", "22345/tcp"], ["ufw", "allow", "22/tcp"]]
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22/tcp") < order.index("ufw default deny incoming")
    assert order.index("ufw allow 22345/tcp") < order.index("ufw default deny incoming")
    assert all(r.status is not Status.FAIL for r in results)


def test_current_ssh_port_falls_back_to_sshd_t(monkeypatch: pytest.MonkeyPatch) -> None:
    """ss without a process column: use the effective sshd port."""
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = CurrentPortExec(ss_out="LISTEN 0 128 [::]:22 [::]:*\n", sshd_t_out="port 22\n")
    firewall.apply_firewall(Runner(exec_fn=exec_fn))
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert ["ufw", "allow", "22/tcp"] in allows
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22/tcp") < order.index("ufw default deny incoming")


def test_same_port_is_not_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = CurrentPortExec(
        ss_out='LISTEN 0 128 0.0.0.0:22345 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
    )
    firewall.apply_firewall(Runner(exec_fn=exec_fn))
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert allows == [["ufw", "allow", "22345/tcp"]]


@pytest.mark.parametrize("allow", [(), ("22/tcp",)])
@pytest.mark.parametrize(
    ("ss_rc", "fallback_rc", "fallback_out"),
    [(127, 127, ""), (0, 1, ""), (0, 0, "port bad\n"), (0, 0, "port 65536\n")],
)
def test_unverified_standalone_ssh_blocks_all_ufw_commands(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    allow: tuple[str, ...],
    ss_rc: int,
    fallback_rc: int,
    fallback_out: str,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("ss -tlnp", ss_rc, "", ""),
            *ABSENT_SOCKETS,
            ("sshd -T", fallback_rc, fallback_out, ""),
        ]
    )
    results = firewall.apply_firewall(Runner(exec_fn=fake_exec), allow=allow)
    assert results[0].status is Status.FAIL
    assert "local console" in results[0].detail
    assert "ss -tlnp" in results[0].detail
    assert "sshd -T" in results[0].detail
    assert not any(call[:1] == ["ufw"] for call in fake_exec.calls)


def test_known_empty_probe_without_allow_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = CurrentPortExec(ss_out="", sshd_t_out="")
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    assert results[0].status is Status.FAIL
    assert "no live SSH listener detected" in results[0].detail
    assert "--allow" in results[0].detail
    assert "unavailable" not in results[0].detail
    # Fail closed BEFORE any ufw command (not even `ufw status`).
    assert not any(call[:1] == ["ufw"] for call in exec_fn.calls)


@pytest.mark.parametrize("allow", [(), ("22/tcp",)])
@pytest.mark.parametrize(
    ("listen_rc", "listen"),
    [(1, ""), (0, "[::]:22 (Stream) [::]:2200 (Stream)\n")],
)
def test_unverified_active_ssh_socket_blocks_all_ufw_commands(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    allow: tuple[str, ...],
    listen_rc: int,
    listen: str,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            (
                "ss -tlnp",
                0,
                'LISTEN 0 128 [::]:22 [::]:* users:(("systemd",pid=1,fd=3))\n'
                'LISTEN 0 128 [::]:2200 [::]:* users:(("sshd",pid=900,fd=4))\n',
                "",
            ),
            ("systemctl is-active ssh.socket", 0, "active\n", ""),
            ("systemctl show --property=Listen --value ssh.socket", listen_rc, listen, ""),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
        ]
    )
    results = firewall.apply_firewall(Runner(exec_fn=fake_exec), allow=allow)
    assert results[0].status is Status.FAIL
    assert "active SSH socket" in results[0].detail
    assert "local console" in results[0].detail
    assert not any(call[:1] == ["ufw"] for call in fake_exec.calls)


@pytest.mark.parametrize("allow", [(), ("22/tcp",)])
@pytest.mark.parametrize("ss_output", ["", SS_TLN_PORT_22], ids=["fallback-only", "live-sshd"])
@pytest.mark.parametrize(
    ("rc", "stderr"),
    [
        (1, "Failed to connect to bus: No such file or directory"),
        (124, "systemctl: timed out after 15.0s"),
    ],
    ids=["dbus-failure", "timeout"],
)
def test_unknown_ssh_socket_state_blocks_all_ufw_commands(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    allow: tuple[str, ...],
    ss_output: str,
    rc: int,
    stderr: str,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("ss -tlnp", 0, ss_output, ""),
            ("systemctl is-active ssh.socket", rc, "", stderr),
            ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
            ("sshd -T", 0, "port 22\n", ""),
        ]
    )
    results = firewall.apply_firewall(Runner(exec_fn=fake_exec), allow=allow)
    assert results[0].status is Status.FAIL
    assert not any(call[:1] == ["ufw"] for call in fake_exec.calls)
    assert "determine SSH socket state" in results[0].detail


def test_known_empty_probe_with_explicit_allow_proceeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = CurrentPortExec(ss_out="", sshd_t_out="")
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["22/tcp"])
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert ["ufw", "allow", "22/tcp"] in allows
    assert any(call[:2] == ["ufw", "--force"] for call in exec_fn.calls)
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22/tcp") < order.index("ufw default deny incoming")
    assert all(result.status is not Status.FAIL for result in results)


def test_forward_rule_does_not_satisfy_inbound_allow() -> None:
    status = checks.UfwStatus(
        active=True,
        default_incoming="deny",
        default_outgoing="allow",
        rules=[checks.UfwRule(to="22345/tcp", action="ALLOW FWD", source="Anywhere")],
    )
    assert not firewall._rule_present(status, "22345/tcp")


@pytest.mark.parametrize("action", ["ALLOW", "ALLOW IN"])
def test_inbound_rule_spellings_are_recognized(action: str) -> None:
    status = checks.UfwStatus(
        active=True,
        default_incoming="deny",
        default_outgoing="allow",
        rules=[checks.UfwRule(to="22345/tcp", action=action, source="Anywhere")],
    )
    assert firewall._rule_present(status, "22345/tcp")


def test_verify_fails_when_only_a_forward_rule_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    forward_only = UFW_ENABLED_CLEAN.replace("ALLOW IN", "ALLOW FWD")
    exec_fn = UfwSequenceExec(initial=forward_only, final=forward_only)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    # The forward rule must not make lhm believe the inbound rule is in place.
    assert results[-1].status is Status.FAIL
    allows = [" ".join(call) for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert "ufw allow 22345/tcp" in allows


V6_SSH = "22345/tcp (v6)             ALLOW IN    Anywhere (v6)\n"
UFW_DUAL_STACK = UFW_ENABLED_CLEAN + V6_SSH


@pytest.mark.parametrize(
    ("initial", "source"),
    [
        (UFW_ENABLED_CLEAN, "::/0"),
        (
            UFW_ENABLED_CLEAN.replace("22345/tcp                  ALLOW IN    Anywhere\n", V6_SSH),
            "0.0.0.0/0",
        ),
    ],
)
def test_repair_adds_only_missing_ssh_family(
    monkeypatch: pytest.MonkeyPatch, initial: str, source: str
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec(UFW_DUAL_STACK, initial=initial, ipv6="yes")

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert [cmd for cmd in exec_fn.calls if cmd[0] == "ufw" and cmd[1] != "status"] == [
        ["ufw", "allow", "proto", "tcp", "from", source, "to", "any", "port", "22345"]
    ]
    assert not any(cmd[0] in {"ip", "curl"} for cmd in exec_fn.calls)
    assert results[-1].status is Status.OK
    assert "IPv4 and IPv6" in results[-1].detail


@pytest.mark.parametrize(
    ("to", "action", "source"),
    [
        ("22345/tcp", "ALLOW IN", "192.0.2.0/24"),
        ("22345/tcp (v6)", "ALLOW IN", "2001:db8::/64"),
        ("192.0.2.1 22345/tcp", "ALLOW IN", "Anywhere"),
        ("22345/tcp on eth0", "ALLOW IN", "Anywhere"),
        ("22345/tcp (v6) on eth0", "ALLOW IN", "Anywhere (v6)"),
        ("22345/tcp", "ALLOW OUT", "Anywhere"),
        ("22345/tcp (v6)", "ALLOW FWD", "Anywhere (v6)"),
    ],
)
def test_scoped_or_non_inbound_rules_do_not_cover_ssh(to: str, action: str, source: str) -> None:
    status = checks.UfwStatus(active=True, rules=[checks.UfwRule(to, action, source)])
    assert not firewall._rule_present(status, firewall.SSH_RULE, 4)
    assert not firewall._rule_present(status, firewall.SSH_RULE, 6)


def test_disabled_ipv6_with_ufw_ipv6_enabled_never_starts_ufw() -> None:
    exec_fn = UfwSequenceExec(ipv6="yes")

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[-1].status is Status.FAIL
    assert "local IPv6 is disabled" in results[-1].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize(
    ("sysctls_present", "socket_errno", "expected"),
    [
        (False, errno.EAFNOSUPPORT, "disabled"),
        (False, errno.EACCES, "unknown"),
        (True, errno.EAFNOSUPPORT, "unknown"),
    ],
)
def test_missing_ipv6_sysctls_require_positive_evidence_of_kernel_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sysctls_present: bool,
    socket_errno: int,
    expected: str,
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "unknown")
    monkeypatch.setattr(
        network, "IPV6_CONF", tmp_path if sysctls_present else tmp_path / "unavailable"
    )

    def unavailable_socket(family: int, kind: int) -> None:
        raise OSError(socket_errno, "fake probe failure")

    monkeypatch.setattr(network.socket, "socket", unavailable_socket)
    assert firewall._local_ipv6_capability() == expected


@pytest.mark.parametrize(
    ("capability", "ufw_ipv6", "message"),
    [
        ("unknown", "yes", "local IPv6 capability unknown"),
        ("enabled", "no", "usable IPv6 is not managed"),
        ("enabled", "invalid", "UFW IPv6 or enabled setting unknown"),
    ],
)
def test_uncertain_or_unmanaged_ipv6_never_changes_firewall(
    monkeypatch: pytest.MonkeyPatch, capability: str, ufw_ipv6: str, message: str
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: capability)
    exec_fn = UfwSequenceExec(initial=UFW_DUAL_STACK, ipv6=ufw_ipv6)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert message in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)
    state = firewall.inspect(Runner(exec_fn=exec_fn))
    assert not state["ssh_allowed"]
    assert not any(cmd[0] in {"ip", "curl"} for cmd in exec_fn.calls)


def test_dual_stack_verify_rejects_missing_ipv6_ssh_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec(ipv6="yes")

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[-1].status is Status.FAIL
    assert "22345/tcp not allowed on IPv6" in results[-1].detail


@pytest.mark.parametrize(
    ("initial", "configured", "rc", "message"),
    [
        ("", "no", 0, "could not be verified"),
        ("Status: inactive\n", "no", 1, "could not be verified"),
        ("Status: inactive\n", "yes", 0, "could not be verified"),
        (
            UFW_ENABLED_CLEAN.replace("deny (incoming)", "allow (incoming)"),
            "yes",
            0,
            "would restart",
        ),
        (
            UFW_ENABLED_CLEAN.replace("allow (outgoing)", "reject (outgoing)"),
            "yes",
            0,
            "would restart",
        ),
    ],
)
def test_inconsistent_ufw_or_active_policy_change_stops_before_mutation(
    initial: str, configured: str, rc: int, message: str
) -> None:
    exec_fn = UfwSequenceExec(initial=initial, configured=configured, initial_rc=rc)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["80/tcp"])

    assert results[0].status is Status.FAIL
    assert message in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize(
    ("to", "source"),
    [
        ("22000:23000/tcp", "Anywhere"),
        ("22345/tcp on eth0", "192.0.2.0/24"),
        ("Anywhere", "192.0.2.0/24"),
        ("192.0.2.1 22345/tcp", "Anywhere"),
    ],
)
def test_active_blocking_rule_is_not_replaced_or_reported_as_covered(to: str, source: str) -> None:
    blocked = UFW_ENABLED_CLEAN.replace("22345/tcp ", f"{to}  DENY IN  {source}\n22345/tcp ")
    exec_fn = UfwSequenceExec(initial=blocked)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert "blocks or limits 22345/tcp" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize(
    "entry",
    [
        "-p tcp --dport 22000:23000 -j DROP",
        "-i eth0 -p tcp --dport 22345 -j DROP",
        "-j DROP",
    ],
)
@pytest.mark.parametrize("family", ["", "6"])
def test_inactive_saved_rules_hidden_from_status_stop_all_mutation(
    monkeypatch: pytest.MonkeyPatch, entry: str, family: str
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    exec_fn = UfwSequenceExec(ipv6="yes")
    exec_fn.saved[family].append(entry)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert "ordering is unsafe or unknown" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


def test_failed_persistent_staging_never_enables_ufw(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec()
    exec_fn.skip_stage = True

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[-1].status is Status.FAIL
    assert "UFW not enabled" in results[-1].detail
    assert ["ufw", "--force", "enable"] not in exec_fn.calls
    assert ["ufw", "default", "deny", "incoming"] not in exec_fn.calls


@pytest.mark.parametrize("mode", ["missing", "detached", "earlier scoped drop"])
def test_persistent_allow_without_runtime_coverage_does_not_pass_or_skip(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    exec_fn = UfwSequenceExec(UFW_DUAL_STACK, initial=UFW_DUAL_STACK, ipv6="yes")
    if mode == "detached":
        exec_fn.detach.add("6")
    elif mode == "missing":
        exec_fn.live_override["6"] = []
    else:
        exec_fn.live_override["6"] = [
            "-s fc00::/7 -p tcp -m tcp --dport 22000:23000 -j DROP",
            *exec_fn.saved["6"],
        ]
    runner = Runner(exec_fn=exec_fn)

    results = firewall.apply_firewall(runner)

    assert results[0].status is Status.FAIL
    assert "IPv6 saved and runtime" in results[0].detail
    assert not firewall.inspect(runner)["ssh_allowed"]
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize("override", ["IPV6=no\n", "IPV6=unknown\n", 'IPV6="$flag"\n'])
def test_conflicting_or_ambiguous_ipv6_override_stops_before_mutation(
    monkeypatch: pytest.MonkeyPatch, override: str
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    exec_fn = UfwSequenceExec(ipv6="yes", config_suffix=override)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert "setting unknown" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize("identity", [None, False, "", "verified-deployment"])
def test_caddy_ingress_query_and_apply_only_for_verified_routing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, identity: str | bool | None
) -> None:
    monkeypatch.setattr(caddy, "firewall_ingress_identity", lambda runner: identity)
    monkeypatch.setattr(caddy, "CADDYFILE", tmp_path / "caddy/Caddyfile")
    expected = ["80/tcp", "443/tcp"] if identity else []
    query, apply = (
        UfwSequenceExec(),
        UfwSequenceExec(
            UFW_ENABLED_CLEAN + "".join(f"{rule}  ALLOW IN  Anywhere\n" for rule in expected)
        ),
    )
    plans: list[list[str]] = []

    def confirm(plan: list[str]) -> bool:
        plans.append(plan)
        return True

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    assert cli._query_firewall(Runner(exec_fn=query))[2]["caddy_ingress"] == expected
    results = firewall.apply_firewall(Runner(exec_fn=apply))

    assert results[-1].status is Status.OK
    assert len(plans) == 1
    assert [cmd[2] for cmd in apply.calls if cmd[:2] == ["ufw", "allow"]] == [
        "22345/tcp",
        *expected,
    ]
    assert not any("delete" in cmd for cmd in apply.calls)


def test_verified_caddy_does_not_override_missing_ssh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "_caddy_ingress_identity", lambda runner: "verified")
    exec_fn = CurrentPortExec()
    assert firewall.apply_firewall(Runner(exec_fn=exec_fn))[0].status is Status.FAIL
    assert not any(cmd[0] == "ufw" for cmd in exec_fn.calls)


def test_caddy_change_at_confirmation_aborts_before_ufw_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity = "before"
    monkeypatch.setattr(firewall, "_caddy_ingress_identity", lambda runner: identity)
    monkeypatch.setattr(caddy, "CADDYFILE", tmp_path / "caddy/Caddyfile")

    def confirm(plan: list[str]) -> bool:
        nonlocal identity
        identity = "after"
        return True

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    exec_fn = UfwSequenceExec()
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert "Caddy changed" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


def test_caddy_ingress_only_fills_missing_families_under_deployment_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    monkeypatch.setattr(firewall, "_caddy_ingress_identity", lambda runner: "verified")
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    monkeypatch.setattr(caddy, "CADDYFILE", tmp_path / "caddy/Caddyfile")
    initial = UFW_DUAL_STACK + "80/tcp  ALLOW IN  Anywhere\n443/tcp (v6)  ALLOW IN  Anywhere (v6)\n"
    final = initial + "80/tcp (v6)  ALLOW IN  Anywhere (v6)\n443/tcp  ALLOW IN  Anywhere\n"
    model = UfwSequenceExec(final, initial=initial, ipv6="yes")

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["ufw", "allow"]:
            with pytest.raises(BlockingIOError), firewall.locked_target(caddy.CADDYFILE.parent):
                pytest.fail("the deployment lock was not held while adding firewall rules")
        return model(cmd, timeout)

    assert firewall.apply_firewall(Runner(exec_fn=execute))[-1].status is Status.OK
    assert [cmd for cmd in model.calls if cmd[:2] == ["ufw", "allow"]] == [
        ["ufw", "allow", "proto", "tcp", "from", "::/0", "to", "any", "port", "80"],
        ["ufw", "allow", "proto", "tcp", "from", "0.0.0.0/0", "to", "any", "port", "443"],
    ]
    already = UfwSequenceExec(final, initial=final, ipv6="yes")
    assert firewall.apply_firewall(Runner(exec_fn=already))[0].status is Status.SKIPPED
    assert not any(cmd[:2] == ["ufw", "allow"] for cmd in already.calls)


def test_saved_rule_change_during_confirmation_blocks_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exec_fn = UfwSequenceExec()

    def confirm(plan: list[str]) -> bool:
        exec_fn.saved[""].append("-j DROP")
        return True

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    assert "UFW evidence changed" in firewall.apply_firewall(Runner(exec_fn=exec_fn))[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


def test_fresh_dual_stack_accepts_real_ufw_generated_logging_chains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    exec_fn = UfwSequenceExec(UFW_DUAL_STACK, ipv6="yes")
    generated = _UFW_0362_USER_RULES.read_text(encoding="ascii")
    exec_fn.user_files[""] = generated
    exec_fn.user_files["6"] = generated.replace("ufw-", "ufw6-").replace("0.0.0.0/0", "::/0")

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[-1].status is Status.OK
    assert ["ufw", "--force", "enable"] in exec_fn.calls


def test_custom_processing_in_generated_logging_chain_stops_active_apply() -> None:
    exec_fn = UfwSequenceExec(initial=UFW_ENABLED_CLEAN)
    generated = _UFW_0362_USER_RULES.read_text(encoding="ascii")
    exec_fn.user_files[""] = generated.replace(
        "### LOGGING ###", "### LOGGING ###\n-A ufw-before-logging-output -j DROP"
    )

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert "unsafe or unknown" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize("entry", ["-j DROP", "-p tcp --sport 22345 -j REJECT"])
@pytest.mark.parametrize("active", [False, True])
def test_preceding_before_output_block_never_passes(entry: str, active: bool) -> None:
    initial = UFW_ENABLED_CLEAN if active else "Status: inactive\n"
    exec_fn = UfwSequenceExec(initial=initial)
    chain = [entry, *exec_fn.before_reply]
    if active:
        exec_fn.live_before_reply = chain
    else:
        exec_fn.before_reply = chain
    runner = Runner(exec_fn=exec_fn)

    results = firewall.apply_firewall(runner)

    assert results[0].status is Status.FAIL
    assert "unsafe or unknown" in results[0].detail
    assert not firewall.inspect(runner)["ssh_allowed"]
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize("builtins", ["", "MANAGE_BUILTINS=yes\n", "MANAGE_BUILTINS=maybe\n"])
def test_first_enable_requires_explicitly_safe_builtins(builtins: str) -> None:
    exec_fn = UfwSequenceExec(builtins=builtins)

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize(
    ("rc", "stderr", "can_enable"),
    [
        (0, "", False),
        (1, "Permission denied", False),
        (1, "Address family not supported by protocol", True),
    ],
)
def test_ipv4_only_first_enable_when_ipv6_filter_cannot_run(
    monkeypatch: pytest.MonkeyPatch, rc: int, stderr: str, can_enable: bool
) -> None:
    monkeypatch.setattr(firewall_ufw, "ipv6_filter_unavailable", _IPV6_FILTER_UNAVAILABLE)
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)

    def unavailable_socket(family: int, kind: int) -> None:
        raise OSError(errno.EAFNOSUPPORT, "fake probe failure")

    monkeypatch.setattr(firewall_ufw.socket, "socket", unavailable_socket)
    model = UfwSequenceExec()

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[0] == "ip6tables":
            assert cmd == ["ip6tables", "-w", "2", "-L", "INPUT", "-n"]
            return subprocess.CompletedProcess(cmd, rc, "", stderr)
        return model(cmd, timeout)

    results = firewall.apply_firewall(Runner(exec_fn=execute))

    assert (["ufw", "--force", "enable"] in model.calls) is can_enable
    if can_enable:
        assert results[-1].status is Status.OK
        assert not model.saved["6"]
    else:
        assert results[0].status is Status.FAIL
        assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in model.calls)


@pytest.mark.parametrize("ports_after", [[22], None])
def test_repoll_of_ssh_listener_ports_is_locked_and_rejects_drift(
    monkeypatch: pytest.MonkeyPatch, ports_after: list[int] | None
) -> None:
    confirmed = False

    def confirm(plan: list[str]) -> bool:
        nonlocal confirmed
        confirmed = True
        return True

    def current(runner: Runner) -> list[int] | None:
        if not confirmed:
            return [22345]
        with pytest.raises(BlockingIOError), firewall.locked_target(firewall.UFW_LOCK_TARGET):
            pytest.fail("firewall writer lock missing at SSH re-probe")
        return ports_after

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    monkeypatch.setattr(checks, "current_ssh_ports", current)
    exec_fn = UfwSequenceExec()

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert "SSH listener ports changed" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


def test_firewall_writer_lock_is_held_through_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    model = UfwSequenceExec()

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["ufw", "allow"] or (model.active and cmd[0] == "iptables"):
            with pytest.raises(BlockingIOError), firewall.locked_target(firewall.UFW_LOCK_TARGET):
                pytest.fail("firewall writer lock released before verification")
        return model(cmd, timeout)

    assert firewall.apply_firewall(Runner(exec_fn=execute))[-1].status is Status.OK


def test_pending_ssh_transaction_stops_before_ufw_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    pending = ssh_watchdog.Pending("f" * 32, 1, "awaiting-confirm", {})
    monkeypatch.setattr(ssh_watchdog, "current", lambda: pending)
    model = UfwSequenceExec()

    results = firewall.apply_firewall(Runner(exec_fn=model))

    assert results[0].status is Status.FAIL
    assert "still pending" in results[0].detail
    assert model.calls == []


def test_ssh_transaction_start_during_confirmation_stops_under_ordered_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    confirmed = False

    def confirm(plan: list[str]) -> bool:
        nonlocal confirmed
        confirmed = True
        return True

    def current() -> ssh_watchdog.Pending | None:
        if not confirmed:
            return None
        with pytest.raises(BlockingIOError), firewall.locked_target(ssh.SSHD_DROPIN):
            pytest.fail("watchdog pending check ran without the SSH transaction lock")
        return ssh_watchdog.Pending("f" * 32, 1, "armed", {})

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    monkeypatch.setattr(ssh_watchdog, "current", current)
    model = UfwSequenceExec()

    assert "still pending" in firewall.apply_firewall(Runner(exec_fn=model))[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in model.calls)


def test_ssh_writer_contending_during_confirmation_stops_ufw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    model = UfwSequenceExec()
    with firewall.locked_target(ssh.SSHD_DROPIN):
        results = firewall.apply_firewall(Runner(exec_fn=model))
    assert results[0].status is Status.FAIL
    assert "lock unavailable" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in model.calls)


def test_ssh_lock_held_while_ufw_writes_and_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    model = UfwSequenceExec()

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["ufw", "allow"] or (model.active and cmd[0] == "iptables"):
            with pytest.raises(BlockingIOError), firewall.locked_target(ssh.SSHD_DROPIN):
                pytest.fail("SSH transaction could start during UFW write or verification")
        return model(cmd, timeout)

    assert firewall.apply_firewall(Runner(exec_fn=execute))[-1].status is Status.OK


def test_firewall_dry_run_does_not_read_ssh_marker_or_create_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unexpected_probe() -> None:
        pytest.fail("dry-run must not probe the SSH pending marker")

    monkeypatch.setattr(ssh_watchdog, "current", unexpected_probe)
    model = UfwSequenceExec()
    results = firewall.apply_firewall(Runner(dry_run=True, exec_fn=model))

    assert all(result.status is Status.PLANNED for result in results)
    assert model.calls == []
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("config_file", ["defaults", "ufw.conf"])
def test_first_enable_refuses_sysctl_that_disables_ipv6(
    monkeypatch: pytest.MonkeyPatch, config_file: str
) -> None:
    setting = "IPT_SYSCTL=/etc/ufw/custom-sysctl.conf\n"
    exec_fn = UfwSequenceExec(
        builtins="MANAGE_BUILTINS=no\n" + (setting if config_file == "defaults" else ""),
        config_suffix=setting if config_file == "ufw.conf" else "",
    )

    def sysctl(path: Path) -> str:
        assert path == Path("/etc/ufw/custom-sysctl.conf")
        return "net.ipv6.conf.all.disable_ipv6=1\n"

    monkeypatch.setattr(firewall_ufw, "_read_trusted_sysctl", sysctl)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert results[0].status is Status.FAIL
    assert "IPT_SYSCTL" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize(
    "setting",
    [
        'IPT_SYSCTL="/etc/ufw/one.conf /etc/ufw/two.conf"\n',
        "IPT_SYSCTL=/etc/ufw/../sysctl.conf\n",
        'IPT_SYSCTL="$SYSTEM_SYSCTL"\n',
        "IPT_SYSCTL=sysctl.conf\n",
        "# comment\rIPT_SYSCTL=/etc/ufw/local.conf\nIPT_SYSCTL=/etc/ufw/sysctl.conf\r\n",
    ],
)
def test_ambiguous_sysctl_path_stops_before_file_read_or_mutation(
    monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    def unexpected_read(path: Path) -> str:
        pytest.fail(f"attempted to read an ambiguous path: {path}")

    monkeypatch.setattr(firewall_ufw, "_read_trusted_sysctl", unexpected_read)
    exec_fn = UfwSequenceExec(config_suffix=setting)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))
    assert results[0].status is Status.FAIL
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


def test_conflicting_sysctl_assignments_stop_without_reading_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_read(path: Path) -> str:
        pytest.fail(f"attempted to read a contradictory path: {path}")

    monkeypatch.setattr(firewall_ufw, "_read_trusted_sysctl", unexpected_read)
    exec_fn = UfwSequenceExec(
        builtins="MANAGE_BUILTINS=no\nIPT_SYSCTL=/etc/ufw/sysctl.conf\n",
        config_suffix="IPT_SYSCTL=/etc/ufw/local.conf\n",
    )
    assert firewall.apply_firewall(Runner(exec_fn=exec_fn))[0].status is Status.FAIL
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)


@pytest.mark.parametrize("mode", ["baseline", "comment-only", "blank", "untrusted", "modified"])
def test_first_enable_accepts_only_verified_baseline_or_no_directives(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "ufw-0.36.2-sysctl.conf"
    stock = fixture.read_text(encoding="ascii")
    text = {
        "baseline": stock,
        "comment-only": "# not active\n; net.ipv6.conf.all.disable_ipv6=1\n",
        "blank": "",
        "untrusted": None,
        "modified": stock + "\nnet.ipv6.conf.all.disable_ipv6=1\n",
    }[mode]
    path = "/etc/ufw/local.conf" if mode == "comment-only" else "/etc/ufw/sysctl.conf"
    monkeypatch.setattr(firewall, "confirm_once", lambda plan: True)
    reads: list[Path] = []

    def sysctl(requested: Path) -> str | None:
        reads.append(requested)
        return text

    monkeypatch.setattr(firewall_ufw, "_read_trusted_sysctl", sysctl)
    exec_fn = UfwSequenceExec(config_suffix=f"IPT_SYSCTL={path}\n")
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    if mode in {"untrusted", "modified"}:
        assert results[0].status is Status.FAIL
        assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)
        assert reads == [Path(path)]
    else:
        assert results[-1].status is Status.OK
        assert ["ufw", "--force", "enable"] in exec_fn.calls
        assert reads == [Path(path), Path(path)]


def test_changed_sysctl_file_is_rechecked_under_locks_before_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    confirmed = False

    def confirm(plan: list[str]) -> bool:
        nonlocal confirmed
        confirmed = True
        return True

    def sysctl(path: Path) -> str:
        if not confirmed:
            return "# benign before confirmation\n"
        with pytest.raises(BlockingIOError), firewall.locked_target(firewall.UFW_LOCK_TARGET):
            pytest.fail("startup sysctl recheck was not locked")
        return "net.ipv6.conf.all.disable_ipv6=1\n"

    monkeypatch.setattr(firewall, "confirm_once", confirm)
    monkeypatch.setattr(firewall_ufw, "_read_trusted_sysctl", sysctl)
    exec_fn = UfwSequenceExec(config_suffix="IPT_SYSCTL=/etc/ufw/local.conf\n")

    results = firewall.apply_firewall(Runner(exec_fn=exec_fn))

    assert "UFW evidence changed" in results[0].detail
    assert not any(cmd[0] == "ufw" and cmd[1] != "status" for cmd in exec_fn.calls)
