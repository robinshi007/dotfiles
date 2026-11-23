import subprocess
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import firewall

UFW_ENABLED_CLEAN = """Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22345/tcp                  ALLOW IN    Anywhere
"""


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
    """First ``ufw status`` reports inactive, later ones report the final state."""

    def __init__(self, final: str = UFW_ENABLED_CLEAN) -> None:
        self.calls: list[list[str]] = []
        self.status_calls = 0
        self.final = final

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:3] == ["ufw", "status", "verbose"]:
            self.status_calls += 1
            body = "Status: inactive\n" if self.status_calls == 1 else self.final
            return subprocess.CompletedProcess(cmd, 0, body, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


UFW_ENABLED_WITH_80 = UFW_ENABLED_CLEAN + "80/tcp                     ALLOW IN    Anywhere\n"


def test_apply_order_and_skip_existing_ssh_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
    exec_fn = UfwSequenceExec(UFW_ENABLED_WITH_80)
    results = firewall.apply_firewall(Runner(exec_fn=exec_fn), allow=["80/tcp"])
    mutating = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert mutating == [["ufw", "allow", "22345/tcp"], ["ufw", "allow", "80/tcp"]]
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22345/tcp") < order.index("ufw default deny incoming")
    assert order.index("ufw allow 80/tcp") < order.index("ufw default deny incoming")
    assert order.index("ufw --force enable") > order.index("ufw default allow outgoing")
    assert results[-1].status is Status.OK


def test_already_configured_is_a_noop(fake_exec: Any) -> None:
    fake_exec.responses.append(("ufw status verbose", 0, UFW_ENABLED_CLEAN, ""))
    results = firewall.apply_firewall(Runner(exec_fn=fake_exec))
    assert results[0].status is Status.SKIPPED
    ufw_calls = [call for call in fake_exec.calls if call[:1] == ["ufw"]]
    assert [call[:2] for call in ufw_calls] == [["ufw", "status"]]


def test_existing_rules_are_not_reapplied(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            (
                "ufw status verbose",
                0,
                "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
                "\nTo   Action   From\n--   ------   ----\n22345/tcp  ALLOW IN  Anywhere\n",
                "",
            ),
        ]
    )
    firewall.apply_firewall(Runner(exec_fn=fake_exec), allow=["80/tcp"])
    mutating = [
        " ".join(call)
        for call in fake_exec.calls
        if call[:1] == ["ufw"] and "status" not in call
    ]
    assert "ufw allow 22345/tcp" not in mutating
    assert "ufw allow 80/tcp" in mutating


def test_verify_fails_when_ufw_inactive(fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("ufw status verbose", 0, "Status: inactive\n", ""),
            ("ufw allow", 0, "", ""),
            ("ufw --force enable", 0, "", ""),
            ("ufw status verbose", 0, "Status: inactive\n", ""),
        ]
    )
    results = firewall.apply_firewall(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.FAIL
    assert "not active" in results[-1].detail


class TimeoutAwareExec:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.timeouts.append(timeout)
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


class CurrentPortExec:
    """sshd still on port 22 (apply all with only ssh-user done)."""

    def __init__(self, ss_out: str = "", sshd_t_out: str = "") -> None:
        self.calls: list[list[str]] = []
        self.ss_out = ss_out
        self.sshd_t_out = sshd_t_out
        self.status_calls = 0

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:3] == ["ufw", "status", "verbose"]:
            self.status_calls += 1
            if self.status_calls == 1:
                return subprocess.CompletedProcess(cmd, 0, "Status: inactive\n", "")
            return subprocess.CompletedProcess(
                cmd,
                0,
                "Status: active\n"
                "Default: deny (incoming), allow (outgoing), disabled (routed)\n\n"
                "To   Action   From\n--   ------   ----\n"
                "22345/tcp  ALLOW IN  Anywhere\n22/tcp  ALLOW IN  Anywhere\n",
                "",
            )
        if cmd == ["ss", "-tlnp"]:
            return subprocess.CompletedProcess(cmd, 0, self.ss_out, "")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, self.sshd_t_out, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_current_ssh_port_is_allowed_before_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server still on port 22 must keep 22/tcp open before default deny."""
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
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
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
    exec_fn = CurrentPortExec(ss_out="", sshd_t_out="port 22\n")
    firewall.apply_firewall(Runner(exec_fn=exec_fn))
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert ["ufw", "allow", "22/tcp"] in allows
    order = [" ".join(call) for call in exec_fn.calls]
    assert order.index("ufw allow 22/tcp") < order.index("ufw default deny incoming")


def test_same_port_is_not_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall, "confirm_twice", lambda plan: True)
    exec_fn = CurrentPortExec(
        ss_out='LISTEN 0 128 0.0.0.0:22345 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
    )
    firewall.apply_firewall(Runner(exec_fn=exec_fn))
    allows = [call for call in exec_fn.calls if call[:2] == ["ufw", "allow"]]
    assert allows == [["ufw", "allow", "22345/tcp"]]
