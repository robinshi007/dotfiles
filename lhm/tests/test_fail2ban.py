from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import fail2ban

JAIL_STATUS = """Status for the jail: sshd
|- Filter
|  |- Currently failed: 3
|  |- Total failed:     12
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 1
   |- Total banned:     4
   `- Banned IP list:   203.0.113.9
"""


@pytest.fixture
def jail_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "fail2ban" / "jail.local"
    monkeypatch.setattr(fail2ban, "JAIL_LOCAL", target)
    return target


def test_template_renders_ssh_port_22345(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fail2ban.socket, "gethostname", lambda: "box1")
    text = fail2ban.desired_conf(bantime="2h", findtime="5m", maxretry="3")
    assert "port = 22345" in text
    assert "bantime  = 2h" in text
    assert "findtime = 5m" in text
    assert "maxretry = 3" in text
    assert "sender = fail2ban@box1" in text
    assert "backend = systemd" in text


def test_invalid_duration_is_refused(fake_exec: Any, jail_path: Path) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), bantime="soon")
    assert results[0].status is Status.FAIL
    assert "invalid bantime" in results[0].detail
    assert fake_exec.calls == []
    assert not jail_path.exists()


def test_dry_run_records_no_commands(fake_exec: Any, jail_path: Path) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = fail2ban.apply_fail2ban(runner)
    assert fake_exec.calls == []
    assert not jail_path.exists()
    assert [r.status for r in results] == [Status.PLANNED, Status.PLANNED, Status.PLANNED]
    planned = [" ".join(cmd) for cmd in runner.planned]
    assert any("apt-get install" in cmd and "fail2ban" in cmd for cmd in planned)
    assert "systemctl enable --now fail2ban" in planned


def test_apply_installs_writes_and_verifies(
    fake_exec: Any, jail_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query -W -f=${Status} fail2ban", 1, "", "not installed"),
            ("dpkg-query -W -f=${Status} nftables", 1, "", "not installed"),
            ("fail2ban-client status sshd", 0, JAIL_STATUS, ""),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["install fail2ban nftables"] is Status.CHANGED
    assert names["write " + str(jail_path)] is Status.CHANGED
    assert names["enable --now fail2ban"] is Status.CHANGED
    assert results[-1].status is Status.OK
    assert "currently banned: 1" in results[-1].detail
    content = jail_path.read_text(encoding="utf-8")
    assert "port = 22345" in content
    executed = [" ".join(call) for call in fake_exec.calls]
    assert any("apt-get install" in call and "nftables" in call for call in executed)
    assert "systemctl enable --now fail2ban" in executed


def test_second_run_is_idempotent(
    fake_exec: Any, jail_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jail_path.parent.mkdir(parents=True)
    jail_path.write_text(fail2ban.desired_conf(), encoding="utf-8")
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client status sshd", 0, JAIL_STATUS, ""),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    statuses = [r.status for r in results]
    assert statuses.count(Status.SKIPPED) == 3
    assert results[-1].status is Status.OK
    assert not (jail_path.parent / "jail.local.bak").exists()
    executed = [" ".join(call) for call in fake_exec.calls]
    assert not any("apt-get install" in call for call in executed)
    assert "systemctl enable --now fail2ban" not in executed


def test_verify_fails_without_sshd_jail(
    fake_exec: Any, jail_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client status sshd", 1, "", "Sorry but the jail 'sshd' does not exist"),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.FAIL
    assert "does not exist" in results[-1].detail
