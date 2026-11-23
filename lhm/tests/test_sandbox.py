import subprocess
from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import sandbox


@pytest.fixture
def unit_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sandbox, "UNIT_DIR", tmp_path / "systemd")
    return tmp_path / "systemd"


def test_whitelist_refuses_unknown_service(fake_exec: Any, unit_dir: Path) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = sandbox.apply_sandbox(runner, services=["docker"])
    assert results[0].status is Status.FAIL
    assert "ssh, nginx, fail2ban" in results[0].detail
    assert fake_exec.calls == []
    assert not unit_dir.exists()


def test_whitelist_map_is_complete() -> None:
    assert set(sandbox.ALLOWED) == {"ssh", "nginx", "fail2ban"}
    ssh = dict(sandbox.WHITELIST["ssh"])
    assert ssh["ProtectSystem"] == "strict"
    # read-only, not yes: sshd must read /home/*/.ssh/authorized_keys.
    assert ssh["ProtectHome"] == "read-only"
    assert ssh["ReadWritePaths"] == "/etc/ssh"
    nginx = dict(sandbox.WHITELIST["nginx"])
    assert nginx["ProtectSystem"] == "full"  # documented deviation for nginx
    assert nginx["RuntimeDirectory"] == "nginx"
    assert "ProtectHome" not in nginx
    assert nginx["ReadWritePaths"] == "/var/log/nginx /var/lib/nginx"
    jail = dict(sandbox.WHITELIST["fail2ban"])
    assert jail["NoNewPrivileges"] == "yes"
    assert jail["ProtectSystem"] == "full"


def test_dropin_content(fake_exec: Any, unit_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(
        ("systemctl show -p LoadState --value ssh.service", 0, "loaded\n", "")
    )
    fake_exec.responses.append(
        (
            "systemd-analyze security ssh.service",
            0,
            "  Overall exposure level for ssh.service: 4.0 OK 🙂\n",
            "",
        )
    )
    results = sandbox.apply_sandbox(Runner(exec_fn=fake_exec), services=["ssh"])
    path = unit_dir / "ssh.service.d" / "99-lhm-sandbox.conf"
    text = path.read_text(encoding="utf-8")
    assert "[Service]" in text
    assert "ProtectSystem=strict" in text
    assert "ProtectHome=read-only" in text
    assert "NoNewPrivileges=yes" in text
    assert "ReadWritePaths=/etc/ssh" in text
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "systemctl daemon-reload" in executed
    assert "systemctl restart ssh.service" in executed
    verify = next(r for r in results if r.name.startswith("verify"))
    assert verify.status is Status.OK
    assert "4.0 OK" in verify.detail


def test_missing_unit_is_skipped_with_warning(
    fake_exec: Any,
    unit_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sandbox, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(
        ("systemctl show -p LoadState --value nginx.service", 0, "not-found\n", "")
    )
    fake_exec.responses.append(
        ("systemctl show -p LoadState --value ssh.service", 0, "loaded\n", "")
    )
    results = sandbox.apply_sandbox(Runner(exec_fn=fake_exec), services=["nginx", "ssh"])
    skip = next(r for r in results if r.name == "skip nginx.service")
    assert skip.status is Status.SKIPPED
    assert "not installed" in capsys.readouterr().out
    executed = [" ".join(call) for call in fake_exec.calls]
    assert not any(call.startswith("systemctl restart nginx") for call in executed)
    assert "systemctl restart ssh.service" in executed


class RestartFailingExec:
    """Fails restarting ssh.service the first time, then accepts the rollback restart."""

    def __init__(self, fail_times: int = 1) -> None:
        self.calls: list[list[str]] = []
        self.remaining_failures = fail_times

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:4] == ["systemctl", "show", "-p", "LoadState"]:
            return subprocess.CompletedProcess(cmd, 0, "loaded\n", "")
        if cmd == ["systemctl", "restart", "ssh.service"] and self.remaining_failures > 0:
            self.remaining_failures -= 1
            return subprocess.CompletedProcess(cmd, 1, "", "Job failed: exit code 226/NAMESPACE")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_restart_failure_auto_rolls_back_dropin(
    unit_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox, "confirm_twice", lambda plan: True)
    exec_fn = RestartFailingExec()
    results = sandbox.apply_sandbox(Runner(exec_fn=exec_fn), services=["ssh"])
    restart = next(r for r in results if r.name == "restart ssh.service")
    assert restart.status is Status.FAIL
    assert "removed the new drop-in" in restart.detail
    assert not (unit_dir / "ssh.service.d" / "99-lhm-sandbox.conf").exists()
    executed = [" ".join(call) for call in exec_fn.calls]
    # Rollback is followed by daemon-reload + a restart of the restored unit.
    assert executed.count("systemctl daemon-reload") == 2
    assert executed.count("systemctl restart ssh.service") == 2


def test_restart_failure_restores_existing_dropin(
    unit_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox, "confirm_twice", lambda plan: True)
    path = unit_dir / "ssh.service.d" / "99-lhm-sandbox.conf"
    path.parent.mkdir(parents=True)
    path.write_text("# old sandbox\n", encoding="utf-8")
    results = sandbox.apply_sandbox(Runner(exec_fn=RestartFailingExec()), services=["ssh"])
    restart = next(r for r in results if r.name == "restart ssh.service")
    assert restart.status is Status.FAIL
    assert "restored" in restart.detail
    assert path.read_text(encoding="utf-8") == "# old sandbox\n"


def test_rollback_delete_prints_red_minus(unit_dir: Path) -> None:
    import io

    from lhm.core import colors

    path = unit_dir / "ssh.service.d" / "99-lhm-sandbox.conf"
    path.parent.mkdir(parents=True)
    path.write_text("[Service]\n", encoding="utf-8")
    stream = io.StringIO()
    colors.configure("always")
    colors.set_output(stream)
    try:
        assert sandbox._rollback_dropin("ssh") == "removed the new drop-in"
    finally:
        colors.set_output(None)
    assert stream.getvalue() == f"\033[31m- {path}\033[0m\n"
    assert not path.exists()
