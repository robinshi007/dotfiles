import subprocess
from pathlib import Path
from typing import Any

import pytest

from lhm import cli
from lhm.core.report import Status, StepResult
from lhm.core.runner import Runner
from lhm.modules import APPLY_ALL_ORDER, MODULES
from lhm.modules import backup as backup_module

KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
)


def test_apply_all_order_matches_design() -> None:
    assert APPLY_ALL_ORDER == (
        "updates",
        "ssh",
        "firewall",
        "fail2ban",
        "sysctl",
        "sandbox",
        "logging",
        "audit",
        "alert",
        "backup",
    )
    assert "services" not in APPLY_ALL_ORDER
    assert all(module.implemented for module in MODULES)


def test_apply_all_runs_modules_in_order(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Recorded commands must show updates before ssh before firewall."""
    from lhm.modules import alert, audit, fail2ban, logging, sandbox, ssh, sysctl

    # Redirect every file target into tmp_path: the test must never touch /etc.
    root = tmp_path / "etc"
    monkeypatch.setattr("lhm.modules.updates.APT_CONF", root / "apt.conf.d" / "51-lhm")
    monkeypatch.setattr(fail2ban, "JAIL_DROPIN", root / "fail2ban" / "jail.d" / "99-lhm.local")
    monkeypatch.setattr(fail2ban, "CADDY_FILTER", root / "fail2ban" / "filter.d" / "caddy-lhm.conf")
    monkeypatch.setattr(sysctl, "SYSCTL_DROPIN", root / "sysctl.d" / "99-lhm.conf")
    monkeypatch.setattr(sandbox, "UNIT_DIR", root / "systemd")
    monkeypatch.setattr(logging, "JOURNALD_DROPIN", root / "journald.conf.d" / "99-lhm.conf")
    monkeypatch.setattr(logging, "LOGROTATE_CONF", root / "logrotate.d" / "lhm-audit")
    journal_dir = tmp_path / "journal"
    journal_dir.mkdir()
    monkeypatch.setattr(logging, "JOURNAL_DIR", journal_dir)
    monkeypatch.setattr(audit, "RULES_DROPIN", root / "audit" / "rules.d" / "99-lhm.rules")
    monkeypatch.setattr(alert, "SCRIPT", root / "lhm-alert.sh")
    monkeypatch.setattr(alert, "TIMER_UNIT", root / "systemd" / "lhm-alert.timer")
    monkeypatch.setattr(alert, "SERVICE_UNIT", root / "systemd" / "lhm-alert.service")
    monkeypatch.setattr(backup_module, "SCRIPT", root / "lhm-backup.sh")
    monkeypatch.setattr(backup_module, "SERVICE_UNIT", root / "systemd" / "lhm-backup.service")
    monkeypatch.setattr(backup_module, "TIMER_UNIT", root / "systemd" / "lhm-backup.timer")
    # Never write into the real /home or /etc/ssh during a test.
    home = tmp_path / "home"
    (home / "testadmin" / ".ssh").mkdir(parents=True)
    (home / "testadmin" / ".ssh" / "authorized_keys").write_text(
        KEY + " testadmin@old\n", encoding="utf-8"
    )
    monkeypatch.setattr(ssh, "HOME_ROOT", home)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", root / "ssh" / "99-lhm.conf")
    seen: list[str] = []
    configured: set[str] = set()

    def exec_fn(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        seen.append(" ".join(cmd))
        if cmd[:3] == ["ufw", "status", "verbose"]:
            if "ufw" not in configured:
                return subprocess.CompletedProcess(cmd, 1, "", "ERROR: not configured")
            out = (
                "Status: active\n"
                "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                "To                         Action      From\n"
                "--                         ------      ----\n"
                "22345/tcp                  ALLOW       Anywhere\n"
            )
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if cmd[:3] == ["ufw", "--force", "enable"]:
            configured.add("ufw")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:1] == ["fail2ban-client"]:
            if cmd[1:2] == ["-d"]:
                dump = "['set', 'sshd', 'bantime.increment', True]\n"
                return subprocess.CompletedProcess(cmd, 0, dump, "")
            if cmd[1:2] == ["get"]:
                return subprocess.CompletedProcess(cmd, 0, "28800\n", "")
            out = "Status for the jail: sshd\n|- Currently banned: 0\n"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if cmd[:1] == [str(root / "lhm-backup.sh")]:
            target = tmp_path / "backups"
            target.mkdir(parents=True, exist_ok=True)
            archive = target / "lhm-backup-20261122T020000Z.tar.gz"
            archive.write_bytes(b"archive")
            archive.with_name(archive.name + ".sha256").write_text("x\n", encoding="utf-8")
        if cmd[:4] == ["systemctl", "show", "-p", "LoadState"]:
            return subprocess.CompletedProcess(cmd, 0, "loaded\n", "")
        if cmd == ["ss", "-tlnp"]:
            # A hardened host: sshd already listens on 22345 (anti-lockout probe).
            out = (
                "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
                'LISTEN 0      128          0.0.0.0:22345      0.0.0.0:*     '
                'users:(("sshd",pid=1,fd=3))\n'
            )
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if cmd[:2] == ["dpkg-query", "-W"]:
            return subprocess.CompletedProcess(cmd, 1, "", "not installed")
        if cmd[:2] == ["sysctl", "-n"]:
            wanted = {"kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1"}
            return subprocess.CompletedProcess(cmd, 0, wanted.get(cmd[2], "1") + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "active\n", "")

    key = tmp_path / "id.pub"
    key.write_text(KEY + " robin@test\n", encoding="utf-8")
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=exec_fn, **kw))
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    rc = cli.main(
        [
            "apply",
            "all",
            "--ssh-user",
            "testadmin",
            "--key",
            str(key),
            "--webhook",
            "https://hooks.example/x",
            "--target",
            str(tmp_path / "backups"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    order = [f"== {name} ==" for name in APPLY_ALL_ORDER]
    positions = [out.index(header) for header in order]
    assert positions == sorted(positions)
    assert "== services ==" not in out
    joined = "\n".join(seen)
    assert "apt-get update" in joined
    assert "getent passwd testadmin" in joined
    # Order: updates -> ssh -> firewall (ufw allow 22345/tcp first).
    assert joined.index("apt-get update") < joined.index("getent passwd testadmin")
    assert joined.index("getent passwd testadmin") < joined.index("ufw allow 22345/tcp")
    # Never runs the interactive cleanup-services listing (the caddy probe in
    # fail2ban uses list-unit-files for one specific unit only).
    assert "list-unit-files --state=enabled" not in joined


def test_apply_all_requires_webhook_and_target(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    assert cli.main(["apply", "all", "--dry-run"]) == 2
    assert "needs --webhook" in capsys.readouterr().err


def test_apply_all_requires_ssh_user_with_key(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    rc = cli.main(
        ["apply", "all", "--dry-run", "--webhook", "https://x/y", "--target", "/tmp/b"]
    )
    assert rc == 0
    assert "ssh skipped" in capsys.readouterr().err


def test_apply_all_stops_on_first_fail(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    def fake_apply(self: Any, runner: Runner, **options: object) -> list[StepResult]:
        calls.append(self.name)
        if self.name == "firewall":
            return [StepResult("firewall", Status.FAIL, "boom")]
        return [StepResult(self.name, Status.OK)]

    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    for module in MODULES:
        monkeypatch.setattr(type(module), "apply", fake_apply, raising=False)
    rc = cli.main(
        [
            "apply",
            "all",
            "--webhook",
            "https://x/y",
            "--target",
            "/tmp/b",
        ]
    )
    assert rc == 1
    assert calls == ["updates", "firewall"]
    assert "stopped at 'firewall'" in capsys.readouterr().err


def test_query_sysctl_and_audit(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.modules import sysctl

    monkeypatch.setattr(sysctl, "SYSCTL_DROPIN", Path("/nonexistent/99-lhm.conf"))
    fake_exec.responses.append(("auditctl -s", 0, "enabled 2\nfailure 1\n", ""))
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    assert cli.main(["query", "sysctl", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"dropin_current": false' in out
    assert cli.main(["query", "audit", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"immutable": true' in out
    assert '"enabled 2' in out


def test_check_lists_all_eleven_areas_without_unknown(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    for module in MODULES:
        assert module.name in out
    assert "UNKNOWN" not in out


def test_apply_alert_requires_webhook_flag() -> None:
    with pytest.raises(SystemExit):
        cli.main(["apply", "alert"])
    with pytest.raises(SystemExit):
        cli.main(["apply", "backup"])


def test_apply_all_abort_stops_and_exits_3(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    def fake_apply(self: Any, runner: Runner, **options: object) -> list[StepResult]:
        calls.append(self.name)
        if self.name == "firewall":
            return [StepResult("firewall", Status.ABORTED, "aborted; no changes made")]
        return [StepResult(self.name, Status.OK)]

    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    for module in MODULES:
        monkeypatch.setattr(type(module), "apply", fake_apply, raising=False)
    rc = cli.main(["apply", "all", "--webhook", "https://x/y", "--target", "/tmp/b"])
    assert rc == cli.EXIT_ABORT
    assert calls == ["updates", "firewall"]
    assert "aborted at 'firewall'" in capsys.readouterr().err
