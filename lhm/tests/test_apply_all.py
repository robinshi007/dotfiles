import base64
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from lhm import cli
from lhm.core import network
from lhm.core.apt_security import Release
from lhm.core.report import Status, StepResult
from lhm.core.runner import Runner
from lhm.modules import APPLY_ALL_ORDER, MODULES
from lhm.modules import backup as backup_module

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


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
    assert "caddy" not in APPLY_ALL_ORDER
    assert all(module.implemented for module in MODULES)


@pytest.mark.parametrize("pending", [False, True])
def test_apply_all_runs_modules_in_order(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    pending: bool,
) -> None:
    """Recorded commands must show updates before ssh before firewall."""
    from lhm.modules import (
        alert,
        audit,
        caddy,
        fail2ban,
        firewall,
        firewall_ufw,
        logging,
        sandbox,
        ssh,
        sysctl,
        updates,
    )

    # Redirect every file target into tmp_path: the test must never touch /etc.
    root = tmp_path / "etc"
    root.mkdir(mode=0o700)
    release = Release("debian", "bookworm", "amd64")
    security_site = "security.debian.org"
    pattern = release.pattern(security_site)
    apt_conf = root / "apt.conf.d" / "51-lhm"
    apt_conf.parent.mkdir(parents=True)
    apt_conf.write_text(updates.desired_conf((pattern,)), encoding="utf-8")
    monkeypatch.setattr(updates, "APT_CONF", apt_conf)
    installed_packages = {updates.PACKAGE, *updates.TOOLS, release.keyring_package}

    def apt_security(runner: Runner) -> SimpleNamespace:
        # The updates tests cover authenticating APT; this test focuses on module order.
        return SimpleNamespace(
            runner=runner,
            release=release,
            components=("main",),
            legacy_https=False,
            sources=lambda: {release.uri},
            require_keyring=lambda: None,
            refresh=lambda: runner.run(["apt-get", "update"]),
            verify=lambda _uris: (security_site,),
        )

    monkeypatch.setattr(updates, "AptSecurity", apt_security)
    # The updates tests cover the trusted helper and host timer; do not touch them here.
    monkeypatch.setattr(updates, "configure_timer", lambda _runner: False)
    monkeypatch.setattr(updates, "preflight_timer", lambda _runner: None)
    (root / "caddy").mkdir(mode=0o700)
    (root / "fail2ban").mkdir(mode=0o700)
    monkeypatch.setattr(caddy, "CADDYFILE", root / "caddy" / "Caddyfile")
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
    # Model the account and helper result without touching a home directory.
    home = tmp_path / "home"
    account_home = home / "testadmin"
    installed_key = KEY + " robin@test\n"
    monkeypatch.setattr(ssh, "HOME_ROOT", home)
    (root / "ssh").mkdir(mode=0o700)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", root / "ssh" / "99-lhm.conf")
    marker = ssh.ssh_watchdog.Pending("f" * 32, 1, "awaiting-confirm", {}) if pending else None
    monkeypatch.setattr(ssh.ssh_watchdog, "current", lambda: marker)
    monkeypatch.setattr(network, "read_ipv6_capability", lambda: "enabled")
    monkeypatch.setattr(firewall, "UFW_LOCK_TARGET", tmp_path / "ufw.conf")
    seen: list[str] = []
    configured: set[str] = set()
    monkeypatch.setattr(
        firewall_ufw,
        "saved_coverage",
        lambda runner, family, rules, fresh: set() if fresh else set(rules),
    )
    monkeypatch.setattr(
        firewall_ufw,
        "runtime_coverage",
        lambda runner, family, rules, active: set(rules) if active else set(),
    )

    def exec_fn(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        seen.append(" ".join(cmd))
        if cmd == ["/usr/bin/getent", "passwd", "testadmin"]:
            passwd = f"testadmin:x:1201:1202::{account_home}:/bin/bash\n"
            return subprocess.CompletedProcess(cmd, 0, passwd, "")
        if cmd[0] == "/usr/bin/setpriv":
            op = cmd[cmd.index("lhm-userkeys") + 1]
            assert cmd[1:5] == ["--reuid", "1201", "--regid", "1202"]
            if op == "ensure":
                frame = "CHANGED 0"
            else:
                assert op == "probe"
                frame = "STATE 1 0600 " + base64.b64encode(installed_key.encode()).decode()
            return subprocess.CompletedProcess(cmd, 0, f"LHM_USERKEYS_V1 {frame}\n", "")
        if cmd == ["cat", "/etc/default/ufw"]:
            return subprocess.CompletedProcess(cmd, 0, "IPV6=yes\nMANAGE_BUILTINS=no\n", "")
        if cmd == ["cat", "/etc/ufw/ufw.conf"]:
            enabled = "yes" if "ufw" in configured else "no"
            return subprocess.CompletedProcess(cmd, 0, f"ENABLED={enabled}\n", "")
        if cmd[:3] == ["ufw", "status", "verbose"]:
            if "ufw" not in configured:
                return subprocess.CompletedProcess(cmd, 0, "Status: inactive\n", "")
            out = (
                "Status: active\n"
                "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                "To                         Action      From\n"
                "--                         ------      ----\n"
                "22345/tcp                  ALLOW       Anywhere\n"
                "22345/tcp (v6)             ALLOW       Anywhere (v6)\n"
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
        if cmd == ["systemctl", "is-enabled", "fail2ban"]:
            return subprocess.CompletedProcess(cmd, 0, "enabled\n", "")
        if cmd[:1] == [str(root / "lhm-backup.sh")]:
            target = tmp_path / "backups"
            target.mkdir(parents=True, exist_ok=True)
            archive = target / "lhm-backup-20261122T020000Z.tar.gz"
            archive.write_bytes(b"archive")
            archive.with_name(archive.name + ".sha256").write_text("x\n", encoding="utf-8")
        if cmd[:4] == ["systemctl", "show", "-p", "LoadState"]:
            return subprocess.CompletedProcess(cmd, 0, "loaded\n", "")
        if cmd in (
            ["systemctl", "is-active", "ssh.socket"],
            ["systemctl", "is-active", "sshd.socket"],
        ):
            return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
        if cmd == ["ss", "-tlnp"]:
            # A hardened host: sshd already listens on 22345 (anti-lockout probe).
            out = (
                "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
                "LISTEN 0      128          0.0.0.0:22345      0.0.0.0:*     "
                'users:(("sshd",pid=1,fd=3))\n'
            )
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if cmd == ["apt-config", "dump"]:
            policy = f'Unattended-Upgrade::Origins-Pattern:: "{pattern}";\n'
            return subprocess.CompletedProcess(cmd, 0, policy, "")
        if cmd[-2:] == ["/usr/bin/apt-config", "dump"]:
            config = next(
                arg.removeprefix("APT_CONFIG=") for arg in cmd if arg.startswith("APT_CONFIG=")
            )
            return subprocess.CompletedProcess(cmd, 0, Path(config).read_text(encoding="utf-8"), "")
        if cmd[:3] == ["apt-config", "shell", "PREF"]:
            return subprocess.CompletedProcess(
                cmd, 0, f"PREF='{root / 'preferences'}'\nPREFS='{root / 'preferences.d'}'\n", ""
            )
        if cmd[:3] == ["dpkg-query", "-W", "-f=${db:Status-Status}"]:
            if cmd[-1] in installed_packages:
                return subprocess.CompletedProcess(cmd, 0, "installed\n", "")
        if cmd[:2] == ["dpkg-query", "-W"]:
            return subprocess.CompletedProcess(cmd, 1, "", "not installed")
        if cmd[:2] == ["sysctl", "-n"]:
            wanted = {"kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1"}
            return subprocess.CompletedProcess(cmd, 0, wanted.get(cmd[2], "1") + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "active\n", "")

    key = tmp_path / "id.pub"
    key.write_text(installed_key, encoding="utf-8")
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=exec_fn, **kw))
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(ssh, "geteuid", lambda: 1200)
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
    if pending:
        assert rc == 1
        assert "f" * 32 in capsys.readouterr().out
        assert not any("lhm-userkeys" in command or command.startswith("ufw ") for command in seen)
        return
    assert rc == 0
    out = capsys.readouterr().out
    order = [f"== {name} ==" for name in APPLY_ALL_ORDER]
    positions = [out.index(header) for header in order]
    assert positions == sorted(positions)
    assert "== services ==" not in out
    assert "== caddy ==" not in out
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
    rc = cli.main(["apply", "all", "--dry-run", "--webhook", "https://x/y", "--target", "/tmp/b"])
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
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "Runner", lambda **kw: Runner(exec_fn=fake_exec, **kw))
    monkeypatch.setattr(cli.ssh_module, "HOME_ROOT", tmp_path / "absent-home")
    monkeypatch.setattr(
        cli.updates_module,
        "inspect",
        lambda _runner: {"installed": True, "apt_conf_current": True},
    )
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
