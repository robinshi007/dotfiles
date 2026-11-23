from pathlib import Path
from typing import Any

import pytest

from lhm import cli
from lhm.core.runner import Runner


def test_query_system_no_traceback(fake_exec: Any, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["query", "system"]) == 0
    out = capsys.readouterr().out
    assert "hostname" in out
    assert fake_exec.calls == []  # system probe is pure stdlib


def test_query_ports_json(fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from lhm.core import checks

    monkeypatch.setattr(
        checks,
        "listening_ports",
        lambda runner: [checks.PortRecord("tcp", "LISTEN", "0.0.0.0", 22, "*", "sshd")],
    )
    assert cli.main(["query", "ports", "--json"]) == 0


def test_apply_updates_dry_run_executes_nothing(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.modules import updates

    monkeypatch.setattr(updates, "APT_CONF", Path("/nonexistent/51-lhm"))
    monkeypatch.setattr(Runner, "exec_fn", staticmethod(fake_exec))
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "updates", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "dry-run: no changes will be made"
    assert "Plan (updates)" in out
    assert "PLANNED" in out
    assert fake_exec.calls == []


def _runner_factory(fake_exec: Any) -> Any:
    def factory(*, dry_run: bool = False, verbose: bool = False) -> Runner:
        return Runner(dry_run=dry_run, verbose=verbose, exec_fn=fake_exec)

    return factory


def test_apply_updates_non_tty_fails_closed(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from lhm.modules import updates

    target = tmp_path / "51-lhm"
    monkeypatch.setattr(updates, "APT_CONF", target)
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    fake_exec.responses.append(("dpkg-query", 1, "", "not installed"))
    assert cli.main(["apply", "updates"]) == 0
    assert not target.exists()
    mutating = [c for c in fake_exec.calls if "--version" not in c]
    assert not any("apt-get" in " ".join(c) for c in mutating)


def test_apply_requires_root(fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(cli, "is_root", lambda: False)
    assert cli.main(["apply", "updates"]) == 1


def test_all_modules_now_implemented(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(cli, "is_root", lambda: True)
    # sysctl is implemented now: a non-TTY run must abort inside the module (no y answers)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["apply", "sysctl"]) == 0
    assert "aborted" in capsys.readouterr().out


def test_check_reports_needs_change_areas(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.modules import updates

    monkeypatch.setattr(updates, "APT_CONF", Path("/nonexistent/51-lhm"))
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    fake_exec.responses.append(("dpkg-query", 1, "", ""))
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "needs-change" in out
    # Phase 3: every area is implemented, so nothing is UNKNOWN any more.
    assert "UNKNOWN" not in out


def test_rollback_dry_run_needs_no_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: False)
    assert cli.main(["rollback", "/etc/ssh/sshd_config", "--dry-run"]) == 0


def test_rollback_relative_path_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: True)
    assert cli.main(["rollback", "relative/file"]) == 2


def test_rollback_requires_tty_and_double_confirm(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("current\n", encoding="utf-8")
    (tmp_path / "sshd_config.bak").write_text("previous\n", encoding="utf-8")
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["rollback", str(target)]) == 1
    assert target.read_text(encoding="utf-8") == "current\n"
    assert "not a TTY" in capsys.readouterr().err
    # TTY but only one confirmation: still refused.
    answers = iter(["y", "n"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert cli.main(["rollback", str(target)]) == 1
    assert target.read_text(encoding="utf-8") == "current\n"


def test_rollback_backs_up_current_file_first(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("current\n", encoding="utf-8")
    (tmp_path / "sshd_config.bak").write_text("previous\n", encoding="utf-8")
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    assert cli.main(["rollback", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == "previous\n"
    # The overwritten "current" content is preserved for a rollback of the rollback.
    assert (tmp_path / "sshd_config.bak.1").read_text(encoding="utf-8") == "current\n"


def test_apply_ssh_hardening_dry_run_prints_banner_and_port(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from lhm.modules import ssh

    home = tmp_path / "home"
    (home / "robin" / ".ssh").mkdir(parents=True)
    (home / "robin" / ".ssh" / "authorized_keys").write_text(
        (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
            " robin@laptop\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ssh, "HOME_ROOT", home)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", tmp_path / "99-lhm.conf")
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "ssh-hardening", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "dry-run: no changes will be made"
    assert "Port 22345" in out
    assert fake_exec.calls == []


def test_apply_firewall_dry_run_plan_order(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "firewall", "--dry-run", "--allow", "80/tcp"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == "dry-run: no changes will be made"
    assert lines.index("  - allow 22345/tcp") < lines.index("  - default deny incoming")
    assert lines.index("  - allow 80/tcp") < lines.index("  - default deny incoming")


def test_apply_fail2ban_dry_run(fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "fail2ban", "--dry-run", "--bantime", "2h"]) == 0
    assert fake_exec.calls == []


def test_apply_cleanup_services_dry_run(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "cleanup-services", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "PLANNED" in out
    assert fake_exec.calls == []


def test_query_services_and_firewall_json(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.core import checks

    fake_exec.responses.append(("ufw status verbose", 1, "", "ERROR: not found"))
    assert cli.main(["query", "firewall", "--json"]) == 0
    assert '"available": false' in capsys.readouterr().out
    monkeypatch.setattr(checks, "SERVICES", ())
    assert cli.main(["query", "services", "--json"]) == 0
    assert "cleanup_candidates" in capsys.readouterr().out


def test_check_reports_new_modules(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.modules import updates

    monkeypatch.setattr(updates, "APT_CONF", Path("/nonexistent/51-lhm"))
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    for area in (
        "updates",
        "ssh",
        "firewall",
        "fail2ban",
        "services",
        "sysctl",
        "sandbox",
        "logging",
        "audit",
        "alert",
        "backup",
    ):
        assert area in out
    assert "UNKNOWN" not in out


def test_usage_error_on_missing_subcommand() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2


def test_query_ssh_without_root_reports_needs_root(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # sshd -T fails (e.g. root-only drop-in files) -> values must say so, not
    # silently print "unavailable".
    fake_exec.responses.append(
        ("sshd -T", 1, "", "/etc/ssh/sshd_config.d/50-cloud-init.conf: Permission denied")
    )
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh"]) == 0
    out = capsys.readouterr().out
    assert "unavailable (needs root)" in out
    assert "sudo lhm query ssh" in out


def test_query_all_prints_sections_with_separators(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "all"]) == 0
    out = capsys.readouterr().out
    for name in ("system", "ssh", "firewall", "services", "ports", "sysctl", "audit", "updates"):
        assert f"== {name} ==" in out
    assert out.index("== system ==") < out.index("== updates ==")
    # sections are separated by a blank line
    assert "\n\n== ssh ==" in out


def test_query_all_json_emits_pure_json(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "all", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {
        "system", "ssh", "firewall", "services", "ports", "sysctl", "audit", "updates",
    }


def test_query_ssh_with_effective_config_shows_values(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_exec.responses.append(
        ("sshd -T", 0, "port 22345\npermitrootlogin no\npasswordauthentication no\n", "")
    )
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh"]) == 0
    out = capsys.readouterr().out
    # provided keys show real values; the missing four stay "unavailable"
    assert "22345" in out
    assert "needs root" not in out
    assert out.count("unavailable") == 4


SSHD_HARDENED = (
    "port 22345\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "kbdinteractiveauthentication no\n"
    "pubkeyauthentication yes\n"
    "x11forwarding no\n"
    "maxauthtries 3\n"
)


def test_query_ssh_hardened_values_are_green(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.core.colors import Color
    from lhm.modules import ssh

    monkeypatch.setattr(ssh, "HOME_ROOT", Path("/nonexistent"))
    fake_exec.responses.append(("sshd -T", 0, SSHD_HARDENED, ""))
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh", "--color=always"]) == 0
    out = capsys.readouterr().out
    for value in ("22345", "no", "yes", "3"):
        assert f"{Color.GREEN}{value}{Color.RESET}" in out


def test_query_ssh_weak_values_are_red(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.core.colors import Color
    from lhm.modules import ssh

    monkeypatch.setattr(ssh, "HOME_ROOT", Path("/nonexistent"))
    fake_exec.responses.append(
        (
            "sshd -T",
            0,
            "port 22\npermitrootlogin yes\npasswordauthentication yes\n"
            "pubkeyauthentication yes\nmaxauthtries 6\n",
            "",
        )
    )
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh", "--color=always"]) == 0
    out = capsys.readouterr().out
    assert f"{Color.RED}22{Color.RESET}" in out
    assert f"{Color.RED}yes{Color.RESET}" in out
    assert f"{Color.RED}6{Color.RESET}" in out


def test_query_ssh_probe_failure_rows_are_yellow(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.core.colors import Color
    from lhm.modules import ssh

    monkeypatch.setattr(ssh, "HOME_ROOT", Path("/nonexistent"))
    fake_exec.responses.append(("sshd -T", 1, "", "permission denied"))
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh", "--color=always"]) == 0
    out = capsys.readouterr().out
    assert out.count(Color.YELLOW) == 7


def test_query_all_without_tty_emits_no_ansi(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "all"]) == 0
    assert "\033[" not in capsys.readouterr().out


def test_color_always_overrides_no_tty_and_no_color(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "system", "--color=always"]) == 0
    # system has no judged cells, so force a check run instead: still no codes...
    capsys.readouterr()
    assert cli.main(["check", "--color=always"]) == 0
    assert "\033[" in capsys.readouterr().out


def test_color_never_on_a_tty(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["check", "--color=never"]) == 0
    assert "\033[" not in capsys.readouterr().out


def test_check_status_column_is_colored(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.core.colors import Color

    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(
        cli,
        "CHECKERS",
        {module.name: (lambda runner: (True, "fine")) for module in cli.MODULES}
        | {"ssh": lambda runner: (False, "weak")},
    )
    assert cli.main(["check", "--color=always"]) == 0
    out = capsys.readouterr().out
    assert f"{Color.GREEN}OK" in out
    assert f"{Color.RED}needs-change{Color.RESET}" in out


def test_json_output_stays_pure_even_with_forced_color(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "ssh", "--json", "--color=always"]) == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    json.loads(out)
