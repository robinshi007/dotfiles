import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from lhm import cli
from lhm.core.confirm import BYPASS_ENV
from lhm.core.report import Status, StepResult
from lhm.core.runner import Runner


@pytest.fixture(autouse=True)
def _isolate_ssh_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.ssh_module, "HOME_ROOT", tmp_path / "absent-home")


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
    # Non-TTY: nothing is written, but the run must not look like "already done".
    assert cli.main(["apply", "updates"]) == cli.EXIT_ABORT
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
    assert cli.main(["apply", "sysctl"]) == cli.EXIT_ABORT
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
    assert cli.main(["rollback", str(cli.ssh_module.SSHD_DROPIN), "--dry-run"]) == 0


def test_rollback_relative_path_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: True)
    assert cli.main(["rollback", "relative/file"]) == 2


@pytest.mark.parametrize(
    ("tty", "answers", "reason"),
    [
        (False, [], "not a TTY"),
        (True, ["n"], "nothing further was changed"),
        (True, [EOFError()], "no input available"),
    ],
)
def test_rollback_aborts_without_tty_or_confirmation(
    tty: bool,
    answers: list[str | EOFError],
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("current\n", encoding="utf-8")
    (tmp_path / "sshd_config.bak").write_text("previous\n", encoding="utf-8")
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: tty)
    prompt = Mock(side_effect=answers)
    monkeypatch.setattr("builtins.input", prompt)
    assert cli.main(["rollback", str(target)]) == cli.EXIT_ABORT
    assert target.read_text(encoding="utf-8") == "current\n"
    assert reason in capsys.readouterr().err
    assert prompt.call_count == len(answers)


@pytest.mark.parametrize("ssh_target", [True, False])
def test_rollback_backs_up_current_file_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ssh_target: bool
) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("current\n", encoding="utf-8")
    (tmp_path / "sshd_config.bak").write_text("previous\n", encoding="utf-8")
    if ssh_target:
        monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    else:
        monkeypatch.setattr(cli.sysctl_module, "SYSCTL_DROPIN", target)
    current = Mock(return_value=None)
    monkeypatch.setattr(cli.ssh_watchdog, "current", current)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    prompt = Mock(side_effect=["y", "n"])
    monkeypatch.setattr("builtins.input", prompt)
    assert cli.main(["rollback", str(target)]) == 0
    prompt.assert_called_once()
    assert target.read_text(encoding="utf-8") == "previous\n"
    # The overwritten "current" content is preserved for a rollback of the rollback.
    assert (tmp_path / "sshd_config.bak.1").read_text(encoding="utf-8") == "current\n"
    assert current.call_count == int(ssh_target)


@pytest.mark.parametrize("state", ["awaiting-confirm", "failed", "unreadable"])
def test_rollback_refuses_ssh_watchdog_state_under_target_lock(
    state: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("current\n", encoding="utf-8")
    (tmp_path / "99-lhm.conf.bak").write_text("previous\n", encoding="utf-8")
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "confirm_once", lambda _plan: True)

    def current() -> SimpleNamespace:
        with pytest.raises(BlockingIOError), cli.locked_target(target):
            pytest.fail("watchdog checked outside the SSH target lock")
        if state == "unreadable":
            raise cli.ssh_watchdog.WatchdogError("invalid watchdog state")
        return SimpleNamespace(phase=state)

    monkeypatch.setattr(cli.ssh_watchdog, "current", current)
    assert cli.main(["rollback", str(target)]) == cli.EXIT_FAIL
    err = capsys.readouterr().err
    assert "SSH watchdog" in err
    if state == "unreadable":
        assert "invalid watchdog state" in err
    assert target.read_text(encoding="utf-8") == "current\n"
    assert not (tmp_path / "99-lhm.conf.bak.1").exists()


def test_rollback_rejects_unmanaged_and_symlink_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "config"
    target.write_text("untouched\n", encoding="utf-8")
    (outside / "config.bak").write_text("old\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    leaf = tmp_path / "leaf"
    leaf.symlink_to(target)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", alias / "config")
    monkeypatch.setattr(cli.sysctl_module, "SYSCTL_DROPIN", leaf)
    for path in (target, alias / "config", leaf):
        for flags in ([], ["--dry-run"]):
            assert cli.main(["rollback", str(path), *flags]) == 2
    assert target.read_text(encoding="utf-8") == "untouched\n"
    assert not (outside / "config.bak.1").exists()


def test_rollback_managed_file_without_backup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "managed"
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    assert cli.main(["rollback", str(target)]) == 1
    assert "no backup found" in capsys.readouterr().err


def test_rollback_refuses_target_held_by_another_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "managed"
    target.write_text("current", encoding="utf-8")
    older = target.with_suffix(".bak")
    older.write_text("previous", encoding="utf-8")
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "confirm_once", lambda _plan: True)
    with cli.locked_target(target):
        assert cli.main(["rollback", str(target)]) == 1
    assert target.read_text(encoding="utf-8") == "current"
    assert not target.with_suffix(".bak.1").exists()


def test_rollback_refuses_backup_that_changed_after_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "managed"
    target.write_text("current", encoding="utf-8")
    target.with_suffix(".bak").write_text("previous", encoding="utf-8")
    monkeypatch.setattr(cli.ssh_module, "SSHD_DROPIN", target)
    monkeypatch.setattr(cli, "is_root", lambda: True)

    def confirm(_plan: list[str]) -> bool:
        target.with_suffix(".bak.1").write_text("a newer backup", encoding="utf-8")
        return True

    monkeypatch.setattr(cli.ssh_watchdog, "current", lambda: None)
    monkeypatch.setattr(cli, "confirm_once", confirm)
    assert cli.main(["rollback", str(target)]) == 1
    assert "backup changed" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "current"


def test_cli_dry_run_guards_even_a_misplaced_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lhm.core.files import write_dropin

    target = tmp_path / "misplaced"

    def apply_before_check(*_args: object) -> int:
        assert write_dropin(target, "content") == "planned"
        return 0

    monkeypatch.setattr(cli, "_handle_apply", apply_before_check)
    assert cli.main(["apply", "sysctl", "--dry-run"]) == 0
    assert not target.exists()
    assert write_dropin(target, "content") == "written"


def test_apply_ssh_hardening_dry_run_prints_banner_and_port(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from lhm.modules import ssh

    monkeypatch.setattr(ssh, "SSHD_DROPIN", tmp_path / "99-lhm.conf")
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "ssh-hardening", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "dry-run: no changes will be made"
    assert "Port 22345" in out
    assert "key validation deferred until live apply" in out
    assert fake_exec.calls == []


@pytest.mark.parametrize(
    ("args", "exit_code", "status"),
    [([], cli.EXIT_FAIL, "FAIL"), (["--dry-run"], cli.EXIT_OK, "PLANNED")],
)
def test_ssh_confirm_root_gate_and_dry_run(
    args: list[str],
    exit_code: int,
    status: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: False)
    confirm = Mock()
    disarm = Mock()
    monkeypatch.setattr(cli, "confirm_once", confirm)
    monkeypatch.setattr(cli.ssh_module, "confirm_watchdog", disarm)
    assert cli.main(["ssh-confirm", "txid", "--json", *args]) == exit_code
    (step,) = json.loads(capsys.readouterr().out)
    assert step["status"] == status
    if args:
        assert "txid" in step["detail"]
        assert "independent, non-multiplexed SSH key login" in step["detail"]
    else:
        assert "requires root" in step["detail"]
    confirm.assert_not_called()
    disarm.assert_not_called()


@pytest.mark.parametrize(("tty", "answers"), [(False, []), (True, ["n"]), (True, [EOFError()])])
def test_ssh_confirm_aborts_without_tty_or_confirmation_even_with_bypass(
    tty: bool,
    answers: list[str | EOFError],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setenv(BYPASS_ENV, "1")
    monkeypatch.setattr("sys.stdin.isatty", lambda: tty)
    prompt = Mock(side_effect=answers)
    disarm = Mock()
    monkeypatch.setattr("builtins.input", prompt)
    monkeypatch.setattr(cli.ssh_module, "confirm_watchdog", disarm)

    assert cli.main(["ssh-confirm", "txid", "--json"]) == cli.EXIT_ABORT
    captured = capsys.readouterr()
    assert json.loads(captured.out)[0]["status"] == "ABORTED"
    assert BYPASS_ENV not in captured.err
    assert prompt.call_count == len(answers)
    disarm.assert_not_called()


@pytest.mark.parametrize(
    ("outcome", "status", "exit_code"),
    [
        (Status.CHANGED, "CHANGED", cli.EXIT_OK),
        (Status.FAIL, "FAIL", cli.EXIT_FAIL),
        ("exception", "FAIL", cli.EXIT_FAIL),
    ],
)
def test_ssh_confirm_calls_watchdog_after_one_confirmation_and_reports_result(
    outcome: str,
    status: str,
    exit_code: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setenv(BYPASS_ENV, "1")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    prompt = Mock(side_effect=["y", "n"])
    monkeypatch.setattr("builtins.input", prompt)
    calls: list[str] = []

    def disarm(runner: Runner, txid: str) -> list[StepResult]:
        prompt.assert_called_once()
        assert not runner.dry_run
        calls.append(txid)
        if outcome == "exception":
            raise cli.ssh_watchdog.WatchdogError("invalid watchdog state")
        return [StepResult("ssh-confirm", Status(outcome), "result from watchdog")]

    monkeypatch.setattr(cli.ssh_module, "confirm_watchdog", disarm)
    assert cli.main(["ssh-confirm", "txid", "--json"]) == exit_code
    captured = capsys.readouterr()
    (step,) = json.loads(captured.out)
    detail = "invalid watchdog state" if outcome == "exception" else "result from watchdog"
    assert step == {"name": "ssh-confirm", "status": status, "detail": detail}
    assert "independent, non-multiplexed SSH key login" in captured.err
    assert calls == ["txid"]


def test_apply_ssh_user_dry_run_defers_key_import(
    fake_exec: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(cli.ssh_module, "geteuid", lambda: 0)
    args = ["apply", "ssh-user", "robin", "--key", str(tmp_path / "missing.pub"), "--dry-run"]
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "dry-run: no changes will be made"
    assert "account and --key validation deferred" in out
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
    for name in (
        "system",
        "ssh",
        "firewall",
        "fail2ban",
        "services",
        "ports",
        "sysctl",
        "audit",
        "updates",
    ):
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
        "system",
        "ssh",
        "firewall",
        "fail2ban",
        "services",
        "ports",
        "sysctl",
        "audit",
        "updates",
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


def test_apply_fail2ban_dry_run_shows_strict_values_and_both_paths(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from lhm.modules import fail2ban

    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["apply", "fail2ban", "--dry-run", "--caddy"]) == 0
    out = capsys.readouterr().out
    assert str(fail2ban.JAIL_DROPIN) in out
    assert str(fail2ban.CADDY_FILTER) in out
    assert "bantime 8h" in out
    assert "maxretry 3" in out
    assert "findtime 30m" in out
    assert "caddy jail enabled in the drop-in" in out
    assert "preserved untouched" in out
    assert fake_exec.calls == []


def test_query_fail2ban_judges_targets(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from lhm.modules import fail2ban

    root = Path("/tmp") / "lhm-query-fail2ban" / "etc" / "fail2ban"
    monkeypatch.setattr(fail2ban, "JAIL_DROPIN", root / "jail.d" / "99-lhm.local")
    monkeypatch.setattr(fail2ban, "CADDY_FILTER", root / "filter.d" / "caddy-lhm.conf")
    monkeypatch.setattr(fail2ban, "LEGACY_JAIL_LOCAL", root / "jail.local")
    monkeypatch.setattr(fail2ban, "DBFILE", root / "fail2ban.sqlite3")
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client get sshd bantime", 0, "28800\n", ""),
            ("fail2ban-client get sshd maxretry", 0, "3\n", ""),
            ("fail2ban-client get sshd findtime", 0, "1800\n", ""),
            ("fail2ban-client -d", 0, "['set', 'sshd', 'bantime.increment', True]\n", ""),
        ]
    )
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    assert cli.main(["query", "fail2ban", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sshd_bantime"] == "28800"
    assert data["sshd_maxretry"] == "3"
    assert data["sshd_findtime"] == "1800"
    assert data["sshd_bantime_increment"] is True
    assert data["legacy_jail_local_present"] is False
    assert data["caddy_enabled"] is None  # drop-in absent -> not configured


def test_apply_abort_by_user_answer_exits_3(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from lhm.modules import updates

    target = tmp_path / "51-lhm"
    monkeypatch.setattr(updates, "APT_CONF", target)
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    fake_exec.responses.append(("dpkg-query", 1, "", "not installed"))
    assert cli.main(["apply", "updates"]) == cli.EXIT_ABORT
    assert not target.exists()


def test_apply_dry_run_is_unaffected_by_the_abort_code(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from lhm.modules import updates

    target = tmp_path / "51-lhm"
    monkeypatch.setattr(updates, "APT_CONF", target)
    monkeypatch.setattr(cli, "Runner", _runner_factory(fake_exec))
    # No TTY and no is_root: a dry-run plans and exits 0 without asking.
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(cli, "is_root", lambda: False)
    assert cli.main(["apply", "updates", "--dry-run"]) == 0
    assert not target.exists()
