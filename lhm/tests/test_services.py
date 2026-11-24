import subprocess
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import services

UNIT_FILES = """ssh.service enabled enabled
cron.service enabled enabled
nginx.service enabled enabled
unattended-upgrades.service enabled enabled
getty@tty1.service enabled enabled
lhm-backup.timer enabled enabled
docker.service enabled enabled
systemd-resolved.service enabled enabled
"""


@pytest.fixture
def enabled(fake_exec: Any) -> Any:
    fake_exec.responses.append(("systemctl list-unit-files", 0, UNIT_FILES, ""))
    return fake_exec


def test_protected_set_excludes_essentials() -> None:
    for unit in (
        "ssh.service",
        "sshd.service",
        "ufw.service",
        "fail2ban.service",
        "auditd.service",
        "cron.service",
        "rsyslog.service",
        "unattended-upgrades.service",
        "getty@tty1.service",
        "lhm-backup.timer",
        "systemd-resolved.service",
        "systemd-journald.service",
        "udisks2.service",
        "polkit.service",
        "sudo.service",
        "networking.service",
        "dbus.service",
    ):
        assert services.is_protected(unit), unit


def test_candidates_filter_protected_units(enabled: Any) -> None:
    items = services.candidates(Runner(exec_fn=enabled))
    names = [item.unit for item in items]
    assert names == ["nginx.service", "docker.service"]


def test_parse_selection_forms() -> None:
    assert services.parse_selection("1 3", 4) == [0, 2]
    assert services.parse_selection("2,3", 4) == [1, 2]
    assert services.parse_selection("all", 3) == [0, 1, 2]
    assert services.parse_selection("none", 3) == []
    assert services.parse_selection("", 3) == []
    assert services.parse_selection("3 3 1", 3) == [0, 2]


def test_parse_selection_rejects_bad_input() -> None:
    with pytest.raises(services.SelectionError):
        services.parse_selection("abc", 3)
    with pytest.raises(services.SelectionError):
        services.parse_selection("4", 3)
    with pytest.raises(services.SelectionError):
        services.parse_selection("0", 3)


def test_cleanup_dry_run_executes_nothing(enabled: Any, capsys: pytest.CaptureFixture[str]) -> None:
    runner = Runner(dry_run=True, exec_fn=enabled)
    results = services.apply_cleanup_services(runner)
    out = capsys.readouterr().out
    assert "systemctl list-unit-files" in out
    assert all(r.status is Status.PLANNED for r in results)
    assert enabled.calls == []


class StatefulExec:
    """Tracks disabled units so the verification listing reflects the change."""

    def __init__(self, disabled_unit: str = "") -> None:
        self.calls: list[list[str]] = []
        self.disabled_unit = disabled_unit

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "disable"]:
            self.disabled_unit = cmd[-1]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["systemctl", "list-unit-files"]:
            lines = [
                line
                for line in UNIT_FILES.splitlines()
                if not (self.disabled_unit and self.disabled_unit in line)
            ]
            return subprocess.CompletedProcess(cmd, 0, "".join(f"{line}\n" for line in lines), "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.mark.parametrize("select", ["", "1"])
def test_cleanup_disables_selected_units_only(monkeypatch: pytest.MonkeyPatch, select: str) -> None:
    expected_prompts = ["Disable these units now? type 'y' to continue: "]
    if not select:
        expected_prompts.insert(0, "selection: ")
    prompts: list[str] = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return "1" if prompt == "selection: " else "y"

    monkeypatch.setattr(services.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", answer)
    enabled = StatefulExec()
    results = services.apply_cleanup_services(Runner(exec_fn=enabled), select=select)
    assert prompts == expected_prompts
    assert results[0].status is Status.CHANGED
    assert results[0].name == "disable --now nginx.service"
    assert results[-1].status is Status.OK
    disables = [call for call in enabled.calls if call[:2] == ["systemctl", "disable"]]
    assert disables == [["systemctl", "disable", "--now", "nginx.service"]]
    assert not any("autoremove" in call or "remove" in call for call in enabled.calls)


def test_cleanup_none_selected_is_skipped(enabled: Any) -> None:
    results = services.apply_cleanup_services(Runner(exec_fn=enabled), select="none")
    assert results[0].status is Status.SKIPPED
    assert results[0].detail == "nothing selected"
    assert not any(call[:2] == ["systemctl", "disable"] for call in enabled.calls)


def test_cleanup_eof_is_aborted(
    enabled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def eof(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    results = services.apply_cleanup_services(Runner(exec_fn=enabled))
    assert results[0].status is Status.ABORTED
    assert "no input" in results[0].detail
    assert "aborted" in capsys.readouterr().err
    assert not any(call[:2] == ["systemctl", "disable"] for call in enabled.calls)


def test_cleanup_bad_selection_fails_closed(enabled: Any) -> None:
    results = services.apply_cleanup_services(Runner(exec_fn=enabled), select="9")
    assert results[0].status is Status.FAIL
    assert "out of range" in results[0].detail
    assert not any(call[:2] == ["systemctl", "disable"] for call in enabled.calls)


class StubbornExec(StatefulExec):
    """disable --now reports success but the unit stays enabled."""

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = super().__call__(cmd, timeout)
        if cmd[:2] == ["systemctl", "disable"]:
            self.disabled_unit = ""
        return result


def test_cleanup_verify_reports_still_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(services.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    enabled = StubbornExec()
    results = services.apply_cleanup_services(Runner(exec_fn=enabled), select="1")
    assert results[-1].status is Status.FAIL
    assert "nginx.service" in results[-1].detail


def test_cleanup_without_candidates_is_skipped(fake_exec: Any) -> None:
    listing = "ssh.service enabled enabled\n"
    fake_exec.responses.append(("systemctl list-unit-files", 0, listing, ""))
    results = services.apply_cleanup_services(Runner(exec_fn=fake_exec), select="all")
    assert results[0].status is Status.SKIPPED
    assert "no non-protected enabled units" in results[0].detail
