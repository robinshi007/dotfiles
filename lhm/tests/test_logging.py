from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import logging


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    journald = tmp_path / "etc" / "systemd" / "journald.conf.d" / "99-lhm.conf"
    logrotate = tmp_path / "etc" / "logrotate.d" / "lhm-audit"
    journal_dir = tmp_path / "var" / "log" / "journal"
    monkeypatch.setattr(logging, "JOURNALD_DROPIN", journald)
    monkeypatch.setattr(logging, "LOGROTATE_CONF", logrotate)
    monkeypatch.setattr(logging, "JOURNAL_DIR", journal_dir)
    return {"journald": journald, "logrotate": logrotate, "journal_dir": journal_dir}


def test_dry_run_plans_and_writes_nothing(
    fake_exec: Any, paths: dict[str, Path]
) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = logging.apply_logging(runner)
    assert fake_exec.calls == []
    assert all(r.status is Status.PLANNED for r in results)
    assert not paths["journald"].exists()
    assert ["systemctl", "restart", "systemd-journald"] in runner.planned


def test_apply_creates_dropin_dir_and_verifies(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(logging, "confirm_twice", lambda plan: True)
    paths["journal_dir"].mkdir(parents=True)
    results = logging.apply_logging(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["write " + str(paths["journald"])] is Status.CHANGED
    assert names["write " + str(paths["logrotate"])] is Status.CHANGED
    assert names["restart systemd-journald"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert "Storage=persistent" in paths["journald"].read_text(encoding="utf-8")
    assert "/var/log/audit/audit.log" in paths["logrotate"].read_text(encoding="utf-8")
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "systemctl restart systemd-journald" in executed
    assert paths["journald"].stat().st_mode & 0o777 == 0o644


def test_verify_fails_when_journal_dir_missing(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(logging, "confirm_twice", lambda plan: True)
    results = logging.apply_logging(Runner(exec_fn=fake_exec))
    verify = next(r for r in results if r.name == "verify")
    assert verify.status is Status.FAIL
    assert "/var/log/journal missing" in verify.detail


def test_second_run_skips_everything(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(logging, "confirm_twice", lambda plan: True)
    paths["journal_dir"].mkdir(parents=True)
    logging.apply_logging(Runner(exec_fn=fake_exec))
    fake_exec.calls.clear()
    results = logging.apply_logging(Runner(exec_fn=fake_exec))
    assert fake_exec.calls == []
    assert {r.status for r in results} == {Status.SKIPPED, Status.OK}
