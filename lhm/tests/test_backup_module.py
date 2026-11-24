import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import backup


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    script = tmp_path / "usr" / "local" / "lib" / "lhm" / "lhm-backup.sh"
    unit_dir = tmp_path / "systemd"
    monkeypatch.setattr(backup, "SCRIPT", script)
    monkeypatch.setattr(backup, "UNIT_DIR", unit_dir)
    monkeypatch.setattr(backup, "SERVICE_UNIT", unit_dir / "lhm-backup.service")
    monkeypatch.setattr(backup, "TIMER_UNIT", unit_dir / "lhm-backup.timer")
    return {
        "script": script,
        "service": unit_dir / "lhm-backup.service",
        "timer": unit_dir / "lhm-backup.timer",
        "target": tmp_path / "backups",
    }


def _runner(calls: list[list[str]], on_script: Any = None) -> Runner:
    def exec_fn(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if on_script is not None and cmd[:1] == [str(on_script[0])]:
            on_script[1]()
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return Runner(exec_fn=exec_fn)


def _write_archive(target: Path, with_manifest: bool = True) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    archive = target / "lhm-backup-20261122T020000Z.tar.gz"
    archive.write_bytes(b"archive")
    if with_manifest:
        archive.with_name(archive.name + ".sha256").write_text("deadbeef\n", encoding="utf-8")
    return archive


@pytest.mark.parametrize(
    "target", ["backups", "./backups", "", "../etc", "/", "/home", "/home/robin/backups", "/etc/x"]
)
def test_relative_or_unsafe_target_refused(
    target: str, fake_exec: Any, paths: dict[str, Path]
) -> None:
    results = backup.apply_backup(Runner(exec_fn=fake_exec), target=target, keep=7)
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []
    assert not paths["script"].exists()


def test_target_inside_home_or_etc_names_the_reason(
    fake_exec: Any, paths: dict[str, Path]
) -> None:
    results = backup.apply_backup(Runner(exec_fn=fake_exec), target="/etc/backups", keep=7)
    assert results[0].status is Status.FAIL
    assert "inside /etc" in results[0].detail


def test_target_with_single_quote_refused(fake_exec: Any, paths: dict[str, Path]) -> None:
    results = backup.apply_backup(Runner(exec_fn=fake_exec), target="/srv/a'b", keep=7)
    assert results[0].status is Status.FAIL
    assert "single quote" in results[0].detail


def test_backup_dir_is_0700_and_script_umasks_077(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "confirm_once", lambda plan: True)
    calls: list[list[str]] = []
    runner = _runner(calls, on_script=(paths["script"], lambda: _write_archive(paths["target"])))
    backup.apply_backup(runner, target=str(paths["target"]), keep=7)
    assert paths["target"].stat().st_mode & 0o777 == 0o700
    script = paths["script"].read_text(encoding="utf-8")
    assert "umask 077" in script
    assert "chmod 700 \"$TARGET_DIR\"" in script


def test_keep_must_be_positive(fake_exec: Any, paths: dict[str, Path]) -> None:
    results = backup.apply_backup(
        Runner(exec_fn=fake_exec), target=str(paths["target"]), keep=0
    )
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []


def test_dry_run_writes_nothing(fake_exec: Any, paths: dict[str, Path]) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = backup.apply_backup(runner, target=str(paths["target"]), keep=3)
    assert fake_exec.calls == []
    assert not paths["target"].exists()
    assert not paths["script"].exists()
    assert all(r.status in {Status.PLANNED, Status.SKIPPED} for r in results)
    assert ["systemctl", "enable", "--now", "lhm-backup.timer"] in runner.planned


def test_apply_runs_script_once_and_checks_archive(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "confirm_once", lambda plan: True)
    calls: list[list[str]] = []
    runner = _runner(calls, on_script=(paths["script"], lambda: _write_archive(paths["target"])))
    results = backup.apply_backup(runner, target=str(paths["target"]), keep=7)
    names = {r.name: r.status for r in results}
    assert names["install " + str(paths["script"])] is Status.CHANGED
    assert names["write " + str(paths["service"])] is Status.CHANGED
    assert names["write " + str(paths["timer"])] is Status.CHANGED
    assert names["test run"] is Status.OK
    assert names["verify"] is Status.OK
    assert "lhm-backup-20261122T020000Z.tar.gz" in next(
        r for r in results if r.name == "verify"
    ).detail
    assert calls.count([str(paths["script"])]) == 1
    assert paths["script"].stat().st_mode & 0o777 == 0o755
    script = paths["script"].read_text(encoding="utf-8")
    assert "TARGET_DIR='" + str(paths["target"]) + "'" in script
    assert "KEEP=7" in script
    assert 'OUT="$TARGET_DIR/lhm-backup-$STAMP.tar.gz"' in script
    assert "ReadWritePaths=" + str(paths["target"]) in paths["service"].read_text(encoding="utf-8")
    executed = [" ".join(call) for call in calls]
    assert "systemctl daemon-reload" in executed
    assert "systemctl enable --now lhm-backup.timer" in executed


def test_missing_manifest_fails_verification(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "confirm_once", lambda plan: True)
    calls: list[list[str]] = []
    runner = _runner(
        calls, on_script=(paths["script"], lambda: _write_archive(paths["target"], False))
    )
    results = backup.apply_backup(runner, target=str(paths["target"]), keep=7)
    assert results[-1].status is Status.FAIL
    assert "manifest missing" in results[-1].detail


def test_verify_archive_prefers_newest(paths: dict[str, Path]) -> None:
    target = paths["target"]
    target.mkdir()
    old = target / "lhm-backup-20260101T000000Z.tar.gz"
    new = _write_archive(target)
    old.write_bytes(b"old")
    old.with_name(old.name + ".sha256").write_text("x\n", encoding="utf-8")
    os.utime(old, (1_700_000_000, 1_700_000_000))
    os.utime(new, (1_800_000_000, 1_800_000_000))
    result = backup.verify_archive(target)
    assert result.status is Status.OK
    assert new.name in result.detail


def test_empty_archive_fails(paths: dict[str, Path]) -> None:
    target = paths["target"]
    target.mkdir()
    archive = target / "lhm-backup-20261122T000000Z.tar.gz"
    archive.write_bytes(b"")
    archive.with_name(archive.name + ".sha256").write_text("x\n", encoding="utf-8")
    assert backup.verify_archive(target).status is Status.FAIL


@pytest.mark.parametrize("target", ["/srv/a b", "/srv/a%n", "//etc/backup", "/srv/a\tb"])
def test_space_percent_and_double_slash_refused(
    target: str, fake_exec: Any, paths: dict[str, Path]
) -> None:
    results = backup.apply_backup(Runner(exec_fn=fake_exec), target=target, keep=7)
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []
    assert not paths["script"].exists()


def test_symlinked_parent_inside_etc_is_refused(
    tmp_path: Path, fake_exec: Any, paths: dict[str, Path]
) -> None:
    link = tmp_path / "sneaky"
    link.symlink_to("/etc")
    results = backup.apply_backup(Runner(exec_fn=fake_exec), target=str(link / "backup"), keep=7)
    assert results[0].status is Status.FAIL
    assert "inside /etc" in results[0].detail
    assert fake_exec.calls == []
