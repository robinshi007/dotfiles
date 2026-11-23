from pathlib import Path

import pytest

from lhm.core.backup import backup_file, newest_backup, rollback_file


def test_backup_creates_bak_then_rotates(tmp_path: Path) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("v1\n", encoding="utf-8")

    first = backup_file(target)
    assert first == tmp_path / "sshd_config.bak"
    assert first.read_text(encoding="utf-8") == "v1\n"

    target.write_text("v2\n", encoding="utf-8")
    second = backup_file(target)
    assert second == tmp_path / "sshd_config.bak.1"
    assert second.read_text(encoding="utf-8") == "v2\n"

    target.write_text("v3\n", encoding="utf-8")
    third = backup_file(target)
    assert third == tmp_path / "sshd_config.bak.2"

    # Existing backups are never overwritten.
    assert first.read_text(encoding="utf-8") == "v1\n"
    assert second.read_text(encoding="utf-8") == "v2\n"


def test_newest_backup_prefers_highest_index(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("old", encoding="utf-8")
    (tmp_path / "f.bak.1").write_text("newer", encoding="utf-8")
    (tmp_path / "f.bak.2").write_text("newest", encoding="utf-8")
    assert newest_backup(target) == tmp_path / "f.bak.2"


def test_rollback_restores_newest(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("old", encoding="utf-8")
    (tmp_path / "f.bak.1").write_text("newest", encoding="utf-8")
    used = rollback_file(target)
    assert used == tmp_path / "f.bak.1"
    assert target.read_text(encoding="utf-8") == "newest"


def test_relative_paths_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "f").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        backup_file("f")


def test_dotdot_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        backup_file(tmp_path / ".." / "etc" / "passwd")


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        backup_file(tmp_path / "nope")


def test_rollback_without_backup_raises(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        rollback_file(target)
