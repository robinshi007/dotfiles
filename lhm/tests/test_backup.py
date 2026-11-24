import errno
import os
import stat
import struct
import sys
from pathlib import Path

import pytest

from lhm.core import backup as backup_module
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


def test_backup_with_numbering_gap_still_becomes_newest(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("new", encoding="utf-8")
    (tmp_path / "f.bak.2").write_text("old", encoding="utf-8")
    created = backup_file(target)
    assert created.name == "f.bak.3"
    assert newest_backup(target) == created


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


def _temp_files(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.startswith(".lhm-")]


def test_backup_stages_private_temp_then_publishes_source_mode(tmp_path: Path) -> None:
    target = tmp_path / "secret.conf"
    target.write_text("token\n", encoding="utf-8")
    target.chmod(0o640)
    real_mkstemp = backup_module.tempfile.mkstemp
    staged_modes: list[int] = []

    def tracking_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
        staged_modes.append(stat.S_IMODE(os.stat(name).st_mode))
        return fd, name

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_module.tempfile, "mkstemp", tracking_mkstemp)
        result = backup_file(target)
    # Staged privately, published with the source's own mode.
    assert staged_modes == [0o600]
    assert stat.S_IMODE(result.stat().st_mode) == 0o640
    assert _temp_files(tmp_path) == []


def test_backup_preserves_mtime_and_content_from_regular_source(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("data\n", encoding="utf-8")
    stamp = 1_600_000_000_123_456_789
    os.utime(target, ns=(stamp, stamp))
    result = backup_file(target)
    assert result.read_text(encoding="utf-8") == "data\n"
    assert result.stat().st_mtime_ns == stamp


@pytest.mark.parametrize("restore", [False, True])
def test_access_acl_is_installed_privately_before_final_mode_and_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool
) -> None:
    target = tmp_path / "f"
    source = tmp_path / "f.bak" if restore else target
    target.write_bytes(b"current")
    source.write_bytes(b"previous")
    source.chmod(0o664)
    src_stat = source.stat()
    acl = b"fake extended ACL"
    attr = "system.posix_acl_access"
    calls: list[str] = []
    real_chown = os.fchown
    real_chmod = os.fchmod
    publish = os.replace if restore else os.link
    final_mode = 0o664 if restore else 0o640

    def get_acl(fd: int, name: str) -> bytes:
        assert os.path.samestat(os.fstat(fd), src_stat)
        assert name == attr
        calls.append("read ACL")
        return acl

    def chown(fd: int, uid: int, gid: int) -> None:
        assert (uid, gid) == (src_stat.st_uid, src_stat.st_gid)
        calls.append("chown")
        real_chown(fd, uid, gid)

    def set_acl(fd: int, name: str, value: bytes) -> None:
        assert (name, value) == (attr, acl)
        (staging,) = _temp_files(tmp_path)
        assert stat.S_IMODE(staging.stat().st_mode) == 0o700
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        assert os.pread(fd, len(b"previous"), 0) == b"previous"
        calls.append("set ACL")
        real_chmod(fd, 0o664)  # Linux setxattr can change group and other mode bits.

    def chmod(fd: int, mode: int) -> None:
        assert mode == final_mode
        calls.append("chmod")
        real_chmod(fd, mode)

    def checked_publish(src: Path, dst: Path) -> None:
        assert stat.S_IMODE(src.stat().st_mode) == final_mode
        calls.append("publish")
        publish(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(os, "getxattr", get_acl)
        mp.setattr(os, "fchown", chown)
        mp.setattr(os, "setxattr", set_acl)
        mp.setattr(os, "fchmod", chmod)
        mp.setattr(os, "replace" if restore else "link", checked_publish)
        if restore:
            assert rollback_file(target) == source
        else:
            assert backup_file(target, mode=final_mode) == tmp_path / "f.bak"

    assert calls == ["read ACL", "chown", "set ACL", "chmod", "publish"]
    assert _temp_files(tmp_path) == []


@pytest.mark.parametrize("missing", [errno.ENODATA, errno.EOPNOTSUPP])
def test_missing_or_unsupported_acl_clears_inherited_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: int
) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"data")
    removed: list[str] = []

    def get_acl(fd: int, name: str) -> bytes:
        raise OSError(missing, "no source ACL")

    def remove_acl(fd: int, name: str) -> None:
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        removed.append(name)
        raise OSError(missing, "no inherited ACL")

    with monkeypatch.context() as mp:
        mp.setattr(os, "getxattr", get_acl)
        mp.setattr(os, "removexattr", remove_acl)
        assert backup_file(target).read_bytes() == b"data"
    assert removed == ["system.posix_acl_access"]


@pytest.mark.parametrize("restore", [False, True])
@pytest.mark.parametrize("failure", [errno.EOPNOTSUPP, errno.ENODATA, errno.EACCES])
def test_existing_acl_copy_failure_does_not_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool, failure: int
) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"current")
    previous = tmp_path / "f.bak"
    if restore:
        previous.write_bytes(b"previous")

    def reject_acl(fd: int, name: str, value: bytes) -> None:
        raise OSError(failure, "cannot copy ACL")

    with monkeypatch.context() as mp:
        mp.setattr(os, "getxattr", lambda fd, name: b"existing ACL")
        mp.setattr(os, "setxattr", reject_acl)
        with pytest.raises(OSError, match="cannot copy ACL") as caught:
            (rollback_file if restore else backup_file)(target)
    assert caught.value.errno == failure
    assert target.read_bytes() == b"current"
    if restore:
        assert previous.read_bytes() == b"previous"
    else:
        assert not previous.exists()
    assert _temp_files(tmp_path) == []


def test_backup_with_acl_does_not_publish_under_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"data")
    real_fstat = os.fstat
    source = target.stat()

    def fstat(fd: int) -> os.stat_result:
        opened = real_fstat(fd)
        if os.path.samestat(opened, source):
            return opened
        return os.stat_result((*opened[:4], source.st_uid + 1, *opened[5:]))

    def deny_chown(fd: int, uid: int, gid: int) -> None:
        raise PermissionError(errno.EPERM, "cannot preserve ACL ownership")

    with monkeypatch.context() as mp:
        mp.setattr(os, "getxattr", lambda fd, name: b"existing ACL")
        mp.setattr(os, "fstat", fstat)
        mp.setattr(os, "fchown", deny_chown)
        with pytest.raises(PermissionError, match="cannot preserve ACL ownership"):
            backup_file(target)
    assert newest_backup(target) is None
    assert _temp_files(tmp_path) == []


def test_native_access_acl_preserves_named_entries_and_does_not_inherit(tmp_path: Path) -> None:
    attr = "system.posix_acl_access"
    target = tmp_path / "f"
    plain = tmp_path / "plain"
    target.write_bytes(b"before")
    plain.write_bytes(b"plain")

    def acl(mask: int, other: int) -> bytes:
        # Linux xattr format: version, followed by (tag, permissions, id) entries.
        none = 0xFFFFFFFF
        entries = [
            (1, 6, none),
            (2, 6, os.geteuid() + 1),
            (4, 4, none),
            (16, mask, none),
            (32, other, none),
        ]
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)

    try:
        os.setxattr(target, attr, acl(6, 4))
    except OSError as exc:
        if exc.errno == errno.EOPNOTSUPP:
            pytest.skip("isolated filesystem does not support POSIX access ACLs")
        raise

    backup = backup_file(target)
    assert os.getxattr(backup, attr) == acl(6, 4)
    capped = backup_file(target, mode=0o640)
    assert stat.S_IMODE(capped.stat().st_mode) == 0o640
    assert os.getxattr(capped, attr) == acl(4, 0)
    target.write_bytes(b"after")
    rollback_file(target, backup=capped)
    assert target.read_bytes() == b"before"
    assert os.getxattr(target, attr) == acl(4, 0)

    os.setxattr(tmp_path, "system.posix_acl_default", acl(6, 4))
    plain_backup = backup_file(plain)
    with pytest.raises(OSError) as caught:
        os.getxattr(plain_backup, attr)
    assert caught.value.errno == errno.ENODATA


def test_backup_link_failure_leaves_no_candidate_or_temp(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("v1", encoding="utf-8")
    (tmp_path / "f.bak").write_text("v1", encoding="utf-8")

    def failing_link(src: object, dst: object) -> None:
        raise OSError(errno.ENOSPC, "no space left on device")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_module.os, "link", failing_link)
        with pytest.raises(OSError, match="no space"):
            backup_file(target)
    # The existing backup is untouched, no truncated new one, no leftovers.
    assert (tmp_path / "f.bak").read_text(encoding="utf-8") == "v1"
    assert not (tmp_path / "f.bak.1").exists()
    assert _temp_files(tmp_path) == []


def test_backup_copy_failure_leaves_no_candidate_or_temp(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("x" * 4096, encoding="utf-8")
    real_read = os.read
    calls = 0

    def flaky_read(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_read(fd, size)
        raise OSError(errno.EIO, "input/output error")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_module.os, "read", flaky_read)
        with pytest.raises(OSError, match="input/output error"):
            backup_file(target)
    assert newest_backup(target) is None
    assert _temp_files(tmp_path) == []


def test_concurrent_writer_cannot_overwrite_backup(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("mine", encoding="utf-8")
    real_link = os.link

    def racing_link(src: Path, dst: Path) -> None:
        # Simulate another process taking the candidate just before we link.
        if dst == tmp_path / "f.bak":
            dst.write_text("racer", encoding="utf-8")
        real_link(src, dst)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_module.os, "link", racing_link)
        result = backup_file(target)
    assert result == tmp_path / "f.bak.1"
    assert result.read_text(encoding="utf-8") == "mine"
    assert (tmp_path / "f.bak").read_text(encoding="utf-8") == "racer"
    assert _temp_files(tmp_path) == []


def test_backup_rejects_symlink_leaf(tmp_path: Path) -> None:
    real = tmp_path / "real.conf"
    real.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.conf"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        backup_file(link)
    assert not (tmp_path / "link.conf.bak").exists()
    assert _temp_files(tmp_path) == []


def test_backup_rejects_non_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(ValueError, match="non-regular"):
        backup_file(directory)
    assert _temp_files(tmp_path) == []


def test_newest_backup_ignores_symlink_candidate(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("old", encoding="utf-8")
    (tmp_path / "f.bak.1").symlink_to(tmp_path / "f.bak")
    assert newest_backup(target) == tmp_path / "f.bak"


def test_rollback_copy_failure_keeps_target_and_backup(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("previous", encoding="utf-8")
    real_read = os.read
    calls = 0

    def flaky_read(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_read(fd, size)
        raise OSError(errno.EIO, "input/output error")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_module.os, "read", flaky_read)
        with pytest.raises(OSError, match="input/output error"):
            rollback_file(target)
    assert target.read_text(encoding="utf-8") == "current"
    assert (tmp_path / "f.bak").read_text(encoding="utf-8") == "previous"
    assert _temp_files(tmp_path) == []


def test_rollback_preserves_backup_mode(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("previous", encoding="utf-8")
    (tmp_path / "f.bak").chmod(0o600)
    rollback_file(target)
    assert target.read_text(encoding="utf-8") == "previous"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert _temp_files(tmp_path) == []


def test_rollback_explicit_backup_must_sit_next_to_target(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    (other / "f.bak").write_text("elsewhere", encoding="utf-8")
    with pytest.raises(ValueError, match="next to the target"):
        rollback_file(target, backup=other / "f.bak")
    assert target.read_text(encoding="utf-8") == "current"


def test_rollback_explicit_backup_must_be_backup_name(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "unrelated").write_text("nope", encoding="utf-8")
    with pytest.raises(ValueError, match="not a backup name"):
        rollback_file(target, backup=tmp_path / "unrelated")
    assert target.read_text(encoding="utf-8") == "current"


def test_rollback_rejects_symlink_backup_candidate(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    real_backup = tmp_path / "real.bak"
    real_backup.write_text("previous", encoding="utf-8")
    (tmp_path / "f.bak").symlink_to(real_backup)
    with pytest.raises(ValueError, match="symlink"):
        rollback_file(target, backup=tmp_path / "f.bak")
    assert target.read_text(encoding="utf-8") == "current"


def test_rollback_explicit_older_backup(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("current", encoding="utf-8")
    (tmp_path / "f.bak").write_text("oldest", encoding="utf-8")
    (tmp_path / "f.bak.1").write_text("newest", encoding="utf-8")
    used = rollback_file(target, backup=tmp_path / "f.bak")
    assert used == tmp_path / "f.bak"
    assert target.read_text(encoding="utf-8") == "oldest"


@pytest.mark.skipif(sys.platform != "linux", reason="O_NOFOLLOW semantics differ")
def test_backup_does_not_follow_symlink_swapped_after_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "f"
    target.write_text("x", encoding="utf-8")
    other = tmp_path / "other"
    other.write_text("not the source", encoding="utf-8")
    real_open = os.open

    def swap_then_open(path: Path, flags: int) -> int:
        assert path == target
        target.unlink()
        target.symlink_to(other)
        return real_open(path, flags)

    with monkeypatch.context() as ctx:
        ctx.setattr(backup_module.os, "open", swap_then_open)
        with pytest.raises(OSError) as failure:
            backup_file(target)
    assert failure.value.errno == errno.ELOOP
    assert newest_backup(target) is None
    # A dangling symlink is rejected rather than raising FileNotFoundError.
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="symlink"):
        backup_file(dangling)
