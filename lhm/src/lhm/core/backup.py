"""Backup policy: ``f.bak`` then ``f.bak.1``, ``f.bak.2``... never overwriting.

Backups are copied into a private staging directory beside the target, fsynced,
then published with a hard link to an unused backup name. A failure before
publication never leaves a partial ``.bak``, and concurrent writers cannot
overwrite each other.
"""

import errno
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from lhm.core.mutations import mutations_allowed

_CHUNK = 1 << 20
_ACCESS_ACL = "system.posix_acl_access"
_NO_ACL = (errno.ENODATA, errno.EOPNOTSUPP)


def _safe_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"refusing relative path: {p}")
    if ".." in p.parts:
        raise ValueError(f"refusing path with '..': {p}")
    if not p.name:
        raise ValueError("refusing to operate on /")
    return p


def _backup_name(path: Path, index: int) -> Path:
    if index == 0:
        return path.with_name(path.name + ".bak")
    return path.with_name(f"{path.name}.bak.{index}")


def _is_regular(path: Path) -> bool:
    """True for a regular file that is not a symlink."""
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    """Open ``path`` read-only, refusing symlinks and non-regular files."""
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"refusing to use symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"refusing to use non-regular file: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise ValueError(f"refusing to use changing file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd, fst


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _access_acl(fd: int) -> bytes | None:
    try:
        return os.getxattr(fd, _ACCESS_ACL)
    except OSError as exc:
        if exc.errno not in _NO_ACL:
            raise
        return None


def _apply_access_acl(fd: int, acl: bytes | None) -> None:
    if acl is not None:
        os.setxattr(fd, _ACCESS_ACL, acl)
        return
    # A parent default ACL may have supplied named entries to the new file.
    # Remove them before chmod could grant them effective permissions.
    try:
        os.removexattr(fd, _ACCESS_ACL)
    except OSError as exc:
        if exc.errno not in _NO_ACL:
            raise


@contextmanager
def _stage_copy(
    src: Path,
    *,
    mode: int | None = None,
    check_source: Callable[[os.stat_result], None] | None = None,
    check_copy: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield a fsynced temp file, hidden even while installing its access ACL."""
    with ExitStack() as cleanup:
        src_fd, src_stat = _open_regular(src)
        cleanup.callback(os.close, src_fd)
        if check_source is not None:
            check_source(src_stat)
        acl = _access_acl(src_fd)
        # Setting an ACL can unmask group permissions before fchmod applies the cap.
        # Start private, then restore owner access if a default ACL masked it.
        staging = cleanup.enter_context(tempfile.TemporaryDirectory(dir=src.parent, prefix=".lhm-"))
        os.chmod(staging, 0o700)
        tmp_fd, tmp_name = tempfile.mkstemp(dir=staging, suffix=".bak.tmp")
        try:
            while chunk := os.read(src_fd, _CHUNK):
                view = memoryview(chunk)
                while view:
                    written = os.write(tmp_fd, view)
                    if written <= 0:
                        raise OSError(f"short write while staging {src}")
                    view = view[written:]
            owner = (src_stat.st_uid, src_stat.st_gid)
            try:
                os.fchown(tmp_fd, *owner)
            except PermissionError:
                if acl is not None:
                    staged = os.fstat(tmp_fd)
                    if (staged.st_uid, staged.st_gid) != owner:
                        raise  # ACL owner and owning-group entries would change meaning.
            _apply_access_acl(tmp_fd, acl)
            source_mode = stat.S_IMODE(src_stat.st_mode)
            os.fchmod(tmp_fd, source_mode if mode is None else source_mode & mode)
            os.utime(tmp_fd, ns=(src_stat.st_atime_ns, src_stat.st_mtime_ns))
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        staged = Path(tmp_name)
        if check_source is not None or check_copy is not None:
            after = os.fstat(src_fd)
            if (after.st_uid, after.st_mode, after.st_ctime_ns) != (
                src_stat.st_uid,
                src_stat.st_mode,
                src_stat.st_ctime_ns,
            ):
                raise ValueError(f"refusing to use changing backup: {src}")
        if check_copy is not None:
            check_copy(staged)
        yield staged


def backup_file(path: str | Path, *, mode: int | None = None) -> Path:
    """Copy ``path`` to a new numbered backup without overwriting old backups."""
    if not mutations_allowed():
        raise RuntimeError("backup is not allowed in dry-run")
    src = _safe_path(path)
    if not src.exists() and not src.is_symlink():
        raise FileNotFoundError(f"cannot back up missing file: {src}")
    with _stage_copy(src, mode=mode) as tmp:
        previous = newest_backup(src)
        if previous is None:
            index = 0
        elif previous == _backup_name(src, 0):
            index = 1
        else:
            index = int(previous.name.rsplit(".", 1)[-1]) + 1
        while True:
            candidate = _backup_name(src, index)
            try:
                os.link(tmp, candidate)
            except FileExistsError:
                index += 1  # another writer took this name: keep the next one
                continue
            break
    _fsync_dir(src.parent)
    return candidate


def newest_backup(path: str | Path) -> Path | None:
    """Return the most recent backup for ``path``, or None if there is none."""
    src = _safe_path(path)
    candidates: list[tuple[int, Path]] = []
    plain = src.with_name(src.name + ".bak")
    if _is_regular(plain):
        candidates.append((0, plain))
    for candidate in src.parent.glob(src.name + ".bak.*"):
        suffix = candidate.name.rsplit(".bak.", 1)[-1]
        if suffix.isascii() and suffix.isdecimal() and _is_regular(candidate):
            candidates.append((int(suffix), candidate))
    if not candidates:
        return None
    return max(candidates)[1]


def _validated_backup(src: Path, chosen: Path) -> Path:
    """Require an explicit backup to be a sibling named ``<target>.bak[.N]``."""
    if os.path.realpath(chosen.parent) != os.path.realpath(src.parent):
        raise ValueError(f"backup must live next to the target: {chosen}")
    if not re.fullmatch(rf"{re.escape(src.name)}\.bak(?:\.\d+)?", chosen.name):
        raise ValueError(f"not a backup name for {src}: {chosen}")
    return chosen


def rollback_file(
    path: str | Path,
    *,
    backup: str | Path | None = None,
    check_source: Callable[[os.stat_result], None] | None = None,
    check_copy: Callable[[Path], None] | None = None,
) -> Path:
    """Restore a backup (default: the newest) over ``path`` and return it.

    The backup is copied to a same-filesystem temp file and swapped in with
    ``os.replace``, so the target is either the old content or the restored
    backup, never a partial copy. ``check_source`` checks the opened source's
    metadata before any read; ``check_copy`` checks the staged copy before publication.
    """
    if not mutations_allowed():
        raise RuntimeError("rollback is not allowed in dry-run")
    src = _safe_path(path)
    if backup is None:
        chosen = newest_backup(src)
        if chosen is None:
            raise FileNotFoundError(f"no backup found for {src}")
    else:
        chosen = _validated_backup(src, _safe_path(backup))
    with _stage_copy(chosen, check_source=check_source, check_copy=check_copy) as tmp:
        os.replace(tmp, src)
    _fsync_dir(src.parent)
    return chosen
