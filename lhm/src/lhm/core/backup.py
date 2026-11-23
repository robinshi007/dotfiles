"""Backup policy: ``f.bak`` then ``f.bak.1``, ``f.bak.2``... never overwriting."""

import os
import shutil
from pathlib import Path


def _safe_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"refusing relative path: {p}")
    if ".." in p.parts:
        raise ValueError(f"refusing path with '..': {p}")
    if p == Path("/"):
        raise ValueError("refusing to operate on /")
    return p


def _backup_names(path: Path) -> list[Path]:
    names = [path.with_name(path.name + ".bak")]
    index = 1
    while True:
        names.append(path.with_name(f"{path.name}.bak.{index}"))
        if not names[-1].exists():
            return names
        index += 1


def _copy_like_cp_a(src: Path, dst: Path) -> None:
    """Copy file data and metadata, approximating ``cp -a`` (owner best-effort)."""
    shutil.copy2(src, dst, follow_symlinks=False)
    stat = src.lstat()
    try:
        os.chown(dst, stat.st_uid, stat.st_gid, follow_symlinks=False)
    except PermissionError:
        pass  # unprivileged runs cannot preserve foreign ownership


def backup_file(path: str | Path) -> Path:
    """Copy ``path`` to the first free backup name and return that name."""
    src = _safe_path(path)
    if not src.exists() and not src.is_symlink():
        raise FileNotFoundError(f"cannot back up missing file: {src}")
    for candidate in _backup_names(src):
        if not candidate.exists():
            _copy_like_cp_a(src, candidate)
            return candidate
    raise AssertionError("unreachable: _backup_names always yields a free name")


def newest_backup(path: str | Path) -> Path | None:
    """Return the most recent backup for ``path``, or None if there is none."""
    src = _safe_path(path)
    candidates: list[tuple[int, Path]] = []
    plain = src.with_name(src.name + ".bak")
    if plain.exists():
        candidates.append((0, plain))
    for candidate in src.parent.glob(src.name + ".bak.*"):
        suffix = candidate.name.rsplit(".bak.", 1)[-1]
        if suffix.isdigit():
            candidates.append((int(suffix), candidate))
    if not candidates:
        return None
    return max(candidates)[1]


def rollback_file(path: str | Path, *, backup: str | Path | None = None) -> Path:
    """Restore a backup (default: the newest) over ``path`` and return it."""
    src = _safe_path(path)
    chosen = newest_backup(src) if backup is None else _safe_path(backup)
    if chosen is None:
        raise FileNotFoundError(f"no backup found for {src}")
    if not chosen.exists():
        raise FileNotFoundError(f"backup is gone: {chosen}")
    _copy_like_cp_a(chosen, src)
    return chosen
