"""Drop-in writes, marked-block appends and template rendering."""

import errno
import fcntl
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from string import Template
from typing import Literal
from unicodedata import category

from lhm.core import colors
from lhm.core.backup import backup_file
from lhm.core.mutations import mutations_allowed

_PACKAGE_DIR = Path(__file__).resolve().parents[1]
_PACKAGED_TEMPLATES = _PACKAGE_DIR / "templates"
TEMPLATES_DIR = (
    _PACKAGE_DIR.parents[1] / "templates"
    if _PACKAGE_DIR.parent.name == "src" and not _PACKAGED_TEMPLATES.is_dir()
    else _PACKAGED_TEMPLATES
)

WriteOutcome = Literal["skipped", "written", "planned"]
AppendOutcome = Literal["skipped", "appended", "planned"]


def _checked_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"refusing relative path: {p}")
    if ".." in p.parts:
        raise ValueError(f"refusing path with '..': {p}")
    return p


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OSError(errno.ELOOP, "refusing to overwrite symlink", path)


@contextmanager
def locked_target(path: str | Path) -> Iterator[int | None]:
    """Serialize cooperating writers; fail immediately if the target is locked.

    The managed parent must already exist and be trusted. The lock persists
    beside the target so contenders always lock the same inode. This advisory
    lock cannot guard against other writers or path changes above the parent.
    """
    p = _checked_path(path)
    if not p.name:
        raise ValueError("refusing to lock /")
    if not mutations_allowed():
        yield
        return

    lock = p.with_name(f".{p.name}.lhm.lock")
    uid = os.geteuid()
    parent_fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != uid or parent.st_mode & 0o022:
            raise PermissionError(errno.EPERM, "unsafe managed directory for lock", p.parent)
        try:
            existing = os.stat(lock.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing.st_mode):
                raise OSError(errno.ELOOP, "refusing symlink lock file", lock)
            if not stat.S_ISREG(existing.st_mode):
                raise OSError(errno.EINVAL, "refusing non-regular lock file", lock)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        lock_fd = os.open(lock.name, flags, 0o600, dir_fd=parent_fd)
        try:
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != uid
                or opened.st_nlink != 1
            ):
                raise PermissionError(errno.EPERM, "unsafe target lock file", lock)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BlockingIOError(exc.errno, "managed target is locked", p) from exc
            named = os.stat(lock.name, dir_fd=parent_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise OSError(errno.ESTALE, "target lock file changed", lock)
            _reject_symlink(p)
            yield lock_fd
        finally:
            os.close(lock_fd)
    finally:
        os.close(parent_fd)


def notify_file_change(
    kind: str,
    path: Path,
    *,
    old: str | None = None,
    new: str | None = None,
    link: str | None = None,
    secret: bool = False,
) -> None:
    """Report a completed change without treating an output error as a failed write."""
    try:
        colors.file_change(kind, path, old=old, new=new, link=link, secret=secret)
    except OSError:
        pass


def ensure_dir(
    path: str | Path, mode: int = 0o755, *, parents: bool = True, exist_ok: bool = True
) -> None:
    if mutations_allowed():
        _checked_path(path).mkdir(mode=mode, parents=parents, exist_ok=exist_ok)


def set_mode(path: str | Path, mode: int) -> None:
    if mutations_allowed():
        _checked_path(path).chmod(mode)


def remove_file(path: str | Path, *, missing_ok: bool = False) -> bool:
    if not mutations_allowed():
        return False
    try:
        _checked_path(path).unlink()
    except FileNotFoundError:
        if not missing_ok:
            raise
        return False
    return True


def _atomic_write(path: Path, content: str, mode: int | None = None) -> None:
    effective = 0o644 if mode is None else mode
    if mode is None and path.is_file() and not path.is_symlink():
        effective = path.stat().st_mode & 0o777
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".lhm-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, effective)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def write_dropin(
    path: str | Path,
    content: str,
    mode: int | None = None,
    *,
    secret: bool = False,
    on_backup: Callable[[Path], None] | None = None,
    require_backup: bool = False,
) -> WriteOutcome:
    """Write a drop-in atomically, skipping when content is already identical.

    ``mode`` fixes the resulting file mode and caps the fresh backup's mode.
    ``on_backup`` receives the exact backup produced for this write, if any.
    ``require_backup`` refuses to write unless a fresh backup can be made.
    ``secret`` keeps ``--verbose`` from printing the content (and the diff or
    the deleted backup content): a secret-bearing script must not be echoed.
    """
    p = _checked_path(path)
    if not mutations_allowed():
        return "planned"
    _reject_symlink(p)
    old = _read_text(p) if p.is_file() else None
    if old == content:
        return "skipped"
    if require_backup or p.exists():
        backup = backup_file(p, mode=mode)
        if on_backup is not None:
            on_backup(backup)
    _atomic_write(p, content, mode)
    notify_file_change(
        "created" if old is None else "modified", p, old=old, new=content, secret=secret
    )
    return "written"


_MARK = re.compile(r"# ===== lhm (?:(\S+) )?([a-zA-Z0-9_.-]+) (begin|end) =====")


def _marked_body(text: str, marker: str) -> tuple[int, int] | None:
    active: str | None = None
    start = offset = 0
    body: tuple[int, int] | None = None
    for line in text.splitlines(keepends=True):
        match = _MARK.fullmatch(line.rstrip("\r\n"))
        if match is not None:
            stamp, name, kind = match.groups()
            if kind == "begin" and stamp and active is None:
                active = name
                start = offset + len(line)
            elif kind == "end" and stamp is None and active == name:
                if name == marker:
                    if body is not None:
                        raise ValueError(f"duplicate managed marker: {marker}")
                    body = (start, offset)
                active = None
            else:
                raise ValueError("malformed managed marker block")
        elif line.startswith("# ===== lhm ") and re.search(r" (?:begin|end) =====", line):
            raise ValueError("malformed managed marker line")
        offset += len(line)
    if active is not None:
        raise ValueError(f"unterminated managed marker block: {active}")
    return body


def append_marked(path: str | Path, marker: str, content: str) -> AppendOutcome:
    """Append or update a managed block without changing surrounding bytes."""
    p = _checked_path(path)
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", marker):
        raise ValueError("invalid managed marker name")
    if not mutations_allowed():
        return "planned"
    _reject_symlink(p)
    exists = p.is_file()
    existing = p.read_bytes().decode("utf-8") if exists else ""
    bounds = _marked_body(existing, marker)

    body = content.rstrip("\r\n") + "\n"
    if any(_MARK.fullmatch(line) for line in body.splitlines()):
        raise ValueError("managed block content cannot contain marker lines")
    if bounds is not None:
        start, end = bounds
        old_body = existing[start:end]
        if old_body.replace("\r\n", "\n") == body:
            return "skipped"
        replacement = body.replace("\n", "\r\n") if old_body.endswith("\r\n") else body
        updated = existing[:start] + replacement + existing[end:]
    else:
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        separator = "" if not existing or existing.endswith("\n") else "\n"
        updated = (
            f"{existing}{separator}# ===== lhm {stamp} {marker} begin =====\n"
            f"{body}# ===== lhm {marker} end =====\n"
        )

    if p.exists():
        backup_file(p)
    _atomic_write(p, updated)
    notify_file_change(
        "modified" if exists else "created",
        p,
        old=existing or None,
        new=updated,
    )
    return "appended"


def _validate_value(key: str, value: str, *, quotes: str) -> str:
    if any(char in quotes or category(char) in {"Cc", "Zl", "Zp"} for char in value):
        raise ValueError(f"refusing template variable {key!r}: quote or control character")
    return value


def render_template(name: str, **variables: str) -> str:
    """Render single-line configuration values; callers validate their syntax."""
    template_path = TEMPLATES_DIR / name
    values = {key: _validate_value(key, value, quotes="'\"") for key, value in variables.items()}
    return Template(template_path.read_text(encoding="utf-8")).substitute(**values)


class _ShellTemplate:
    """Placeholder pattern for shell templates: only ``${lower_case}`` is ours."""

    pattern = re.compile(r"\$\{(?P<name>[_a-z][_a-z0-9]*)\}")


def render_shell_template(name: str, **variables: str) -> str:
    """Render a shell-script template: only ``${lower_case}`` placeholders change.

    Shell's own ``$VAR``, ``$(...)`` and ``$((...))`` must survive untouched, which
    ``string.Template`` (which treats every ``$`` as a placeholder) cannot do.
    Values are single-quoted by the templates, so a quote or control character
    would break out of the string: refuse instead of escaping.
    """
    template_path = TEMPLATES_DIR / name
    text = template_path.read_text(encoding="utf-8")

    def replace(match: re.Match[str]) -> str:
        key = match.group("name")
        if key not in variables:
            raise KeyError(f"missing template variable {key!r} in {name}")
        return _validate_value(key, variables[key], quotes="'")

    return _ShellTemplate.pattern.sub(replace, text)


def restrict(path: str | Path, mode: int) -> None:
    """Lock down a secret-bearing file: chmod and root:root when running as root."""
    if not mutations_allowed():
        return
    p = _checked_path(path)
    os.chmod(p, mode)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(p, 0, 0)
