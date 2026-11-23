"""Drop-in writes, marked-block appends and template rendering."""

import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from string import Template
from typing import Literal

from lhm.core.backup import backup_file

TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"

WriteOutcome = Literal["skipped", "written"]
AppendOutcome = Literal["skipped", "appended"]


def _checked_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"refusing relative path: {p}")
    if ".." in p.parts:
        raise ValueError(f"refusing path with '..': {p}")
    return p


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


def write_dropin(path: str | Path, content: str, mode: int | None = None) -> WriteOutcome:
    """Write a drop-in atomically, skipping when content is already identical.

    ``mode`` forces the resulting file (and its fresh backup) to that mode, so a
    secret-bearing file never lands world-readable between write and chmod.
    """
    p = _checked_path(path)
    if p.is_file() and p.read_text(encoding="utf-8") == content:
        return "skipped"
    backup: Path | None = None
    if p.exists() or p.is_symlink():
        backup = backup_file(p)
    _atomic_write(p, content, mode)
    if mode is not None and backup is not None:
        os.chmod(backup, mode)
    return "written"


def _has_marker(text: str, marker: str) -> bool:
    suffix = f" {marker} begin ====="
    return any(
        line.startswith("# ===== lhm ") and line.endswith(suffix)
        for line in text.splitlines()
    )


def append_marked(path: str | Path, marker: str, content: str) -> AppendOutcome:
    """Append ``content`` in a marker block, skipping when the marker exists."""
    p = _checked_path(path)
    existing = p.read_text(encoding="utf-8") if p.is_file() else ""
    if _has_marker(existing, marker):
        return "skipped"

    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = content.rstrip("\n")
    block = (
        f"# ===== lhm {stamp} {marker} begin =====\n"
        f"{body}\n"
        f"# ===== lhm {marker} end =====\n"
    )
    updated = existing
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += block

    if p.exists() or p.is_symlink():
        backup_file(p)
    _atomic_write(p, updated)
    return "appended"


def render_template(name: str, **variables: str) -> str:
    """Render ``templates/<name>`` with string.Template substitution."""
    template_path = TEMPLATES_DIR / name
    return Template(template_path.read_text(encoding="utf-8")).substitute(**variables)


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
        value = variables[key]
        if "'" in value:
            raise ValueError(f"refusing {key} value with a single quote: {value!r}")
        if any(character < " " or character == "\x7f" for character in value):
            raise ValueError(f"refusing {key} value with control characters: {value!r}")
        return value

    return _ShellTemplate.pattern.sub(replace, text)


def restrict(path: str | Path, mode: int) -> None:
    """Lock down a secret-bearing file: chmod and root:root when running as root."""
    p = _checked_path(path)
    os.chmod(p, mode)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(p, 0, 0)
