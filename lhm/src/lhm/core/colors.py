"""Color policy and every colored line the CLI prints (single owner of ANSI codes).

Policy: auto (color only on a TTY), ``NO_COLOR`` disables auto coloring, and an
explicit ``--color=always`` wins over ``NO_COLOR`` (so piped output can be forced).
"""

import difflib
import os
import shlex
import sys
from collections.abc import Sequence
from enum import StrEnum
from typing import TextIO


class Color(StrEnum):
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    RESET = "\033[0m"


MODES = ("auto", "always", "never")

_mode = "auto"
_verbose = False
_quiet = False
_output: TextIO | None = None


def configure(mode: str = "auto", *, verbose: bool = False, quiet: bool = False) -> None:
    """Set the color mode (``auto``/``always``/``never``), verbose and quiet flags.

    ``quiet`` suppresses the command echo and file-change lines so ``--json``
    output stays machine-readable.
    """
    global _mode, _verbose, _quiet
    if mode not in MODES:
        raise ValueError(f"invalid color mode: {mode!r}")
    _mode = mode
    _verbose = verbose
    _quiet = quiet


def set_output(stream: TextIO | None) -> None:
    """Redirect colored output (tests); ``None`` restores the live ``sys.stdout``."""
    global _output
    _output = stream


def output() -> TextIO:
    return _output if _output is not None else sys.stdout


def enabled() -> bool:
    """True when ANSI codes may be emitted (``--color=always`` beats ``NO_COLOR``)."""
    if _mode == "always":
        return True
    if _mode == "never":
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(output().isatty())


def paint(text: str, color: Color | None = None) -> str:
    if color is None or not enabled():
        return text
    return f"{color}{text}{Color.RESET}"


def paintln(text: str = "", color: Color | None = None) -> None:
    print(paint(text, color), file=output())


def command(argv: Sequence[str]) -> None:
    """Echo one executed command as ``$ cmd`` (nothing in ``--json`` runs)."""
    if _quiet:
        return
    paintln(f"$ {shlex.join([str(part) for part in argv])}", Color.CYAN)


_SYMBOLS: dict[str, tuple[str, Color]] = {
    "created": ("+", Color.GREEN),
    "modified": ("~", Color.YELLOW),
    "deleted": ("-", Color.RED),
    "symlink": ("@", Color.MAGENTA),
}


def file_change(
    kind: str,
    path: object,
    *,
    old: str | None = None,
    new: str | None = None,
    link: str | None = None,
) -> None:
    """Print one file change: ``+ path`` / ``~ path`` / ``- path`` / ``@ path``.

    With ``--verbose`` the content follows: full content for created/deleted,
    a unified diff for modified, and the target for a symlink.
    """
    if _quiet:
        return
    symbol, color = _SYMBOLS[kind]
    paintln(f"{symbol} {path}", color)
    if not _verbose:
        return
    if kind == "created" and new is not None:
        _content(new)
    elif kind == "deleted" and old is not None:
        _content(old)
    elif kind == "modified" and old is not None and new is not None:
        _diff(path, old, new)
    elif kind == "symlink" and link is not None:
        paintln(f"  {path} -> {link}", Color.MAGENTA)


def _content(text: str) -> None:
    for line in text.splitlines():
        paintln(line)


def _diff(path: object, old: str, new: str) -> None:
    lines = difflib.unified_diff(
        old.splitlines(),
        new.splitlines(),
        fromfile=f"{path} (old)",
        tofile=str(path),
        lineterm="",
    )
    for line in lines:
        if line.startswith("+++") or line.startswith("---"):
            paintln(line)
        elif line.startswith("+"):
            paintln(line, Color.GREEN)
        elif line.startswith("-"):
            paintln(line, Color.RED)
        elif line.startswith("@@"):
            paintln(line, Color.CYAN)
        else:
            paintln(line)
