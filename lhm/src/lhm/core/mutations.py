"""Context-local guard shared by managed filesystem and command operations."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_dry_run: ContextVar[bool] = ContextVar("lhm_dry_run", default=False)


def mutations_allowed() -> bool:
    return not _dry_run.get()


@contextmanager
def mutation_mode(*, dry_run: bool) -> Iterator[None]:
    """A nested caller cannot relax an enclosing dry-run."""
    token = _dry_run.set(dry_run or not mutations_allowed())
    try:
        yield
    finally:
        _dry_run.reset(token)
