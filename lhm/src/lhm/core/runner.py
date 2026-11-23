"""Subprocess execution with timeouts, structured logging and dry-run support."""

import logging
import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from time import perf_counter

logger = logging.getLogger("lhm.runner")

DEFAULT_TIMEOUT = 30.0

ExecFn = Callable[[list[str], float], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one command invocation."""

    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    was_dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(RuntimeError):
    """Raised when a command exits non-zero and ``check`` was requested."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        message = f"command failed (rc={result.returncode}): {shlex.join(result.cmd)}"
        if result.stderr.strip():
            message += f"\n{result.stderr.strip()}"
        super().__init__(message)


def _default_exec(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, timeout=timeout, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: command not found ({exc})")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timed out after {timeout}s")


@dataclass
class Runner:
    """Wraps every system call. All commands have a timeout and are logged.

    In dry-run mode commands are recorded in ``planned`` and never executed; a
    synthetic success result with ``was_dry_run=True`` is returned.
    """

    dry_run: bool = False
    verbose: bool = False
    exec_fn: ExecFn = _default_exec
    planned: list[list[str]] = field(default_factory=list)
    history: list[CommandResult] = field(default_factory=list)

    def run(
        self,
        cmd: Sequence[str],
        timeout: float = DEFAULT_TIMEOUT,
        check: bool = True,
    ) -> CommandResult:
        argv = [str(part) for part in cmd]
        if self.dry_run:
            self.planned.append(argv)
            logger.info("dry-run planned cmd=%s timeout=%ss", shlex.join(argv), timeout)
            return CommandResult(argv, 0, "", "", 0.0, was_dry_run=True)

        start = perf_counter()
        completed = self.exec_fn(argv, timeout)
        duration = perf_counter() - start
        result = CommandResult(
            argv,
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
            duration,
        )
        self.history.append(result)
        logger.info(
            "cmd=%s rc=%d duration=%.3fs",
            shlex.join(argv),
            result.returncode,
            duration,
        )
        if check and not result.ok:
            raise CommandError(result)
        return result

    def capture(self, cmd: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> str:
        return self.run(cmd, timeout=timeout, check=True).stdout
