"""Subprocess execution with timeouts, structured logging and dry-run support."""

import locale
import logging
import os
import shlex
import signal
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from time import perf_counter

from lhm.core import colors
from lhm.core.mutations import mutations_allowed

logger = logging.getLogger("lhm.runner")

DEFAULT_TIMEOUT = 30.0

# Bounded wait used when reaping a killed process and draining its pipes. A
# descendant that left the session can hold the inherited pipe write ends open
# forever, so no wait here may be unbounded.
_REAP_GRACE = 0.5

ExecFn = Callable[[list[str], float], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one command invocation."""

    cmd: list[str]
    returncode: int | None  # None for a planned (dry-run) command: nothing ran.
    stdout: str
    stderr: str
    duration_s: float
    was_dry_run: bool = False

    @property
    def ok(self) -> bool:
        """True only for a command that actually exited with status 0."""
        return self.returncode == 0


class CommandError(RuntimeError):
    """Raised when a command exits non-zero and ``check`` was requested."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        message = f"command failed (rc={result.returncode}): {shlex.join(result.cmd)}"
        if result.stderr.strip():
            message += f"\n{result.stderr.strip()}"
        super().__init__(message)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill the initial process group and reap its leader without hanging."""
    try:
        # Descendants that create their own group or session are not covered.
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # Already exited: the exit race, nothing left to signal.
    except PermissionError:  # pragma: no cover - hostile environment
        proc.kill()

    try:
        proc.wait(timeout=_REAP_GRACE)
    except subprocess.TimeoutExpired:  # pragma: no cover - unkillable leader
        logger.warning("pid=%d survived SIGKILL; not waiting further", proc.pid)

    # A descendant that escaped via setsid/daemonisation can still hold the pipe
    # write ends. Closing our read ends is bounded; communicate() would not be.
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:  # pragma: no cover - close rarely fails
                pass


def _default_exec(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    # Match Popen's text-mode encoding without translating line endings here.
    encoding = "utf-8" if sys.flags.utf8_mode else locale.getencoding()
    try:
        # No stdin argument: inherit ours, as the previous subprocess.run did.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: command not found ({exc})")

    try:
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
        stdout, stderr = stdout_bytes.decode(encoding), stderr_bytes.decode(encoding)
    except subprocess.TimeoutExpired:
        # Killing the group is the only bounded way to stop grandchildren
        # (apt-get, dpkg, ...) from mutating the system after we gave up.
        _kill_tree(proc)
        return subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timed out after {timeout}s")
    except BaseException:
        _kill_tree(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


@dataclass
class Runner:
    """Wraps every system call. All commands have a timeout and are logged.

    In dry-run mode commands are recorded in ``planned`` and never executed; a
    placeholder result with ``returncode=None`` and ``was_dry_run=True`` is
    returned. Such a result is not ``ok``: nothing was observed to succeed.
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
        *,
        redact: frozenset[int] = frozenset(),
        preserve_newlines: bool = False,
    ) -> CommandResult:
        """Run a command, normalizing CRLF and CR to LF unless requested otherwise."""
        argv = [str(part) for part in cmd]
        reported = ["<hidden>" if index in redact else value for index, value in enumerate(argv)]
        if self.dry_run or not mutations_allowed():
            self.planned.append(reported)
            logger.info("dry-run planned cmd=%s timeout=%ss", shlex.join(reported), timeout)
            return CommandResult(reported, None, "", "", 0.0, was_dry_run=True)

        start = perf_counter()
        # Echo only in color mode (TTY) or verbose: piped plain output stays clean.
        try:
            if colors.enabled() or self.verbose:
                colors.command(reported)
        except OSError:
            pass  # An output failure must not prevent command execution.
        completed = self.exec_fn(argv, timeout)
        duration = perf_counter() - start
        stdout, stderr = completed.stdout or "", completed.stderr or ""
        if not preserve_newlines:
            stdout = stdout.replace("\r\n", "\n").replace("\r", "\n")
            stderr = stderr.replace("\r\n", "\n").replace("\r", "\n")
        result = CommandResult(
            reported,
            completed.returncode,
            stdout,
            stderr,
            duration,
        )
        self.history.append(result)
        logger.info(
            "cmd=%s rc=%d duration=%.3fs",
            shlex.join(reported),
            result.returncode,
            duration,
        )
        if check and not result.ok:
            raise CommandError(result)
        return result

    def capture(self, cmd: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> str:
        return self.run(cmd, timeout=timeout, check=True).stdout
