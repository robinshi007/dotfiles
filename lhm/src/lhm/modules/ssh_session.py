"""Verify freshness of a stock OpenSSH transport, not its endpoint or auth factors."""

import os
import re
import time
from contextlib import ExitStack
from dataclasses import dataclass
from os import stat as file_stat
from pathlib import Path
from stat import S_ISREG

from lhm.core.userkeys import Account

_PROC = Path("/proc")
_BOOT_ID = re.compile(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_SSHD = {
    "sshd": Path("/usr/sbin/sshd"),
    "sshd-session": Path("/usr/lib/openssh/sshd-session"),
}
_MAX_DEPTH = 64


class SshSessionError(ValueError):
    """A fresh SSH transport could not be established from local evidence."""


def _boot_id() -> str:
    raw = (_PROC / "sys/kernel/random/boot_id").read_bytes().removesuffix(b"\n")
    if not _BOOT_ID.fullmatch(raw):
        raise ValueError("invalid Linux boot ID")
    return raw.decode("ascii")


def freshness_cutoff() -> tuple[str, int]:
    """Read Linux boot ID and the boottime clock in /proc/PID/stat units."""
    try:
        boot_id = _boot_id()
        hz = os.sysconf("SC_CLK_TCK")
        if hz <= 0:
            raise ValueError("invalid clock tick rate")
        return boot_id, time.clock_gettime_ns(time.CLOCK_BOOTTIME) * hz // 1_000_000_000
    except (OSError, ValueError) as exc:
        raise SshSessionError("cannot read Linux boot ID and boottime; check /proc") from exc


def _read(fd: int, name: str, limit: int) -> bytes:
    with os.fdopen(os.open(name, os.O_RDONLY, dir_fd=fd), "rb") as stream:
        return stream.read(limit)


@dataclass(frozen=True)
class _Process:
    fd: int
    pid: int
    parent: int
    tick: int

    @classmethod
    def read(cls, fd: int, pid: int) -> "_Process":
        # The comm field may contain spaces, newlines and closing parentheses.
        head, separator, tail = _read(fd, "stat", 4096).rpartition(b") ")
        fields = tail.split()
        if (
            not separator
            or not head.startswith(f"{pid} (".encode())
            or len(fields) < 20
            or fields[0] in {b"Z", b"X", b"x"}
        ):
            raise ValueError("invalid or exited process in SSH ancestry")
        return cls(fd, pid, int(fields[1]), int(fields[19]))


def _uid(fd: int, expected: int) -> bool:
    for line in _read(fd, "status", 4096).splitlines():
        name, _, value = line.partition(b":")
        if name == b"Uid":
            fields = value.split()
            return len(fields) == 4 and int(fields[0]) == int(fields[1]) == expected
    return False


def _require_pair(monitor: _Process, worker: _Process, executable: Path, uid: int) -> None:
    # OpenSSH 9.6 sshd.c and 10.0 sshd-session.c privsep_postauth: the monitor
    # forks a direct child that drops to the login UID and runs the session.
    reference = file_stat(executable, follow_symlinks=False)
    if not (
        S_ISREG(reference.st_mode)
        and reference.st_uid == 0
        and not reference.st_mode & 0o022
        and _uid(monitor.fd, 0)
        and _uid(worker.fd, uid)
        and os.path.samestat(file_stat("exe", dir_fd=monitor.fd), reference)
        and os.path.samestat(file_stat("exe", dir_fd=worker.fd), reference)
    ):
        raise ValueError("SSH monitor and account worker identity could not be verified")


def _require_ancestry(boot_id: str, cutoff_tick: int, account: Account) -> None:
    if type(cutoff_tick) is not int or cutoff_tick < 0 or _boot_id() != boot_id:
        raise ValueError("invalid SSH freshness cutoff or boot ID changed")
    titles = {f"{name}: {account.name} [priv]".encode(): path for name, path in _SSHD.items()}
    title_limit = max(map(len, titles)) + 1
    pid = os.getpid()
    chain: list[_Process] = []
    with ExitStack() as fds:
        for _ in range(_MAX_DEPTH):
            if pid <= 1 or any(proc.pid == pid for proc in chain):
                break
            # Keep the proc directory open: relative reads never follow a reused PID.
            fd = os.open(_PROC / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.callback(os.close, fd)
            proc = _Process.read(fd, pid)
            if chain and proc.tick > chain[-1].tick:
                raise ValueError("SSH ancestry changed")
            title, separator, _ = _read(fd, "cmdline", title_limit).partition(b"\0")
            executable = titles.get(title) if separator else None
            if executable is not None:
                if not chain or proc.tick <= cutoff_tick:
                    raise ValueError("SSH transport did not start strictly after the cutoff")
                worker = chain[-1]
                _require_pair(proc, worker, executable, account.uid)
                if _read(fd, "cmdline", len(title) + 1) != title + b"\0":
                    raise ValueError("SSH ancestry changed")
                _require_pair(proc, worker, executable, account.uid)
                chain.append(proc)
                if any(_Process.read(item.fd, item.pid) != item for item in reversed(chain)):
                    raise ValueError("SSH ancestry changed")
                if _boot_id() != boot_id:
                    raise ValueError("boot ID changed")
                return
            chain.append(proc)
            pid = proc.parent
    raise ValueError("no supported SSH transport in process ancestry")


def require_fresh_ssh(boot_id: str, cutoff_tick: int, *, account: Account) -> None:
    """Require a provably newer privileged monitor in this command's ancestry."""
    try:
        _require_ancestry(boot_id, cutoff_tick, account)
    except (OSError, ValueError) as exc:
        raise SshSessionError(
            f"cannot verify a fresh SSH transport ({exc}); retry from a new SSH login "
            f"as {account.name} with -o ControlPath=none, or allow rollback"
        ) from exc
