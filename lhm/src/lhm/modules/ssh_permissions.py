"""Inspect and change existing SSH modes without following user-controlled paths."""

import ctypes
import errno
import hashlib
import os
import re
import select
import shlex
import signal
import stat
import struct
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

from lhm.core.userkeys import Account

_PIN = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY = _PIN | os.O_DIRECTORY
_STATX_BTIME = 0x0800
_AT_EMPTY_PATH = 0x1000
_PROC_SUPER_MAGIC = 0x9FA0
_TRANSIENT = {
    errno.EAGAIN,
    errno.EBUSY,
    errno.EINTR,
    errno.EIO,
    errno.ESTALE,
    errno.ETIMEDOUT,
    errno.EMFILE,
    errno.ENFILE,
    errno.ENOMEM,
}
_CHMOD_TIMEOUT = 5
_REAP_TIMEOUT_MS = 500
_RECEIPT = struct.Struct("!iq")
_KEY_LIMIT = 1024 * 1024


class SshPermissionsError(ValueError):
    """An SSH permission target is unsafe or changed."""


class ChmodStillRunning(SshPermissionsError):
    """Only the watchdog may recover once the inherited flock is released."""


def retryable(exc: Exception) -> bool:
    return isinstance(exc, OSError) and exc.errno in _TRANSIENT


def _identity(fd: int) -> list[int]:
    """Device, inode, UID/GID and immutable birth time, or refuse recovery."""

    # Linux statx has a fixed 256-byte ABI. stx_btime begins at byte 80.
    class BirthTime(ctypes.Structure):
        _fields_ = [
            ("mask", ctypes.c_uint32),
            ("before", ctypes.c_ubyte * 76),
            ("seconds", ctypes.c_int64),
            ("nanoseconds", ctypes.c_uint32),
            ("after", ctypes.c_ubyte * 164),
        ]

    info = os.fstat(fd)
    result = BirthTime()
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, "statx"):
        if libc.statx(fd, b"", _AT_EMPTY_PATH, _STATX_BTIME, ctypes.byref(result)) != 0:
            code = ctypes.get_errno()
            if code in _TRANSIENT:
                raise OSError(code, "could not inspect SSH inode identity")
    if not result.mask & _STATX_BTIME or not result.seconds:
        raise SshPermissionsError("filesystem does not provide a durable SSH inode identity")
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, result.seconds, result.nanoseconds]


def _safe_mode(mode: int) -> bool:
    return mode & 0o7022 == 0


def _chmod_fd(fd: int, mode: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    if hasattr(libc, "fchmodat") and libc.fchmodat(fd, b"", mode, _AT_EMPTY_PATH) == 0:
        return
    code = ctypes.get_errno()
    if code not in (0, errno.EINVAL, errno.ENOSYS, errno.ENOENT, errno.EOPNOTSUPP):
        raise OSError(code, "could not chmod pinned SSH inode")
    # Older libc/kernel pairs lack AT_EMPTY_PATH. Pin procfs itself and use
    # its FD magic link; do not resolve a path through an unverified /proc.
    proc = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        fs = (ctypes.c_long * 32)()
        if libc.fstatfs(proc, ctypes.byref(fs)):
            code = ctypes.get_errno()
            raise OSError(code, "could not inspect procfs for pinned chmod")
        if fs[0] != _PROC_SUPER_MAGIC:
            raise SshPermissionsError("could not verify procfs for pinned chmod")
        if not os.path.samestat(os.fstat(fd), os.stat(str(fd), dir_fd=proc)):
            raise SshPermissionsError("procfs FD does not identify the pinned SSH inode")
        os.chmod(str(fd), mode, dir_fd=proc)
    finally:
        os.close(proc)


def _drop_credentials(account: Account) -> None:
    if os.getresuid() == (0, 0, 0):
        os.setgroups([])
        os.setgid(account.gid)
        os.setuid(account.uid)
        if os.getgroups():
            raise SshPermissionsError("could not clear supplementary groups")
    if os.getresuid() != (account.uid,) * 3 or os.getresgid() != (account.gid,) * 3:
        raise SshPermissionsError("credential drop failed")


def _key_digest(target: Target) -> str:
    def metadata(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    original = target.original
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(f"/proc/self/fd/{target.fd}", flags), "rb") as handle:
        before = os.fstat(handle.fileno())
        if not os.path.samestat(original, before) or not stat.S_ISREG(before.st_mode):
            raise SshPermissionsError(f"authorized_keys identity changed: {target.path}")
        if metadata(original) != metadata(before) or before.st_size > _KEY_LIMIT:
            raise SshPermissionsError(f"authorized_keys unsafe or changed: {target.path}")
        data = handle.read(_KEY_LIMIT + 1)
        handle.seek(0)
        if (
            len(data) != before.st_size
            or handle.read(_KEY_LIMIT + 1) != data
            or metadata(os.fstat(handle.fileno())) != metadata(before)
        ):
            raise SshPermissionsError(f"authorized_keys contents changed: {target.path}")
        return hashlib.sha256(data).hexdigest()


def _chmod_child(
    fd: int, mode: int, expected: os.stat_result, account: Account, output: int, lock_fd: int | None
) -> None:
    # This fork-only child keeps the transaction's flock OFD until _exit, even
    # if the caller dies. Never unlock it explicitly or execute another program.
    try:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(_CHMOD_TIMEOUT)
        keep = {fd, output, lock_fd}
        for name in os.listdir("/proc/self/fd"):
            other = int(name)
            if other not in keep:
                try:
                    os.close(other)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        _drop_credentials(account)
        before = os.fstat(fd)
        if (
            not os.path.samestat(expected, before)
            or (before.st_uid, before.st_gid) != (expected.st_uid, expected.st_gid)
            or before.st_mode != expected.st_mode
            or before.st_ctime_ns != expected.st_ctime_ns
            or before.st_nlink != expected.st_nlink
            or mode & ~stat.S_IMODE(before.st_mode)
        ):
            raise SshPermissionsError("pinned SSH inode changed before chmod")
        _chmod_fd(fd, mode)
        after = os.fstat(fd)
        if stat.S_IMODE(after.st_mode) != mode or (after.st_uid, after.st_gid, after.st_nlink) != (
            before.st_uid,
            before.st_gid,
            before.st_nlink,
        ):
            raise SshPermissionsError("pinned SSH inode changed after chmod")
        receipt = _RECEIPT.pack(0, after.st_ctime_ns)
    except OSError as exc:
        receipt = _RECEIPT.pack(exc.errno or errno.EIO, 0)
    except BaseException:
        receipt = _RECEIPT.pack(-1, 0)
    try:
        os.write(output, receipt)
    finally:
        os._exit(0)


def _fork_chmod(
    fd: int, mode: int, expected: os.stat_result, account: Account, lock_fd: int | None
) -> int:
    if len(os.listdir("/proc/self/task")) != 1:
        raise SshPermissionsError("SSH chmod requires a single-threaded process")
    with ExitStack() as fds:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        fds.callback(os.close, read_fd)
        fds.callback(os.close, write_fd)
        pid = os.fork()
        if pid == 0:
            _chmod_child(fd, mode, expected, account, write_fd, lock_fd)
            os._exit(1)
        poll = select.poll()
        child: int | None = None
        try:
            child = os.pidfd_open(pid)
            fds.callback(os.close, child)
            poll.register(child, select.POLLIN)
            if not poll.poll((_CHMOD_TIMEOUT + 1) * 1000):
                raise TimeoutError(errno.ETIMEDOUT, "SSH chmod child timed out")
            _, status = os.waitpid(pid, 0)
        except BaseException as exc:
            try:
                if child is None:
                    os.kill(pid, signal.SIGKILL)
                else:
                    signal.pidfd_send_signal(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if child is not None:
                poll.poll(_REAP_TIMEOUT_MS)
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                reaped = pid
            if not reaped:
                detail = "SSH chmod child has not exited; watchdog retained"
                raise ChmodStillRunning(detail) from exc
            raise
        if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGALRM:
            raise TimeoutError(errno.ETIMEDOUT, "SSH chmod child timed out")
        receipt = os.read(read_fd, _RECEIPT.size + 1)
        if status != 0 or len(receipt) != _RECEIPT.size:
            raise SshPermissionsError("SSH chmod child did not report a result")
        code, ctime = _RECEIPT.unpack(receipt)
        if code in _TRANSIENT:
            raise OSError(code, "temporary SSH chmod error")
        if code != 0 or not 0 < ctime < 2**63:
            raise SshPermissionsError("SSH chmod refused or inode changed")
        return ctime


@dataclass(frozen=True)
class Target:
    path: Path
    fd: int
    original: os.stat_result
    mode: int

    @property
    def old_mode(self) -> int:
        return stat.S_IMODE(self.original.st_mode)

    def chmod(self, mode: int, account: Account, lock_fd: int | None = None) -> int:
        return _fork_chmod(self.fd, mode, self.original, account, lock_fd)


@contextmanager
def _open(account: Account) -> Iterator[tuple[int, tuple[Target, ...]]]:
    home = account.home
    if home.anchor != "/" or not home.name or ".." in home.parts:
        raise SshPermissionsError("unsafe NSS home path")
    with ExitStack() as fds:

        def pin(name: str, flags: int, parent: int | None = None) -> int:
            fd = os.open(name, flags, dir_fd=parent)
            fds.callback(os.close, fd)
            return fd

        directory = pin("/", _DIRECTORY)
        for part in home.parts[1:]:
            directory = pin(part, _DIRECTORY, directory)
        info = os.fstat(directory)
        if info.st_uid not in (0, account.uid) or not _safe_mode(info.st_mode):
            raise SshPermissionsError(f"unsafe home ownership or mode: {home}")
        ssh_path = home / ".ssh"
        try:
            ssh = pin(".ssh", _DIRECTORY, directory)
        except FileNotFoundError:
            yield directory, ()
            return
        info = os.fstat(ssh)
        if info.st_uid != account.uid:
            raise SshPermissionsError(f"wrong owner: {ssh_path}")
        if not _safe_mode(info.st_mode):
            raise SshPermissionsError(f"unsafe write or special permission bits: {ssh_path}")
        targets = (Target(ssh_path, ssh, info, 0o700),)
        try:
            keys = pin("authorized_keys", _PIN, ssh)
        except FileNotFoundError:
            pass
        else:
            info = os.fstat(keys)
            key_path = ssh_path / "authorized_keys"
            if not stat.S_ISREG(info.st_mode) or info.st_uid != account.uid or info.st_nlink != 1:
                raise SshPermissionsError(f"unsafe type, owner or hard links: {key_path}")
            if not _safe_mode(info.st_mode):
                raise SshPermissionsError(f"unsafe write or special permission bits: {key_path}")
            targets += (Target(key_path, keys, info, 0o600),)
        yield directory, targets


@dataclass(frozen=True)
class Plan:
    account: Account
    home: int
    original_home: os.stat_result
    targets: tuple[Target, ...]
    key_digest: str | None

    @property
    def changes(self) -> tuple[Target, ...]:
        return tuple(target for target in self.targets if target.old_mode != target.mode)

    def manifest(self) -> dict[str, object]:
        account = self.account
        return {
            "account": [account.name, account.uid, account.gid, str(account.home)],
            "home": _identity(self.home),
            "targets": [[_identity(target.fd), target.old_mode] for target in self.targets],
            "key_digest": self.key_digest,
        }

    def verify(self, modes: tuple[int, ...], ctimes: tuple[int, ...]) -> None:
        with _open(self.account) as (home, targets):
            info = os.fstat(home)
            if (
                not os.path.samestat(self.original_home, info)
                or (info.st_uid, info.st_gid, info.st_mode)
                != (
                    self.original_home.st_uid,
                    self.original_home.st_gid,
                    self.original_home.st_mode,
                )
                or len(targets) != len(self.targets)
                or any(
                    not os.path.samestat(target.original, other.original)
                    or target.original.st_gid != other.original.st_gid
                    or other.old_mode != mode
                    or other.original.st_ctime_ns != ctime
                    for target, other, mode, ctime in zip(
                        self.targets, targets, modes, ctimes, strict=True
                    )
                )
            ):
                raise SshPermissionsError("SSH permission paths or modes changed; rerun to review")
            if len(targets) == 2 and _key_digest(targets[1]) != self.key_digest:
                raise SshPermissionsError(f"authorized_keys contents changed: {targets[1].path}")

    def verify_original(self) -> None:
        self.verify(
            tuple(target.old_mode for target in self.targets),
            tuple(target.original.st_ctime_ns for target in self.targets),
        )

    def require_narrowing(self) -> None:
        for target in self.changes:
            if target.mode & ~target.old_mode:
                raise SshPermissionsError(
                    f"would add permission bits on {target.path}; adjust manually from the console"
                )

    def apply(
        self,
        before_chmod: Callable[[int, int], None],
        after_chmod: Callable[[int, int], None],
        *,
        lock_fd: int | None = None,
    ) -> None:
        self.require_narrowing()
        modes = [target.old_mode for target in self.targets]
        ctimes = [target.original.st_ctime_ns for target in self.targets]
        for index, target in enumerate(self.targets):
            if target not in self.changes:
                continue
            self.verify(tuple(modes), tuple(ctimes))
            before_chmod(index, ctimes[index])
            ctimes[index] = target.chmod(target.mode, self.account, lock_fd)
            modes[index] = target.mode
            self.verify(tuple(modes), tuple(ctimes))
            after_chmod(index, ctimes[index])


@contextmanager
def inspect(account: Account) -> Iterator[Plan]:
    with _open(account) as (home, targets):
        digest = _key_digest(targets[1]) if len(targets) == 2 else None
        yield Plan(account, home, os.fstat(home), targets, digest)


@dataclass(frozen=True)
class Operation:
    index: int
    before: int
    after: int | None


@dataclass(frozen=True)
class Recovery:
    account: Account
    home: list[int]
    targets: tuple[tuple[list[int], int], ...]
    key_digest: str | None

    @property
    def changed_indices(self) -> tuple[int, ...]:
        return tuple(
            i
            for i, ((_, mode), goal) in enumerate(zip(self.targets, (0o700, 0o600), strict=False))
            if mode != goal
        )

    def operations(self, value: object) -> tuple[Operation, ...]:
        invalid = SshPermissionsError("invalid SSH permission chmod journal")
        if not isinstance(value, list) or len(value) > len(self.changed_indices):
            raise invalid
        operations = []
        for pos, row in enumerate(value):
            if (
                not isinstance(row, list)
                or len(row) != 3
                or type(row[0]) is not int
                or row[0] != self.changed_indices[pos]
                or type(row[1]) is not int
                or not 0 < row[1] < 2**63
                or (row[2] is None and pos != len(value) - 1)
                or (row[2] is not None and (type(row[2]) is not int or not 0 < row[2] < 2**63))
            ):
                raise invalid
            operations.append(Operation(*row))
        return tuple(operations)

    @classmethod
    def parse(cls, value: object) -> Recovery:
        invalid = SshPermissionsError("invalid SSH permission recovery state")

        def identity(row: object) -> list[int]:
            if (
                not isinstance(row, list)
                or len(row) != 6
                or not all(type(part) is int and 0 <= part < 2**63 for part in row)
                or not row[1]
                or not row[4]
                or row[5] >= 1_000_000_000
                or row[2] >= 2**32 - 1
                or row[3] >= 2**32 - 1
            ):
                raise invalid
            return row

        if not isinstance(value, dict) or value.keys() != {
            "account",
            "home",
            "targets",
            "key_digest",
        }:
            raise invalid
        row, home, targets = value["account"], identity(value["home"]), value["targets"]
        if (
            not isinstance(row, list)
            or len(row) != 4
            or not isinstance(row[0], str)
            or not isinstance(row[3], str)
            or Path(row[3]).anchor != "/"
            or Path(row[3]).is_relative_to("/root")
            or ".." in Path(row[3]).parts
            or str(Path(row[3])) != row[3]
            or not isinstance(targets, list)
            or not 1 <= len(targets) <= 2
        ):
            raise invalid
        account = Account(row[0], row[1], row[2], Path(row[3]))
        if account.name == "root" or home[2] not in (0, account.uid):
            raise invalid
        entries = []
        for entry in targets:
            if (
                not isinstance(entry, list)
                or len(entry) != 2
                or type(entry[1]) is not int
                or not 0 <= entry[1] <= 0o777
                or not _safe_mode(entry[1])
                or (0o700 if not entries else 0o600) & ~entry[1]
            ):
                raise invalid
            inode = identity(entry[0])
            if inode[2] != account.uid:
                raise invalid
            entries.append((inode, entry[1]))
        digest = value["key_digest"]
        if (
            len(entries) == 2
            and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest))
        ) or (len(entries) == 1 and digest is not None):
            raise invalid
        recovery = cls(account, home, tuple(entries), digest)
        if not recovery.changed_indices:
            raise invalid
        return recovery

    def check(
        self, plan: Plan, operations: tuple[Operation, ...], *, confirm: bool, manual: bool
    ) -> None:
        if _identity(plan.home) != self.home or len(plan.targets) != len(self.targets):
            raise SshPermissionsError("SSH permission paths changed; left untouched")
        if plan.key_digest != self.key_digest:
            raise SshPermissionsError("authorized_keys contents changed; left untouched")
        by_index = {op.index: op for op in operations}
        for index, (target, (identity, old_mode)) in enumerate(
            zip(plan.targets, self.targets, strict=True)
        ):
            if _identity(target.fd) != identity:
                raise SshPermissionsError(f"SSH permission inode changed: {target.path}")
            op = by_index.get(index)
            if manual:
                if op is not None and target.old_mode != old_mode:
                    raise SshPermissionsError(f"original mode not yet restored: {target.path}")
                continue
            if op is not None and op.after is None:
                raise SshPermissionsError(f"ambiguous chmod intent without receipt: {target.path}")
            if op is not None and (
                op.after != target.original.st_ctime_ns or target.old_mode != target.mode
            ):
                raise SshPermissionsError(f"post-chmod mode or ctime changed: {target.path}")
            if confirm and target.old_mode != target.mode:
                raise SshPermissionsError(f"expected hardened mode not verified: {target.path}")
        plan.verify_original()
        if not confirm and not manual and operations:
            raise SshPermissionsError("automatic permission widening is disabled")

    def console_plan(self, operations: tuple[Operation, ...]) -> str:
        ssh_dir = self.account.home / ".ssh"
        paths = (ssh_dir, ssh_dir / "authorized_keys")
        commands = []
        for op in operations:
            ident, mode = self.targets[op.index]
            path = shlex.quote(str(paths[op.index]))
            commands.append(
                f"device {ident[0]}, inode {ident[1]}, UID {ident[2]}, GID {ident[3]}, "
                f"birth {ident[4]}.{ident[5]:09d}: chmod {mode:04o} -- {path}"
            )
        return "; ".join(commands)
