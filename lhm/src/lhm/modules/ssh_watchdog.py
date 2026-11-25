"""PID 1 watchdog and volatile journal; callers hold the SSH drop-in flock."""

import hashlib
import json
import logging
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from lhm.core.mutations import mutations_allowed
from lhm.core.runner import Runner

logger = logging.getLogger(__name__)

_ROOT_UID = 0
_STATE_DIR = Path("/run/lhm-ssh-rollback")
_STATE = "pending.json"
_VERSION = 1
_PROTOCOL_VERSION = 4
_MAX_BYTES = 1 << 20
_ID = re.compile(r"[0-9a-f]{32}")
_PHASE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_WINDOW = 600
_TIMEOUT = 10
_PYTHON_ROOT = Path("/opt/lhm-ssh-rollback/python")
_PYTHON = _PYTHON_ROOT / "bin/python3.15"
_PACKAGE = Path("/opt/lhm-ssh-rollback/src")
_SERVICE_PATH = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
_INSTALL = (
    "install a standalone CPython 3.15 at /opt/lhm-ssh-rollback/python and this lhm release's "
    "src/lhm Python sources at /opt/lhm-ssh-rollback/src/lhm without bytecode; use root-owned, "
    "non-writable-by-others, symlink-free trees and keep this build available while rollback "
    "is pending"
)
_BOOTSTRAP = """\
import sys
src, op, txid = sys.argv[1:]
prefix = sys.executable.rsplit('/', 2)[0]
if (sys.version_info[:2] != (3, 15) or sys.prefix != prefix
        or sys.exec_prefix != prefix or sys.base_prefix != prefix
        or not all(p.startswith(prefix + '/') for p in sys.path)):
    raise SystemExit('invalid SSH rollback interpreter prefix')
sys.path.append(src)
from lhm.modules.ssh_watchdog import main
raise SystemExit(main(op, txid))
"""


class WatchdogError(ValueError):
    """The journal or timer could not be safely used."""


def _valid_data(value: object, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or type(value) in (bool, str):
        return True
    if type(value) is int:
        return -(1 << 63) <= value < (1 << 63)
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_valid_data(item, depth + 1) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _valid_data(item, depth + 1) for key, item in value.items())
    return False


def _encode(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()


def _build_id(package: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(package.rglob("*.py")):
        rel = path.relative_to(package)
        if "__pycache__" not in rel.parts:
            digest.update(os.fsencode(rel.as_posix()) + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _runtime_identity() -> str:
    try:
        return _encode(
            dict(
                protocol=_PROTOCOL_VERSION,
                schema=_VERSION,
                build=_build_id(Path(__file__).resolve().parents[1]),
            )
        ).decode()
    except OSError as exc:
        raise WatchdogError(f"cannot identify SSH rollback build: {exc}") from exc


@dataclass(frozen=True, init=False, slots=True)
class Pending:
    id: str
    deadline: float  # CLOCK_MONOTONIC seconds, not wall time.
    phase: str
    _data: bytes = field(repr=False)

    def __init__(self, id: str, deadline: float, phase: str, data: dict[str, object]) -> None:
        if (
            type(id) is not str
            or not _ID.fullmatch(id)
            or type(deadline) not in (int, float)
            or not 0 < deadline <= time.monotonic() + _WINDOW + _TIMEOUT
            or type(phase) is not str
            or not _PHASE.fullmatch(phase)
            or type(data) is not dict
            or not _valid_data(data)
        ):
            raise WatchdogError("invalid SSH rollback state")
        encoded = _encode(data)
        if len(encoded) > _MAX_BYTES:
            raise WatchdogError("SSH rollback state is too large")
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "deadline", float(deadline))
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "_data", encoded)

    @property
    def data(self) -> dict[str, object]:
        """A detached copy, including nested values."""
        return json.loads(self._data)


def _trusted(info: os.stat_result, path: Path, *, directory: bool) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022:
        raise WatchdogError(f"untrusted SSH rollback path: {path}")


def _trusted_path(path: Path, *, directory: bool) -> None:
    if path.anchor != "/" or ".." in path.parts:
        raise WatchdogError(f"not a canonical absolute SSH rollback path: {path}")
    for parent in reversed(path.parents):
        _trusted(parent.lstat(), parent, directory=True)
    _trusted(path.lstat(), path, directory=directory)


def _trusted_tree(path: Path, *, source_only: bool = False) -> None:
    with os.scandir(path) as entries:
        for entry in entries:
            child = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            _trusted(info, child, directory=directory)
            if directory:
                _trusted_tree(child, source_only=source_only)
            elif source_only and child.suffix != ".py":
                # -B does not stop Python from *reading* an existing .pyc.
                raise WatchdogError(f"non-source file in SSH rollback package: {child}")


@contextmanager
def _state_dir(*, create: bool = False) -> Iterator[int | None]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY
    try:
        _trusted_path(_STATE_DIR.parent, directory=True)
        parent = os.open(_STATE_DIR.parent, flags)
        try:
            if create:
                try:
                    os.mkdir(_STATE_DIR.name, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                else:
                    os.fsync(parent)
            try:
                fd = os.open(_STATE_DIR.name, flags, dir_fd=parent)
            except FileNotFoundError:
                yield None
                return
            try:
                info = os.fstat(fd)
                _trusted(info, _STATE_DIR, directory=True)
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise WatchdogError(f"SSH rollback directory must be mode 0700: {_STATE_DIR}")
                yield fd
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    except OSError as exc:
        raise WatchdogError(f"cannot access SSH rollback journal: {exc}") from exc


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WatchdogError("duplicate member in SSH rollback state")
        result[key] = value
    return result


def _check_marker(info: os.stat_result) -> None:
    _trusted(info, _STATE_DIR / _STATE, directory=False)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise WatchdogError("SSH rollback marker must be mode 0600 with no other links")
    if not 0 < info.st_size <= _MAX_BYTES:
        raise WatchdogError("invalid SSH rollback marker size")


def _read(fd: int) -> Pending | None:
    try:
        info = os.stat(_STATE, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _check_marker(info)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(_STATE, flags, dir_fd=fd), "rb") as handle:
        _check_marker(os.fstat(handle.fileno()))
        raw = handle.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise WatchdogError("SSH rollback state is too large")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members)
        if (
            type(obj) is not dict
            or set(obj) != {"version", "id", "deadline", "phase", "data"}
            or type(obj["version"]) is not int
            or obj["version"] != _VERSION
        ):
            raise WatchdogError("invalid SSH rollback state version or fields")
        return Pending(obj["id"], obj["deadline"], obj["phase"], obj["data"])
    except (ValueError, RecursionError) as exc:
        raise WatchdogError("invalid SSH rollback marker") from exc


def _store(fd: int, pending: Pending) -> None:
    raw = _encode(
        dict(
            version=_VERSION,
            id=pending.id,
            deadline=pending.deadline,
            phase=pending.phase,
            data=pending.data,
        )
    )
    if len(raw) > _MAX_BYTES:
        raise WatchdogError("SSH rollback state is too large")
    temp = f".pending-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(temp, flags, 0o600, dir_fd=fd), "wb") as handle:
        try:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temp, _STATE, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(temp, dir_fd=fd)
            except FileNotFoundError:
                pass


def current() -> Pending | None:
    """Read the active marker without creating anything, even in dry-run."""
    with _state_dir() as fd:
        return None if fd is None else _read(fd)


def _unit(pending: Pending) -> str:
    return f"lhm-ssh-rollback-{pending.id}"


def _invoke(runner: Runner, argv: list[str], description: str) -> str:
    try:
        redact = frozenset(i for i, arg in enumerate(argv) if arg == _BOOTSTRAP)
        result = runner.run(argv, check=False, timeout=_TIMEOUT, redact=redact)
    except (OSError, ValueError) as exc:
        raise WatchdogError(f"{description} failed: {exc}") from exc
    if not result.ok:
        raise WatchdogError(f"{description} failed (exit {result.returncode})")
    return result.stdout


def _launcher() -> list[str]:
    try:
        for path in (_PYTHON_ROOT, _PYTHON, _PACKAGE):
            if any(ch in str(path) for ch in "$%\x00\n\r"):
                raise WatchdogError(f"unsafe systemd argument: {path}")
        _trusted_path(_PYTHON_ROOT, directory=True)
        _trusted_tree(_PYTHON_ROOT)
        _trusted_path(_PYTHON, directory=False)
        if not _PYTHON.stat().st_mode & stat.S_IXUSR:
            raise WatchdogError(f"not executable: {_PYTHON}")
        _trusted_path(_PACKAGE, directory=True)
        _trusted_tree(_PACKAGE, source_only=True)
        _trusted_path(_PACKAGE / "lhm/__init__.py", directory=False)
        _trusted_path(_PACKAGE / "lhm/modules/ssh_watchdog.py", directory=False)
    except (OSError, WatchdogError) as exc:
        raise WatchdogError(f"unsafe or missing SSH rollback runtime: {exc}; {_INSTALL}") from exc
    return [str(_PYTHON), "-I", "-S", "-B", "-c", _BOOTSTRAP, str(_PACKAGE)]


def _probe(
    runner: Runner,
    unit: str,
    interface: str,
    *,
    read: tuple[str, str] | None = None,
    **expected: tuple[str, object],
) -> object:
    # Unit names come from the fixed prefix, hex transaction ID and unit suffix.
    path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(".", "_2e")
    properties = {name: signature for name, (signature, _) in expected.items()}
    if read is not None:
        properties[read[0]] = read[1]
    raw = _invoke(
        runner,
        [
            "/usr/bin/busctl",
            "--json=short",
            "--address=unix:path=/run/dbus/system_bus_socket",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            f"org.freedesktop.systemd1.{interface}",
            *properties,
        ],
        f"probe watchdog unit {unit}",
    )
    # Each requested property has a typed JSON document, in request order.
    decoder = json.JSONDecoder(object_pairs_hook=_unique_members)
    value: object = None
    for name, signature in properties.items():
        try:
            raw = raw.lstrip()
            row, end = decoder.raw_decode(raw)
            raw = raw[end:]
        except (ValueError, RecursionError) as exc:
            raise WatchdogError(f"invalid D-Bus response for {unit} {name}") from exc
        if type(row) is not dict or set(row) != {"type", "data"} or row["type"] != signature:
            raise WatchdogError(f"invalid D-Bus property for {unit} {name}")
        data = row["data"]
        if name in expected:
            wanted = expected[name][1]
            if type(data) is not type(wanted) or data != wanted:
                raise WatchdogError(f"unexpected watchdog property: {unit} {name}")
        else:
            value = data
    if raw.strip():
        raise WatchdogError(f"trailing D-Bus output for {unit}")
    return value


def _deadline(value: object, before: float, after: float) -> float:
    if type(value) is not int or not 0 < value < 2**64:
        raise WatchdogError("invalid watchdog monotonic deadline")
    deadline = value / 1_000_000
    if (
        deadline <= time.monotonic()
        or not before + _WINDOW - 0.000001 <= deadline <= after + _WINDOW
    ):
        raise WatchdogError("watchdog deadline does not match the requested 10-minute window")
    return deadline


def arm(runner: Runner, data: dict[str, object]) -> Pending:
    """Persist an inert record before scheduling; allow writes only after verification."""
    if runner.dry_run or not mutations_allowed() or os.geteuid() != _ROOT_UID:
        raise WatchdogError("arming SSH rollback requires a live root run")
    if current() is not None:
        raise WatchdogError("another SSH rollback transaction is pending")
    launcher = _launcher()
    txid = secrets.token_hex(16)
    identity = _runtime_identity()
    remote = _invoke(runner, [*launcher, "probe", txid], f"test SSH rollback runtime; {_INSTALL}")
    if remote.strip() != identity:
        raise WatchdogError(f"SSH rollback runtime protocol/schema or build mismatch; {_INSTALL}")
    prepared = Pending(txid, time.monotonic() + _WINDOW, "prepared", data)
    with _state_dir(create=True) as fd:
        if fd is None or _read(fd) is not None:
            raise WatchdogError("cannot prepare SSH rollback marker")
        _store(fd, prepared)
    unit = _unit(prepared)
    timer = f"{unit}.timer"
    service = f"{unit}.service"
    worker = [*launcher, "expire", txid]
    try:
        before = time.monotonic()
        _invoke(
            runner,
            [
                "/usr/bin/systemd-run",
                "--system",
                "--quiet",
                f"--unit={unit}",
                f"--on-active={_WINDOW}s",
                "--timer-property=AccuracySec=1s",
                "--timer-property=RemainAfterElapse=no",
                "--service-type=exec",
                "--property=User=root",
                "--property=Group=root",
                "--property=TimeoutStartSec=15s",
                "--property=StartLimitIntervalSec=0",
                "--property=Restart=no",
                "--property=RestartSec=5s",
                "--property=RestartForceExitStatus=75",
                "--property=WorkingDirectory=/",
                f"--setenv={_SERVICE_PATH}",
                "--",
                *worker,
            ],
            "schedule SSH rollback watchdog",
        )
        after = time.monotonic()
        _probe(
            runner,
            timer,
            "Unit",
            Id=("s", timer),
            LoadState=("s", "loaded"),
            ActiveState=("s", "active"),
            SubState=("s", "waiting"),
            Transient=("b", True),
            DropInPaths=("as", []),
        )
        _probe(
            runner,
            service,
            "Unit",
            Id=("s", service),
            LoadState=("s", "loaded"),
            ActiveState=("s", "inactive"),
            SubState=("s", "dead"),
            Transient=("b", True),
            DropInPaths=("as", []),
            TriggeredBy=("as", [timer]),
            StartLimitIntervalUSec=("t", 0),
        )
        _probe(
            runner,
            service,
            "Service",
            Type=("s", "exec"),
            User=("s", "root"),
            Group=("s", "root"),
            DynamicUser=("b", False),
            WorkingDirectory=("s", "/"),
            RootDirectory=("s", ""),
            RootImage=("s", ""),
            Environment=("as", [_SERVICE_PATH]),
            Restart=("s", "no"),
            RestartUSec=("t", 5_000_000),
            RestartForceExitStatus=("(aiai)", [[75], []]),
            # One exact command, no ignore-failure flag, never yet executed.
            ExecStart=("a(sasbttttuii)", [[worker[0], worker, False, *([0] * 7)]]),
        )
        value = _probe(
            runner,
            timer,
            "Timer",
            read=("NextElapseUSecMonotonic", "t"),
            Unit=("s", service),
            AccuracyUSec=("t", 1_000_000),
            WakeSystem=("b", False),
        )
        deadline = _deadline(value, before, after)
        armed = Pending(txid, deadline, "armed", prepared.data)
        with _state_dir() as fd:
            if fd is None or _read(fd) != prepared:
                raise WatchdogError("prepared SSH rollback marker changed")
            _store(fd, armed)
        return armed
    except BaseException:
        # A timed-out manager request might have started the timer. Remove
        # authorization even if stopping it fails or races a late start.
        try:
            clear(runner, prepared)
        except WatchdogError as exc:
            logger.warning("could not invalidate unverified watchdog %s: %s", txid, exc)
        raise


def update(pending: Pending, *, phase: str | None = None, **data: object) -> Pending:
    """Replace phase and/or merge fields into the current record of this transaction."""
    if not mutations_allowed():
        raise WatchdogError("cannot update an SSH rollback marker in dry-run")
    with _state_dir() as fd:
        existing = None if fd is None else _read(fd)
        if fd is None or existing is None or existing.id != pending.id:
            raise WatchdogError("stale SSH rollback marker")
        updated = Pending(
            existing.id,
            existing.deadline,
            existing.phase if phase is None else phase,
            existing.data | data,
        )
        _store(fd, updated)
        return updated


def clear(runner: Runner, pending: Pending) -> None:
    """Invalidate the marker first, then stop only its timer on a best-effort basis."""
    if runner.dry_run or not mutations_allowed():
        raise WatchdogError("cannot clear an SSH rollback marker in dry-run")
    with _state_dir() as fd:
        existing = None if fd is None else _read(fd)
        if fd is None or existing is None or existing.id != pending.id:
            return
        os.unlink(_STATE, dir_fd=fd)
        os.fsync(fd)
    try:
        _invoke(
            runner,
            ["/usr/bin/systemctl", "--system", "stop", f"{_unit(existing)}.timer"],
            "stop SSH rollback timer",
        )
    except WatchdogError as exc:
        logger.warning("SSH rollback marker cleared, but %s", exc)


def main(op: str, txid: str) -> int:
    """Only the isolated bootstrap calls this entry point."""
    if op not in {"probe", "expire"} or not _ID.fullmatch(txid):
        return 64
    from lhm.modules.ssh import expire_watchdog

    if op == "probe":
        if not callable(expire_watchdog):
            return 1
        print(_runtime_identity())
        return 0
    return expire_watchdog(txid)
