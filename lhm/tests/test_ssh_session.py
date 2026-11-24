import os
from collections.abc import Callable
from pathlib import Path

import pytest

from lhm.core.userkeys import Account
from lhm.modules import ssh_session

_BOOT = "d5bd8c51-70bc-4a0f-8101-d5d3646e07a0"
_ACCOUNT = Account("admin", 1000, 1000, Path("/home/admin"))


@pytest.fixture
def proc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proc"
    boot_id = root / "sys/kernel/random/boot_id"
    boot_id.parent.mkdir(parents=True)
    boot_id.write_text(f"{_BOOT}\n")
    monkeypatch.setattr(ssh_session, "_PROC", root)
    return root


def test_cutoff_uses_boottime_ticks_without_ssh_environment(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def clock_gettime_ns(clock: int) -> int:
        assert clock == ssh_session.time.CLOCK_BOOTTIME
        return 1_999_999_999

    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(ssh_session.time, "clock_gettime_ns", clock_gettime_ns)
    monkeypatch.setattr(ssh_session.os, "sysconf", lambda name: {"SC_CLK_TCK": 100}[name])

    assert ssh_session.freshness_cutoff() == (_BOOT, 199)


def _write_stat(proc: Path, pid: int, parent: int, tick: int) -> None:
    (proc / str(pid) / "stat").write_text(
        f"{pid} (name with ) parentheses) S {parent} {'0 ' * 17}{tick} 0\n"
    )


def _process(
    proc: Path,
    pid: int,
    parent: int,
    tick: int,
    uid: int,
    title: str,
    exe: Path | None = None,
) -> None:
    path = proc / str(pid)
    path.mkdir()
    _write_stat(proc, pid, parent, tick)
    (path / "status").write_text(f"Name:\tprocess\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (path / "cmdline").write_bytes(title.encode() + b"\0\0")
    if exe is not None:
        (path / "exe").symlink_to(exe)


@pytest.fixture(params=["sshd", "sshd-session"])
def transport(
    proc: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> Callable[[int], None]:
    program: str = request.param
    exe = tmp_path / program
    exe.touch(mode=0o755)
    monkeypatch.setattr(ssh_session, "_SSHD", {program: exe})
    monkeypatch.setattr(ssh_session.os, "getpid", lambda: 80)

    def root_stat(
        path: str | Path, *, dir_fd: int | None = None, follow_symlinks: bool = True
    ) -> os.stat_result:
        metadata = os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if os.path.samestat(metadata, exe.stat()):
            fields = list(metadata)
            fields[4] = 0  # Simulate the installed binary's root ownership.
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(ssh_session, "file_stat", root_stat)

    def build(monitor_tick: int) -> None:
        _process(proc, 20, 1, 10, 0, "sshd: /usr/sbin/sshd -D [listener]")
        _process(proc, 30, 20, monitor_tick, 0, f"{program}: admin [priv]", exe)
        _process(proc, 40, 30, monitor_tick + 1, 1000, f"{program}: admin@pts/0", exe)
        _process(proc, 50, 40, 120, 1000, "-bash")
        _process(proc, 60, 50, 121, 1000, "sudo")
        _process(proc, 70, 60, 122, 0, "sudo")
        _process(proc, 80, 70, 123, 0, "lhm ssh-confirm")

    return build


def test_fresh_stock_transport_through_sudo(transport: Callable[[int], None]) -> None:
    transport(101)
    ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


@pytest.mark.parametrize("monitor_tick", [99, 100])
def test_new_channel_on_same_transport_is_not_fresh(
    transport: Callable[[int], None], monitor_tick: int
) -> None:
    transport(monitor_tick)
    with pytest.raises(ssh_session.SshSessionError, match="strictly after the cutoff"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


def test_fresh_looking_transport_from_another_boot_is_rejected(
    transport: Callable[[int], None],
) -> None:
    transport(101)
    with pytest.raises(ssh_session.SshSessionError, match="boot ID changed"):
        ssh_session.require_fresh_ssh("e76c29bb-2b2c-4593-8b77-42e47e735501", 100, account=_ACCOUNT)


@pytest.mark.parametrize(
    ("pid", "uids"), [(30, "1000\t0\t0\t0"), (30, "0\t1000\t0\t0"), (40, "1001\t1001\t1001\t1001")]
)
def test_monitor_must_be_root_and_worker_must_match_account(
    proc: Path, transport: Callable[[int], None], pid: int, uids: str
) -> None:
    transport(101)
    (proc / str(pid) / "status").write_text(f"Uid:\t{uids}\n")
    with pytest.raises(ssh_session.SshSessionError, match="identity could not be verified"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


@pytest.mark.parametrize("pid", [30, 40])
def test_correct_title_does_not_make_a_different_binary_trusted(
    proc: Path, transport: Callable[[int], None], pid: int
) -> None:
    transport(101)
    exe = proc / str(pid) / "exe"
    impostor = exe.resolve().parent / "impostor" / exe.resolve().name
    impostor.parent.mkdir()
    impostor.touch(mode=0o755)
    exe.unlink()
    exe.symlink_to(impostor)
    with pytest.raises(ssh_session.SshSessionError, match="identity could not be verified"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


def test_group_writable_packaged_path_is_not_trusted(
    proc: Path, transport: Callable[[int], None]
) -> None:
    transport(101)
    (proc / "30/exe").resolve().chmod(0o775)
    with pytest.raises(ssh_session.SshSessionError, match="identity could not be verified"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


@pytest.mark.parametrize("parent", [1, 20])
def test_detached_or_only_listener_never_confirms(
    proc: Path, transport: Callable[[int], None], parent: int
) -> None:
    transport(101)
    _write_stat(proc, 20, 1, 101)  # Even a new listener is not a transport.
    _write_stat(proc, 50, parent, 120)
    with pytest.raises(ssh_session.SshSessionError, match="no supported SSH transport"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)


@pytest.mark.parametrize(("parent", "tick"), [(1, 120), (40, 121)])
def test_parent_or_pid_start_change_during_read_is_rejected(
    proc: Path,
    transport: Callable[[int], None],
    monkeypatch: pytest.MonkeyPatch,
    parent: int,
    tick: int,
) -> None:
    transport(101)
    file_stat = ssh_session.file_stat

    def racing_stat(
        path: str | Path, *, dir_fd: int | None = None, follow_symlinks: bool = True
    ) -> os.stat_result:
        if path == "exe":
            _write_stat(proc, 50, parent, tick)
        return file_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(ssh_session, "file_stat", racing_stat)
    with pytest.raises(ssh_session.SshSessionError, match="SSH ancestry changed"):
        ssh_session.require_fresh_ssh(_BOOT, 100, account=_ACCOUNT)
