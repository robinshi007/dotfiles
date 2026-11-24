import base64
import errno
import os
import select
import signal
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from lhm.core import colors
from lhm.core.runner import Runner
from lhm.modules import ssh
from lhm.modules import ssh_watchdog as watchdog

TXID = "3c" * 16
DEADLINE = 600.0
TIMEOUT = 5
ORIGINAL = b"Port 22\r\n# local settings\r\n"
CANDIDATE = "Port 2222\n"


@pytest.fixture
def workdir(tmp_path: Path) -> Iterator[Path]:
    base = Path("/tmp/opencode")
    with TemporaryDirectory(
        prefix="lhm-ssh-watchdog-",
        dir=base if base.is_dir() and os.access(base, os.W_OK | os.X_OK) else tmp_path,
    ) as directory:
        yield Path(directory).resolve()


def _configure_paths(patch: pytest.MonkeyPatch, directory: Path) -> Path:
    target = directory / ssh.SSHD_DROPIN.name
    patch.setattr(ssh, "SSHD_DROPIN", target)
    patch.setattr(ssh, "PRIVSEP_DIR", directory / "run" / "sshd")
    patch.setattr(watchdog, "_STATE_DIR", directory / "state")
    patch.setattr(watchdog, "_ROOT_UID", os.geteuid())
    trusted = watchdog._trusted
    # Keep real ownership and mode checks inside the private test tree.
    ancestors = set(directory.parents)

    def trust_test_ancestors(info: os.stat_result, path: Path, *, directory: bool) -> None:
        if path not in ancestors:
            trusted(info, path, directory=directory)

    patch.setattr(watchdog, "_trusted", trust_test_ancestors)
    return target


def _child(directory: Path) -> None:
    with pytest.MonkeyPatch.context() as patch:
        target = _configure_paths(patch, directory)
        colors.configure(quiet=True)  # Reserve stdout for the readiness byte.
        with ssh.locked_target(target):
            # Seed the post-arm checkpoint; timer scheduling is covered separately.
            pending = watchdog.Pending(
                TXID,
                DEADLINE,
                "armed",
                {
                    "snapshot": base64.b64encode(target.read_bytes()).decode("ascii"),
                    "candidate": base64.b64encode(CANDIDATE.encode()).decode("ascii"),
                    "backup": None,
                    "unit": "ssh.service",
                    "service_state": "enabled",
                    "socket": None,
                    "socket_state": None,
                    "endpoints": [["0.0.0.0", 22]],
                    "port": 2222,
                    "accounts": [["operator", 1000, 1000, str(directory)]],
                    "connection": None,
                    "write_attempted": False,
                    "action": "none",
                },
            )
            with watchdog._state_dir(create=True) as fd:
                assert fd is not None
                watchdog._store(fd, pending)

            def record_backup(path: Path) -> None:
                watchdog.update(pending, write_attempted=True, backup=path.name)

            assert ssh.write_dropin(target, CANDIDATE, on_backup=record_backup) == "written"
            os.write(sys.stdout.fileno(), b"R")
            sys.stdin.buffer.read(1)  # Stay inside the lock until killed (or parent exits).


def test_expiry_restores_dropin_after_lock_holder_is_sigkilled(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _configure_paths(monkeypatch, workdir)
    target.write_bytes(ORIGINAL)
    target.chmod(0o600)
    marker = workdir / "state/pending.json"
    stop = ["/usr/bin/systemctl", "--system", "stop", f"lhm-ssh-rollback-{TXID}.timer"]
    reload = ["systemctl", "reload", "--job-mode=fail", "ssh.service"]
    replies = {
        ("systemctl", "show", "--property=Id", "--property=LoadState", "ssh.service"): (
            "Id=ssh.service\nLoadState=loaded\n"
        ),
        ("systemctl", "is-enabled", "ssh.service"): "enabled\n",
        ("systemctl", "is-active", "ssh.service"): "active\n",
        ("systemctl", "list-jobs", "--no-legend", "--no-pager", "ssh.service"): "",
        ("sshd", "-t"): "",
        tuple(reload): "",
        ("ss", "-tlnp"): 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n',
    }

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == stop:
            assert not marker.exists()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        assert marker.exists() and target.read_bytes() == ORIGINAL
        assert tuple(cmd) in replies
        if cmd in (["sshd", "-t"], reload):
            assert ssh.PRIVSEP_DIR.is_dir()
        return subprocess.CompletedProcess(cmd, 0, replies[tuple(cmd)], "")

    runner = Runner(exec_fn=execute)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    monkeypatch.setattr(ssh, "monotonic", lambda: DEADLINE)
    script = Path(__file__).resolve()
    child = subprocess.Popen(
        [sys.executable, "-B", str(script), str(workdir)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        cwd=workdir,
        env={**os.environ, "PYTHONPATH": str(script.parents[1] / "src")},
    )
    assert child.stdin is not None and child.stdout is not None
    with child.stdin, child.stdout:
        try:
            readable, _, _ = select.select([child.stdout], [], [], TIMEOUT)
            assert readable, "SSH watchdog child did not signal readiness"
            assert os.read(child.stdout.fileno(), 1) == b"R", "SSH watchdog child exited early"
            assert ssh.expire_watchdog(TXID) == ssh._RETRY
            assert not runner.history
        finally:
            child.kill()
            returncode = child.wait(timeout=TIMEOUT)
    assert returncode == -signal.SIGKILL

    pending = watchdog.current()
    assert pending is not None and pending.id == TXID and pending.phase == "armed"
    assert pending.data["write_attempted"] is True
    assert target.read_bytes() == CANDIDATE.encode()

    open_file = os.open

    def fail_marker_read(
        path: str | Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if path == marker.name and dir_fd is not None:
            raise OSError(errno.EIO, "injected journal read failure")
        return open_file(path, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", fail_marker_read)
        assert ssh.expire_watchdog(TXID) == ssh._RETRY
    assert marker.exists() and target.read_bytes() == CANDIDATE.encode() and not runner.history

    assert ssh.expire_watchdog(TXID) == 0
    assert target.read_bytes() == ORIGINAL
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert watchdog.current() is None and not marker.exists()
    assert [result.cmd for result in runner.history if result.cmd in (reload, stop)] == [
        reload,
        stop,
    ]


if __name__ == "__main__":
    _child(Path(sys.argv[1]))
