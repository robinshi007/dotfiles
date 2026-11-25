import base64
import errno
import os
import pwd
import select
import stat
import subprocess
from pathlib import Path

import pytest

from lhm.core.files import locked_target
from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.core.userkeys import Account
from lhm.modules import ssh, ssh_permissions, ssh_watchdog

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n"
MODE_DIR = 0o750
MODE_FILE = 0o640
EFFECTIVE = (
    "port 22345\npermitrootlogin no\npasswordauthentication no\n"
    "kbdinteractiveauthentication no\npubkeyauthentication yes\n"
    "authenticationmethods publickey\nauthorizedkeysfile .ssh/authorized_keys\n"
    "allowusers operator\n"
)


class Watchdog:
    pending: ssh_watchdog.Pending | None = None
    now = 100.0
    boot_id = "cc083046-a214-4159-b81f-bc4a7bde8363"

    def current(self) -> ssh_watchdog.Pending | None:
        return self.pending

    def arm(self, _runner: Runner, data: dict[str, object]) -> ssh_watchdog.Pending:
        assert self.pending is None
        self.pending = ssh_watchdog.Pending("1" * 32, self.now + 60, "armed", data)
        return self.pending

    def update(
        self, pending: ssh_watchdog.Pending, *, phase: str | None = None, **data: object
    ) -> ssh_watchdog.Pending:
        assert self.pending == pending
        self.pending = ssh_watchdog.Pending(
            pending.id, pending.deadline, phase or pending.phase, pending.data | data
        )
        return self.pending

    def clear(self, _runner: Runner, pending: ssh_watchdog.Pending) -> None:
        assert self.pending == pending
        self.pending = None


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Account:
    uid, gid = os.getuid(), os.getgid()
    if not uid or not gid:
        pytest.skip("test requires a non-root file owner; never chown test files")
    home = tmp_path / "srv" / "nss-home"
    directory = home / ".ssh"
    directory.mkdir(parents=True)
    home.chmod(0o750)
    directory.chmod(MODE_DIR)
    keys = directory / "authorized_keys"
    keys.write_text(KEY)
    keys.chmod(MODE_FILE)
    monkeypatch.setattr(ssh, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "operator")
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setenv("SUDO_GID", str(gid))
    monkeypatch.setenv("HOME", str(tmp_path / "must-not-be-used"))
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(ssh, "HOME_ROOT", tmp_path / "not-home")
    dropin = tmp_path / "config" / "99-lhm.conf"
    dropin.parent.mkdir(mode=0o700)
    dropin.write_text(ssh.desired_conf(22345, ["operator"]))
    dropin.chmod(0o644)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", dropin)
    monkeypatch.setattr(ssh, "_SSHD_DROPIN_UID", uid)
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", tmp_path / "run" / "sshd")
    return Account("operator", uid, gid, home)


@pytest.fixture(autouse=True)
def watchdog(monkeypatch: pytest.MonkeyPatch) -> Watchdog:
    fake = Watchdog()
    for name in ("current", "arm", "update", "clear"):
        monkeypatch.setattr(ssh_watchdog, name, getattr(fake, name))
    monkeypatch.setattr(ssh, "monotonic", lambda: fake.now)
    monkeypatch.setattr(ssh.ssh_session, "freshness_cutoff", lambda: (fake.boot_id, 1000))
    monkeypatch.setattr(ssh, "_local_recovery_console", lambda: True)
    return fake


@pytest.fixture
def runner(account: Account) -> Runner:
    def run(cmd: list[str], _timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["/usr/bin/getent", "passwd", account.name]:
            out = f"{account.name}:x:{account.uid}:{account.gid}::{account.home}:/bin/bash\n"
        elif cmd[0] == "/usr/bin/setpriv":
            assert cmd[-6] == "probe"
            assert cmd[-3] == str(account.home)
            keys = account.home / ".ssh" / "authorized_keys"
            ready = int(mode(keys.parent) == 0o700) if keys.parent.exists() else 0
            payload = (
                f"{mode(keys):04o} " + base64.b64encode(keys.read_bytes()).decode()
                if keys.exists()
                else "-"
            )
            out = f"LHM_USERKEYS_V1 STATE {ready} {payload}\n"
        elif cmd[:2] == ["sshd", "-T"]:
            out = EFFECTIVE
        elif cmd == ["ss", "-tlnp"]:
            out = 'LISTEN 0 128 0.0.0.0:22345 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        elif cmd[0:2] == ["systemctl", "is-active"]:
            if cmd[-1] not in ("ssh.service", "rescue.target"):
                return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
            out = "active\n"
        elif cmd[0:2] == ["systemctl", "show"]:
            out = "Id=ssh.service\nLoadState=loaded\n"
        elif cmd[0:2] == ["systemctl", "is-enabled"]:
            out = "enabled\n"
        elif cmd[0:2] == ["systemctl", "list-jobs"]:
            out = ""
        else:
            pytest.fail(f"unexpected command: {cmd}")
        return subprocess.CompletedProcess(cmd, 0, out, "")

    return Runner(exec_fn=run)


def test_modes_only_uses_sudo_nss_home_with_one_confirmation(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    plans: list[list[str]] = []

    def confirm(plan: list[str], *, allow_bypass: bool) -> bool:
        assert not allow_bypass
        plans.append(plan)
        return True

    monkeypatch.setattr(ssh, "confirm_once", confirm)
    keys = account.home / ".ssh" / "authorized_keys"
    inode = keys.stat().st_ino
    result = ssh.apply_hardening(runner)
    assert [step.status for step in result] == [
        Status.CHANGED,
        Status.CHANGED,
        Status.SKIPPED,
        Status.CHANGED,
        Status.OK,
    ]
    assert len(plans) == 1
    assert any(str(account.home) in line and "NSS home" in line for line in plans[0])
    assert any("console" in line and "without SSH" in line for line in plans[0])
    assert (mode(keys.parent), mode(keys)) == (0o700, 0o600)
    assert keys.stat().st_ino == inode and keys.read_text() == KEY
    assert watchdog.pending is not None and watchdog.pending.phase == "awaiting-confirm"
    assert watchdog.pending.data["action"] == "none"
    assert watchdog.pending.data["write_attempted"] is False
    assert not any(item.cmd[1:2] == ["reload"] for item in runner.history)
    txid = watchdog.pending.id
    assert ssh.confirm_watchdog(runner, txid)[0].status is Status.FAIL  # No SSH connection.
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 43210 127.0.0.1 22345")
    transports: list[tuple[str, int, Account]] = []

    def fresh(boot: str, tick: int, *, account: Account) -> None:
        transports.append((boot, tick, account))

    monkeypatch.setattr(ssh.ssh_session, "require_fresh_ssh", fresh)
    assert ssh.confirm_watchdog(runner, txid)[-1].status is Status.CHANGED
    assert transports == [(watchdog.boot_id, 1000, account)]
    assert watchdog.pending is None
    assert ssh.apply_hardening(runner)[0].status is Status.SKIPPED
    assert len(plans) == 1


@pytest.mark.parametrize("kind", ["root", "root-env", "wrong-uid", "explicit-root"])
def test_selection_fails_closed(kind: str, runner: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = None
    if kind == "root":
        for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
            monkeypatch.delenv(var)
    elif kind == "root-env":
        monkeypatch.setenv("SUDO_USER", "root")
        monkeypatch.setenv("SUDO_UID", "0")
        monkeypatch.setenv("SUDO_GID", "0")
    elif kind == "wrong-uid":
        monkeypatch.setenv("SUDO_UID", "42")
    else:
        explicit = "root"
    result = ssh.apply_hardening(runner, ssh_user=explicit)[0]
    assert result.status is Status.FAIL
    assert "--ssh-user" in result.detail or "does not match" in result.detail


def test_explicit_user_overrides_direct_root_and_dry_run_reads_only(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(var)
    fields = ("operator", "x", account.uid, account.gid, "", str(account.home), "/bin/bash")
    monkeypatch.setattr(pwd, "getpwnam", lambda name: pwd.struct_passwd(fields))
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: pytest.fail("dry-run prompted"))
    runner.dry_run = True
    original = list(ssh.SSHD_DROPIN.parent.iterdir())
    result = ssh.apply_hardening(runner, ssh_user=account.name)
    assert [step.status for step in result] == [
        Status.PLANNED,
        Status.PLANNED,
        Status.SKIPPED,
        Status.PLANNED,
    ]
    output = capsys.readouterr().out
    assert "0750 -> 0700" in output and "0640 -> 0600" in output
    keys = account.home / ".ssh" / "authorized_keys"
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)
    assert list(ssh.SSHD_DROPIN.parent.iterdir()) == original and runner.history == []


@pytest.mark.parametrize(
    "case",
    [
        "ancestor",
        "directory",
        "symlink",
        "fifo",
        "hardlink",
        "owner",
        "writable-dir",
        "writable-file",
        "special-dir",
        "special-file",
    ],
)
def test_unsafe_mode_targets_are_refused(
    case: str, account: Account, runner: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    spare = account.home / "spare"
    spare.write_text(KEY)
    spare.chmod(0o644)
    if case == "ancestor":
        old_parent = account.home.parent
        old_parent.rename(old_parent.with_name("real"))
        old_parent.symlink_to(old_parent.with_name("real"), target_is_directory=True)
    elif case == "directory":
        keys.parent.rename(account.home / "real")
        keys.parent.symlink_to(account.home / "real", target_is_directory=True)
    elif case == "owner":
        original = os.fstat
        inode = keys.stat().st_ino

        def wrong_owner(fd: int) -> os.stat_result:
            info = original(fd)
            if info.st_ino != inode:
                return info
            values = list(info)
            values[4] = 0
            return os.stat_result(values)

        monkeypatch.setattr(os, "fstat", wrong_owner)
    elif case.startswith(("writable", "special")):
        target = keys if case.endswith("file") else keys.parent
        target.chmod(mode(target) | (0o020 if case.startswith("writable") else 0o1000))
    else:
        keys.unlink()
        if case == "symlink":
            keys.symlink_to(spare)
        elif case == "fifo":
            os.mkfifo(keys)
        else:
            os.link(spare, keys)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: pytest.fail("unsafe paths prompted"))
    assert ssh.apply_hardening(runner)[0].status is Status.FAIL
    assert mode(spare) == 0o644


@pytest.mark.parametrize("failure", ["decline", "replace", "chmod", "key gate", "listener"])
def test_failed_apply_never_widens_permissions(
    failure: str, account: Account, runner: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    old = keys.with_suffix(".old")

    def confirm(_plan: list[str], *, allow_bypass: bool) -> bool:
        assert not allow_bypass
        if failure == "replace":
            keys.rename(old)
            keys.write_text(KEY)
            keys.chmod(MODE_FILE)
        return failure != "decline"

    if failure == "chmod":
        chmod = ssh_permissions.Target.chmod

        def broken_chmod(
            target: ssh_permissions.Target, new: int, owner: Account, lock_fd: int | None
        ) -> int:
            ctime = chmod(target, new, owner, lock_fd)
            if target.path == keys and new == 0o600:
                raise OSError("simulated failure after chmod")
            return ctime

        monkeypatch.setattr(ssh_permissions.Target, "chmod", broken_chmod)
    if failure == "key gate":

        def bad_effective(_runner: Runner) -> dict[str, str]:
            return {"port": "22"}

        monkeypatch.setattr(ssh.checks, "sshd_effective_config", bad_effective)
    if failure == "listener":
        delegate = runner.exec_fn

        def lost_listener(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
            if cmd == ["ss", "-tlnp"] and mode(keys) == 0o600:
                return subprocess.CompletedProcess(cmd, 127, "", "")
            return delegate(cmd, timeout)

        runner.exec_fn = lost_listener
    monkeypatch.setattr(ssh, "confirm_once", confirm)
    result = ssh.apply_hardening(runner)
    expected = Status.ABORTED if failure == "decline" else Status.FAIL
    assert any(step.status is expected for step in result)
    expected_modes = (MODE_DIR, MODE_FILE) if failure in {"decline", "replace"} else (0o700, 0o600)
    assert (mode(keys.parent), mode(keys)) == expected_modes
    if failure == "replace":
        assert mode(old) == MODE_FILE
    if failure in {"chmod", "key gate", "listener"}:
        assert result[-1].name == "restore SSH permissions"
        assert result[-1].status is Status.FAIL and "no automatic chmod" in result[-1].detail


@pytest.mark.parametrize("missing_dir", [False, True])
def test_absent_paths_are_not_created(account: Account, missing_dir: bool) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    keys.unlink()
    if missing_dir:
        keys.parent.rmdir()
    with ssh_permissions.inspect(account) as plan:
        assert len(plan.targets) == (0 if missing_dir else 1)
        plan.apply(lambda index, ctime: None, lambda index, ctime: None)
    assert not keys.exists() and keys.parent.exists() is not missing_dir


def test_swap_immediately_before_chmod_never_reaches_replacement(
    account: Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    spare = account.home / "spare"
    spare.write_text(KEY)
    spare.chmod(0o644)
    chmod = ssh_permissions.Target.chmod

    def swap(target: ssh_permissions.Target, new: int, owner: Account, lock_fd: int | None) -> int:
        if target.path == keys:
            keys.rename(keys.with_suffix(".old"))
            keys.symlink_to(spare)
        return chmod(target, new, owner, lock_fd)

    monkeypatch.setattr(ssh_permissions.Target, "chmod", swap)
    with ssh_permissions.inspect(account) as plan:
        with pytest.raises(ssh_permissions.SshPermissionsError, match="refused|unsafe type"):
            plan.apply(lambda index, ctime: None, lambda index, ctime: None)
    assert mode(spare) == 0o644


@pytest.mark.parametrize("boundary", ["before-intent", "intent", "chmod", "receipt", "complete"])
def test_watchdog_expiry_never_widens_at_any_chmod_journal_boundary(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
    capsys: pytest.CaptureFixture[str],
    boundary: str,
) -> None:
    class ProcessLost(BaseException):
        pass

    keys = account.home / ".ssh" / "authorized_keys"
    old_config = ssh.SSHD_DROPIN.read_bytes()
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    chmod = ssh_permissions.Target.chmod

    def track_update(
        pending: ssh_watchdog.Pending, *, phase: str | None = None, **fields: object
    ) -> ssh_watchdog.Pending:
        rows = fields.get("permission_operations")
        first = isinstance(rows, list) and len(rows) == 1
        is_intent = first and rows[0][2] is None
        if is_intent and boundary == "before-intent":
            raise ProcessLost
        updated = watchdog.update(pending, phase=phase, **fields)
        if first and (
            (is_intent and boundary == "intent") or (not is_intent and boundary == "receipt")
        ):
            raise ProcessLost
        return updated

    def crash_at_chmod(
        target: ssh_permissions.Target, new: int, owner: Account, lock_fd: int | None
    ) -> int:
        assert watchdog.pending is not None
        rows = watchdog.pending.data["permission_operations"]
        assert isinstance(rows, list) and rows[-1][2] is None
        ctime = chmod(target, new, owner, lock_fd)
        if boundary == "chmod":
            raise ProcessLost
        return ctime

    with monkeypatch.context() as scoped:
        scoped.setattr(ssh_watchdog, "update", track_update)
        scoped.setattr(ssh_permissions.Target, "chmod", crash_at_chmod)
        if boundary != "complete":
            with pytest.raises(ProcessLost):
                ssh.apply_hardening(runner)
    if boundary == "complete":
        assert ssh.apply_hardening(runner)[-1].status is Status.OK

    pending = watchdog.pending
    assert pending is not None
    if boundary in {"intent", "chmod", "receipt"}:
        # An unattempted key was tightened by an independent writer.
        keys.chmod(0o600)
    modes_at_crash = mode(keys.parent), mode(keys)
    watchdog.now = pending.deadline + 1
    assert ssh.expire_watchdog(pending.id) == (0 if boundary == "before-intent" else 1)
    assert (mode(keys.parent), mode(keys)) == modes_at_crash
    assert keys.read_text() == KEY and ssh.SSHD_DROPIN.read_bytes() == old_config
    if boundary == "before-intent":
        assert watchdog.pending is None
        return
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert "chmod 0750 --" in capsys.readouterr().err
    # Only the console operator can put back old permissions.
    keys.parent.chmod(MODE_DIR)
    if boundary == "complete":
        keys.chmod(MODE_FILE)
    assert ssh.recover_failed_watchdog(runner, pending.id)[-1].status is Status.CHANGED
    assert watchdog.pending is None


def test_unverified_daemon_rollback_retains_modes_and_manifest(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_config = ssh.SSHD_DROPIN.read_bytes()
    keys = account.home / ".ssh" / "authorized_keys"
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    delegate = runner.exec_fn

    def failed_recovery(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["sshd", "-t"]:
            status = int(ssh.SSHD_DROPIN.read_bytes() != old_config)
            return subprocess.CompletedProcess(cmd, status, "", "")
        if cmd == ["systemctl", "reload", "--job-mode=fail", "ssh.service"]:
            assert ssh.SSHD_DROPIN.read_bytes() == old_config
            return subprocess.CompletedProcess(cmd, 1, "", "")
        return delegate(cmd, timeout)

    runner.exec_fn = failed_recovery
    steps = {step.name: step for step in ssh.apply_hardening(runner, port=23000)}
    assert steps["sshd -t"].status is Status.FAIL
    assert steps["restore ssh listener"].status is Status.FAIL
    mode_step = steps["restore SSH permissions"]
    assert mode_step.status is Status.FAIL and "no automatic chmod" in mode_step.detail
    assert "SSH recovery not verified" in capsys.readouterr().err
    assert (mode(keys.parent), mode(keys)) == (0o700, 0o600)
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    data = watchdog.pending.data
    operations = ssh_permissions.Recovery.parse(data["permissions"]).operations(
        data["permission_operations"]
    )
    assert [op.index for op in operations if op.after is not None] == [0, 1]
    assert isinstance(data["backup"], str)
    assert ssh.SSHD_DROPIN.with_name(data["backup"]).read_bytes() == old_config
    assert [old for _, old in ssh_permissions.Recovery.parse(data["permissions"]).targets] == [
        MODE_DIR,
        MODE_FILE,
    ]
    txid = watchdog.pending.id

    def restored_daemon(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["systemctl", "reload", "--job-mode=fail", "ssh.service"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return failed_recovery(cmd, timeout)

    runner.exec_fn = restored_daemon
    recovery = {step.name: step for step in ssh.recover_failed_watchdog(runner, txid)}
    assert recovery["restore SSH permissions"].status is Status.FAIL
    assert "original mode not yet restored" in recovery["restore SSH permissions"].detail
    assert (mode(keys.parent), mode(keys)) == (0o700, 0o600)
    keys.chmod(MODE_FILE)
    keys.parent.chmod(MODE_DIR)
    steps = ssh.recover_failed_watchdog(runner, txid)
    assert steps[-1].status is Status.CHANGED
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)
    assert watchdog.pending is None


def test_recovery_rejects_replacement_and_retains_original_modes(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    keys = account.home / ".ssh" / "authorized_keys"
    keys.rename(keys.with_suffix(".old"))
    keys.write_text(KEY)
    keys.chmod(0o600)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    watchdog.now = pending.deadline + 1
    assert ssh.expire_watchdog(pending.id) == 1
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert watchdog.pending.data["permissions"] == pending.data["permissions"]
    assert (mode(keys.parent), mode(keys)) == (0o700, 0o600)


def test_incompatible_worker_refuses_before_chmod(
    account: Account, runner: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def old_worker(_runner: Runner, _data: dict[str, object]) -> ssh_watchdog.Pending:
        raise ssh_watchdog.WatchdogError("SSH rollback runtime protocol/schema or build mismatch")

    monkeypatch.setattr(ssh_watchdog, "arm", old_worker)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    result = ssh.apply_hardening(runner)
    assert result[-1].status is Status.FAIL and "mismatch" in result[-1].detail
    keys = account.home / ".ssh" / "authorized_keys"
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)


def test_mode_only_rechecks_other_admin_keys_after_chmod(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, [account.name, "fallback"]))
    keys = account.home / ".ssh" / "authorized_keys"
    fallback_home = account.home.parent / "fallback"
    delegate = runner.exec_fn

    def lose_fallback(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["/usr/bin/getent", "passwd", "fallback"]:
            row = f"fallback:x:{account.uid}:{account.gid}::{fallback_home}:/bin/bash\n"
            return subprocess.CompletedProcess(cmd, 0, row, "")
        if cmd[0] == "/usr/bin/setpriv" and cmd[-3] == str(fallback_home):
            payload = base64.b64encode(KEY.encode()).decode()
            state = "1 -" if mode(keys) == 0o600 else f"1 0600 {payload}"
            return subprocess.CompletedProcess(cmd, 0, f"LHM_USERKEYS_V1 STATE {state}\n", "")
        return delegate(cmd, timeout)

    runner.exec_fn = lose_fallback
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    steps = ssh.apply_hardening(runner)
    assert any(step.status is Status.FAIL and "refusing fallback" in step.detail for step in steps)
    assert steps[-1].name == "restore SSH permissions" and steps[-1].status is Status.FAIL
    assert (mode(keys.parent), mode(keys)) == (0o700, 0o600)
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"


@pytest.mark.parametrize("code", [errno.EAGAIN, errno.EINTR, errno.ENOMEM, errno.ENFILE])
def test_permission_recovery_retries_transient_errors_without_widening(
    code: int,
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline + 1
    keys.chmod(MODE_FILE)

    def intermittent(_fd: int) -> list[int]:
        raise OSError(code, "simulated transient identity inspection failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(ssh_permissions, "_identity", intermittent)
        assert ssh.expire_watchdog(pending.id) == 75
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert (mode(keys.parent), mode(keys)) == (0o700, MODE_FILE)
    assert ssh.expire_watchdog(pending.id) == 1
    assert (mode(keys.parent), mode(keys)) == (0o700, MODE_FILE)
    keys.parent.chmod(MODE_DIR)
    assert ssh.recover_failed_watchdog(runner, pending.id)[-1].status is Status.CHANGED
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)
    assert watchdog.pending is None


def test_failed_second_intent_never_chmods_key(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    def delayed_record(
        pending: ssh_watchdog.Pending, *, phase: str | None = None, **fields: object
    ) -> ssh_watchdog.Pending:
        rows = fields.get("permission_operations")
        if isinstance(rows, list) and len(rows) == 2:
            assert pending.data["permission_operations"] == rows[:1]
            raise ssh_watchdog.WatchdogError("simulated failure before durable second intent")
        return watchdog.update(pending, phase=phase, **fields)

    keys = account.home / ".ssh" / "authorized_keys"
    chmod = ssh_permissions.Target.chmod
    changes: list[tuple[Path, int]] = []

    def capture(
        target: ssh_permissions.Target, new: int, owner: Account, lock_fd: int | None
    ) -> int:
        changes.append((target.path, new))
        return chmod(target, new, owner, lock_fd)

    monkeypatch.setattr(ssh_watchdog, "update", delayed_record)
    monkeypatch.setattr(ssh_permissions.Target, "chmod", capture)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    steps = ssh.apply_hardening(runner)
    assert any("before durable second intent" in step.detail for step in steps)
    assert changes == [(keys.parent, 0o700)]
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"


def test_permission_recovery_retries_timed_out_nss_lookup(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline + 1
    delegate = runner.exec_fn

    def slow_nss(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert cmd == ["/usr/bin/getent", "passwd", account.name] and timeout == 2
        return subprocess.CompletedProcess(cmd, 124, "", "")

    runner.exec_fn = slow_nss
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    assert ssh.expire_watchdog(pending.id) == 75
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    runner.exec_fn = delegate
    assert ssh.expire_watchdog(pending.id) == 1


@pytest.mark.parametrize("phase", ["prepared", "armed", "awaiting-confirm", "failed"])
def test_key_writer_refuses_pending_watchdog_even_if_armed_during_prompt(
    phase: str,
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    def pending_during_prompt(_plan: list[str]) -> bool:
        watchdog.pending = ssh_watchdog.Pending("1" * 32, watchdog.now + 60, phase, {})
        return True

    monkeypatch.setattr(ssh, "_import_pubkey", lambda runner, path: KEY.strip())
    monkeypatch.setattr(ssh, "confirm_once", pending_during_prompt)

    def no_key_write(*_args: object) -> bool:
        pytest.fail("key write attempted")

    monkeypatch.setattr(ssh.userkeys, "ensure_key", no_key_write)
    steps = ssh.SshModule().apply(runner, command="ssh-user", user=account.name, key="ignored")
    assert steps[0].status is Status.FAIL and "1" * 32 in steps[0].detail
    assert watchdog.pending is not None and watchdog.pending.phase == phase


def test_key_writer_holds_ssh_transaction_lock_through_install_and_verify(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def ensure(_runner: Runner, owner: Account, key: str) -> bool:
        assert owner == account and key == KEY.strip()
        with pytest.raises(BlockingIOError):
            with locked_target(ssh.SSHD_DROPIN):
                pytest.fail("SSH watchdog acquired the key writer's lock")
        seen.append("ensure")
        return True

    def verify(_runner: Runner, owner: Account, key: str) -> None:
        assert owner == account and key == KEY.strip()
        with pytest.raises(BlockingIOError):
            with locked_target(ssh.SSHD_DROPIN):
                pytest.fail("SSH watchdog acquired the key writer's lock")
        seen.append("verify")

    monkeypatch.setattr(ssh, "_import_pubkey", lambda runner, path: KEY.strip())
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    monkeypatch.setattr(ssh.userkeys, "ensure_key", ensure)
    monkeypatch.setattr(ssh, "_verify_installed_key", verify)
    steps = ssh.SshModule().apply(runner, command="ssh-user", user=account.name, key="ignored")
    assert steps[-1].status is Status.OK and seen == ["ensure", "verify"]


@pytest.mark.parametrize("code", [errno.EAGAIN, errno.EINTR, errno.EPERM])
def test_forked_chmod_reports_error_without_effect(
    code: int,
    account: Account,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ssh_permissions.inspect(account) as plan:
        target = plan.targets[0]

        def interrupted(fd: int, new: int) -> None:
            assert fd == target.fd and new == 0o700
            raise OSError(code, "simulated syscall failure")

        error = ssh_permissions.SshPermissionsError if code == errno.EPERM else OSError
        with monkeypatch.context() as scoped:
            scoped.setattr(ssh_permissions, "_chmod_fd", interrupted)
            with pytest.raises(error) as caught:
                target.chmod(0o700, account)
        assert ssh_permissions.retryable(caught.value) == (code != errno.EPERM)
        assert mode(target.path) == MODE_DIR


def test_chmod_child_keeps_flock_after_apply_parent_exits(
    account: Account,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The helper sends its PID before chmod and waits. Its apply parent then
    # exits without unlocking. Release the helper and wait via pidfd.
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    original = ssh_permissions._chmod_child

    def paused(
        fd: int,
        new: int,
        info: os.stat_result,
        owner: Account,
        output: int,
        lock_fd: int | None,
    ) -> None:
        os.write(ready_w, f"{os.getpid()}\n".encode())
        if os.read(go_r, 1) != b"x":
            os._exit(1)
        original(fd, new, info, owner, output, lock_fd)

    monkeypatch.setattr(ssh_permissions, "_chmod_child", paused)

    def parent_exits(_pid: int, _flags: int = 0) -> int:
        os._exit(0)

    parent = os.fork()
    if parent == 0:
        # Exit immediately after the real fork, not before the child inherits.
        os.pidfd_open = parent_exits
        with locked_target(ssh.SSHD_DROPIN) as lock_fd, ssh_permissions.inspect(account) as plan:
            plan.targets[0].chmod(0o700, account, lock_fd)
        os._exit(2)
    os.close(ready_w)
    os.close(go_r)
    poll = select.poll()
    poll.register(ready_r, select.POLLIN)
    try:
        assert poll.poll(2000)
        child = os.pidfd_open(int(os.read(ready_r, 32)))
        try:
            assert os.waitpid(parent, 0)[1] == 0
            with pytest.raises(BlockingIOError), locked_target(ssh.SSHD_DROPIN):
                pytest.fail("watchdog acquired lock while the child could still chmod")
            os.write(go_w, b"x")
            poll.unregister(ready_r)
            poll.register(child, select.POLLIN)
            assert poll.poll(2000)
        finally:
            os.close(child)
        with locked_target(ssh.SSHD_DROPIN):
            assert mode(account.home / ".ssh") == 0o700
    finally:
        os.close(ready_r)
        os.close(go_w)


def test_zero_chmod_plan_refuses_mode_drift_in_lock(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    directory = account.home / ".ssh"
    keys = directory / "authorized_keys"
    directory.chmod(0o700)
    keys.chmod(0o600)

    def confirm(_plan: list[str]) -> bool:
        keys.chmod(0o644)
        return True

    monkeypatch.setattr(ssh, "confirm_once", confirm)
    result = ssh.apply_hardening(runner, port=23000)
    assert result[-1].status is Status.FAIL and "paths or modes changed" in result[-1].detail
    assert mode(keys) == 0o644 and watchdog.pending is None


def test_independent_tightening_before_second_intent_is_not_undone(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"

    def edit_after_receipt(
        pending: ssh_watchdog.Pending,
        *,
        phase: str | None = None,
        **fields: object,
    ) -> ssh_watchdog.Pending:
        updated = watchdog.update(pending, phase=phase, **fields)
        rows = fields.get("permission_operations")
        if isinstance(rows, list) and len(rows) == 1 and rows[0][2] is not None:
            keys.chmod(0o600)
        return updated

    monkeypatch.setattr(ssh_watchdog, "update", edit_after_receipt)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    steps = ssh.apply_hardening(runner)
    assert steps[-1].status is Status.FAIL
    assert "authorized_keys" not in steps[-1].detail  # No second operation to recover.
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert len(watchdog.pending.data["permission_operations"]) == 1
    assert mode(keys) == 0o600


def test_post_receipt_ctime_drift_blocks_confirmation_and_recovery(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
    capsys: pytest.CaptureFixture[str],
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    # Change bytes without changing size, then emulate a filesystem whose
    # ctime has not advanced by a timestamp tick yet.
    before = keys.stat()
    keys.write_text(KEY.replace("AAAAIAAB", "AAAAIAAC"))
    assert keys.stat().st_size == before.st_size and keys.read_text() != KEY
    fstat = os.fstat

    class CoarseStat:
        st_ctime_ns = before.st_ctime_ns

        def __init__(self, info: os.stat_result) -> None:
            self.info = info

        def __getattr__(self, name: str) -> object:
            return getattr(self.info, name)

    def coarse(fd: int) -> os.stat_result | CoarseStat:
        info = fstat(fd)
        return CoarseStat(info) if os.path.samestat(info, before) else info

    monkeypatch.setattr(os, "fstat", coarse)
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 43210 127.0.0.1 22345")
    monkeypatch.setattr(ssh.ssh_session, "require_fresh_ssh", lambda *args, **kwargs: None)
    result = ssh.confirm_watchdog(runner, pending.id)[0]
    assert result.status is Status.FAIL and "contents changed" in result.detail
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    watchdog.now = pending.deadline + 1
    assert ssh.expire_watchdog(pending.id) == 1
    assert mode(keys) == 0o600 and watchdog.pending is not None
    assert "contents changed" in capsys.readouterr().err


def test_other_admin_key_drift_during_final_verification_blocks_commit(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    fallback = account.home.parent / "fallback"
    alt_key = KEY
    delegate = runner.exec_fn

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["/usr/bin/getent", "passwd", "fallback"]:
            row = f"fallback:x:{account.uid}:{account.gid}::{fallback}:/bin/bash\n"
            return subprocess.CompletedProcess(cmd, 0, row, "")
        if cmd[0] == "/usr/bin/setpriv" and cmd[-3] == str(fallback):
            payload = base64.b64encode(alt_key.encode()).decode()
            return subprocess.CompletedProcess(
                cmd, 0, f"LHM_USERKEYS_V1 STATE 1 0600 {payload}\n", ""
            )
        result = delegate(cmd, timeout)
        if cmd[:2] == ["sshd", "-T"]:
            result.stdout += "allowusers fallback\n"
        return result

    runner.exec_fn = execute
    ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, [account.name, "fallback"]))
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 43210 127.0.0.1 22345")
    monkeypatch.setattr(ssh.ssh_session, "require_fresh_ssh", lambda *args, **kwargs: None)
    verify = ssh._verify_hardening

    def edit_during_verification(*args: object, **kwargs: object) -> object:
        nonlocal alt_key
        result = verify(*args, **kwargs)
        alt_key = KEY + "# independent change\n"
        return result

    monkeypatch.setattr(ssh, "_verify_hardening", edit_during_verification)
    result = ssh.confirm_watchdog(runner, pending.id)[0]
    assert result.status is Status.FAIL and "contents changed" in result.detail
    assert watchdog.pending == pending


def test_forward_chmod_will_not_add_owner_permissions(
    account: Account,
    runner: Runner,
    watchdog: Watchdog,
) -> None:
    keys = account.home / ".ssh" / "authorized_keys"
    keys.chmod(0o400)
    result = ssh.apply_hardening(runner)[0]
    assert result.status is Status.FAIL and "would add permission bits" in result.detail
    assert mode(keys) == 0o400 and watchdog.pending is None


def test_no_chmod_from_unverified_console(
    account: Account,
    runner: Runner,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: Watchdog,
) -> None:
    monkeypatch.setattr(ssh, "_local_recovery_console", lambda: False)
    result = ssh.apply_hardening(runner)[0]
    assert result.status is Status.FAIL and "rescue/emergency console" in result.detail
    keys = account.home / ".ssh" / "authorized_keys"
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)
    assert watchdog.pending is None


def test_child_closes_unrelated_fds_before_credentials_drop(
    account: Account,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with locked_target(ssh.SSHD_DROPIN) as lock_fd, ssh_permissions.inspect(account) as plan:
        assert lock_fd is not None
        target = plan.targets[0]

        def drop(owner: Account) -> None:
            assert owner == account
            os.fstat(lock_fd)
            os.fstat(target.fd)
            with pytest.raises(OSError, match="Bad file descriptor"):
                os.fstat(plan.home)

        monkeypatch.setattr(ssh_permissions, "_drop_credentials", drop)
        target.chmod(0o700, account, lock_fd)


def test_remote_or_pty_cannot_acknowledge_manual_modes(
    account: Account,
    runner: Runner,
    watchdog: Watchdog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    console_check = ssh._local_recovery_console
    monkeypatch.setattr(ssh, "confirm_once", lambda plan, **kwargs: True)
    assert ssh.apply_hardening(runner)[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    watchdog.update(pending, phase="failed")
    keys = account.home / ".ssh" / "authorized_keys"
    keys.chmod(MODE_FILE)
    keys.parent.chmod(MODE_DIR)
    monkeypatch.setattr(ssh, "_local_recovery_console", lambda: False)
    result = ssh.recover_failed_watchdog(runner, pending.id)
    assert result[-1].status is Status.FAIL and watchdog.pending is not None
    assert (mode(keys.parent), mode(keys)) == (MODE_DIR, MODE_FILE)
    monkeypatch.setattr(ssh, "_local_recovery_console", console_check)
    assert ssh.recover_failed_watchdog(runner, pending.id)[-1].status is Status.CHANGED


def test_privileged_fork_child_drops_all_credentials_in_order(
    account: Account,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int | list[int]]] = []
    ids = {"uid": 0, "gid": 0}

    def set_id(kind: str, value: int) -> None:
        calls.append((kind, value))
        ids[kind] = value

    monkeypatch.setattr(os, "getresuid", lambda: (ids["uid"],) * 3)
    monkeypatch.setattr(os, "getresgid", lambda: (ids["gid"],) * 3)
    monkeypatch.setattr(os, "getgroups", lambda: [])
    monkeypatch.setattr(os, "setgroups", lambda groups: calls.append(("groups", groups)))
    monkeypatch.setattr(os, "setgid", lambda gid: set_id("gid", gid))
    monkeypatch.setattr(os, "setuid", lambda uid: set_id("uid", uid))
    ssh_permissions._drop_credentials(account)
    assert calls == [("groups", []), ("gid", account.gid), ("uid", account.uid)]
