import base64
import errno
import json
import os
import stat
import struct
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from lhm.core import colors
from lhm.core.files import locked_target
from lhm.core.report import Status
from lhm.core.runner import ExecFn, Runner
from lhm.modules import ssh

PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    " robin@laptop"
)

SSHD_T_OK = """port 22345
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
authenticationmethods any
"""
ROBIN_LOOPBACK = "user=robin,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=22345"
ROBIN_ADMIN_CONFIG = SSHD_T_OK + "allowusers robin\nauthorizedkeysfile .ssh/authorized_keys\n"
ROBIN_ADMIN_PROBE = (f"sshd -T -C {ROBIN_LOOPBACK}", 0, ROBIN_ADMIN_CONFIG, "")
BOOT_ID = "cc083046-a214-4159-b81f-bc4a7bde8363"


class WatchdogFake:
    """Store JSON snapshots so a simulated crash loses foreground-only state."""

    now = 100.0

    def __init__(self) -> None:
        self.pending: ssh.ssh_watchdog.Pending | None = None
        self.prepared: ssh.ssh_watchdog.Pending | None = None
        self.arm_error = False
        self.arms = 0
        self.clears = 0
        self.cutoff_tick = 1000
        self.transport_tick = 1001
        self.freshness_checks: list[tuple[str, int, str]] = []

    def current(self) -> ssh.ssh_watchdog.Pending | None:
        return self.pending

    def arm(self, runner: Runner, data: dict[str, object]) -> ssh.ssh_watchdog.Pending:
        assert not runner.dry_run and self.pending is None
        self.arms += 1
        if self.arm_error:
            raise ssh.ssh_watchdog.WatchdogError("timer was not armed")
        txid = f"{self.arms:032x}"
        self.prepared = ssh.ssh_watchdog.Pending(
            txid, self.now + 60, "prepared", json.loads(json.dumps(data))
        )
        self.pending = ssh.ssh_watchdog.Pending(
            txid, self.prepared.deadline, "armed", self.prepared.data
        )
        return self.pending

    def update(
        self, pending: ssh.ssh_watchdog.Pending, *, phase: str | None = None, **data: object
    ) -> ssh.ssh_watchdog.Pending:
        assert pending == self.pending
        self.pending = ssh.ssh_watchdog.Pending(
            pending.id,
            pending.deadline,
            phase or pending.phase,
            json.loads(json.dumps(pending.data | data)),
        )
        return self.pending

    def clear(self, runner: Runner, pending: ssh.ssh_watchdog.Pending) -> None:
        assert not runner.dry_run and pending == self.pending
        self.clears += 1
        self.pending = None

    def freshness_cutoff(self) -> tuple[str, int]:
        return BOOT_ID, self.cutoff_tick

    def require_fresh_ssh(
        self, boot_id: str, cutoff_tick: int, *, account: ssh.userkeys.Account
    ) -> None:
        self.freshness_checks.append((boot_id, cutoff_tick, account.name))
        if boot_id != BOOT_ID or self.transport_tick <= cutoff_tick:
            raise ValueError("SSH transport predates the watchdog confirmation cutoff")


@pytest.fixture(autouse=True)
def watchdog(monkeypatch: pytest.MonkeyPatch) -> WatchdogFake:
    fake = WatchdogFake()
    for name in ("current", "arm", "update", "clear"):
        monkeypatch.setattr(ssh.ssh_watchdog, name, getattr(fake, name))
    monkeypatch.setattr(ssh, "monotonic", lambda: fake.now)
    monkeypatch.setattr(ssh.ssh_session, "freshness_cutoff", fake.freshness_cutoff)
    monkeypatch.setattr(ssh.ssh_session, "require_fresh_ssh", fake.require_fresh_ssh)
    return fake


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    root = tmp_path / "home"
    root.mkdir()
    monkeypatch.setattr(ssh, "HOME_ROOT", root)
    dropin = tmp_path / "etc" / "ssh" / "sshd_config.d" / "99-lhm.conf"
    dropin.parent.mkdir(mode=0o755, parents=True)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", dropin)
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", tmp_path / "run" / "sshd")
    monkeypatch.setattr(ssh, "geteuid", lambda: 1000)
    return root


def seed_user(home: Path, name: str, key: str = PUBKEY) -> None:
    keys = home / name / ".ssh" / "authorized_keys"
    keys.parent.mkdir(parents=True)
    keys.parent.chmod(0o700)
    keys.write_text(key + "\n", encoding="utf-8")
    keys.chmod(0o600)


class KeyExec:
    """Fake account commands; no subprocesses and no accesses outside test homes."""

    uid = 2712
    gid = 3456

    def __init__(self, home: Path, delegate: ExecFn) -> None:
        self.home = home
        self.delegate = delegate
        self.sudo_users: set[str] = set()
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        if cmd[:2] == ["/usr/bin/getent", "passwd"]:
            name = cmd[2]
            path = self.home / name
            if not path.is_dir():
                return subprocess.CompletedProcess(cmd, 2, "", "")
            return subprocess.CompletedProcess(
                cmd, 0, f"{name}:x:{self.uid}:{self.gid}::{path}:/bin/bash\n", ""
            )
        if cmd[0] == "useradd":
            (self.home / cmd[-1]).mkdir()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["usermod", "-aG", "sudo", cmd[-1]]:
            self.sudo_users.add(cmd[-1])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["id", "-nG"]:
            groups = "users sudo\n" if cmd[-1] in self.sudo_users else "users\n"
            return subprocess.CompletedProcess(cmd, 0, groups, "")
        if cmd[0] != "/usr/bin/setpriv":
            return self.delegate(cmd, timeout)

        op, uid, gid, home, arg, _limit = cmd[cmd.index("lhm-userkeys") + 1 :]
        assert (uid, gid) == (str(self.uid), str(self.gid))
        assert cmd[1:7] == ["--reuid", uid, "--regid", gid, "--clear-groups", "--no-new-privs"]
        assert Path(home).parent == self.home
        keys = Path(home) / ".ssh" / "authorized_keys"
        ready = keys.parent.exists() and stat.S_IMODE(keys.parent.stat().st_mode) == 0o700
        content = keys.read_text(encoding="utf-8") if keys.exists() else None
        mode = stat.S_IMODE(keys.stat().st_mode) if content is not None else None
        if op == "probe":
            payload = "-" if mode is None else f"{mode:04o} {encode_keys(content or '')}"
            frame = f"STATE {int(ready)} {payload}"
        else:
            assert op == "ensure"
            key_present = arg in (content or "").splitlines()
            changed = not ready or not key_present or mode != 0o600
            if changed:
                keys.parent.mkdir(exist_ok=True)
                keys.parent.chmod(0o700)
                if not key_present:
                    keys.write_text((content or "") + arg + "\n", encoding="utf-8")
                keys.chmod(0o600)
            frame = f"CHANGED {int(changed)}"
        return subprocess.CompletedProcess(cmd, 0, "LHM_USERKEYS_V1 " + frame + "\n", "")


def encode_keys(content: str) -> str:
    return base64.b64encode(content.encode()).decode()


def home_runner(home: Path, exec_fn: ExecFn) -> Runner:
    return Runner(exec_fn=KeyExec(home, exec_fn))


def test_invalid_pubkey_is_refused(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text("not-a-key at all\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert "not-a-key" not in results[0].detail
    assert "does not look like an SSH public key" in results[0].detail
    assert fake_exec.calls == []
    assert not (home / "robin").exists()


def test_private_key_pem_is_refused(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert "OPENSSH PRIVATE KEY" not in results[0].detail
    assert fake_exec.calls == []


@pytest.mark.parametrize("kind", ["symlink", "fifo", "large"])
def test_key_import_rejects_unsafe_leaf(
    fake_exec: Any, home: Path, tmp_path: Path, kind: str
) -> None:
    key_file = tmp_path / "id.pub"
    if kind == "symlink":
        target = tmp_path / "valid.pub"
        target.write_text(PUBKEY, encoding="utf-8")
        key_file.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(key_file)
    else:
        with key_file.open("wb") as output:
            output.truncate(2 * 1024 * 1024)
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    expected = "size limit" if kind == "large" else "regular nonsymlink"
    assert expected in results[0].detail
    assert fake_exec.calls == []


def test_direct_root_import_uses_open_directory_fds(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Treat only the test directory as / and synthesize root ownership there.
    home.chmod(0o755)
    admin = home / "root"
    admin.mkdir(mode=0o700)
    (home / "alias").symlink_to(admin, target_is_directory=True)
    key = admin / "admin.pub"
    key.write_text(PUBKEY, encoding="utf-8")
    key.chmod(0o600)
    open_file, stat_file, fstat_file = os.open, os.stat, os.fstat

    def open_fd(path: str, flags: int, *, dir_fd: int | None = None) -> int:
        if path == "/":
            assert dir_fd is None
            return open_file(home, flags)
        assert dir_fd is not None and "/" not in path
        assert flags & os.O_NOFOLLOW
        if path == "admin.pub":
            assert flags & os.O_NONBLOCK
        return open_file(path, flags, dir_fd=dir_fd)

    def as_root(info: os.stat_result) -> os.stat_result:
        values = list(info)
        values[4] = 0  # st_uid
        return os.stat_result(values)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", open_fd)
        scoped.setattr(os, "fstat", lambda fd: as_root(fstat_file(fd)))
        scoped.setattr(os, "stat", lambda path, **kw: as_root(stat_file(path, **kw)))
        assert ssh._read_root_key_source(Path("/root/admin.pub")) == PUBKEY
        with pytest.raises(OSError):
            ssh._read_root_key_source(Path("/alias/admin.pub"))
        admin.chmod(0o722)
        with pytest.raises(ssh.SshError, match="source directories"):
            ssh._read_root_key_source(Path("/root/admin.pub"))


@pytest.mark.parametrize("sudo_gid", ["42", "43"])
def test_sudo_source_import_checks_passwd_before_using_invoker(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sudo_gid: str
) -> None:
    monkeypatch.setattr(ssh, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "admin")
    monkeypatch.setenv("SUDO_UID", "41")
    monkeypatch.setenv("SUDO_GID", sudo_gid)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: False)
    source = str(tmp_path / "unreadable-by-lhm.pub")
    record = f"admin:x:41:42::{home / 'admin'}:/bin/bash\n"
    fake_exec.responses.extend(
        [
            ("/usr/bin/getent passwd admin", 0, record, ""),
            ("/usr/bin/getent passwd robin", 2, "", ""),
            (
                "/usr/bin/setpriv", 0,
                f"LHM_USERKEYS_V1 SOURCE {encode_keys(PUBKEY)}\n", "",
            ),
        ]
    )
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=source)
    if sudo_gid == "43":
        assert results[0].status is Status.FAIL
        assert "sudo invoker does not match" in results[0].detail
        assert fake_exec.calls == [["/usr/bin/getent", "passwd", "admin"]]
    else:
        assert results[0].status is Status.ABORTED
        assert len(fake_exec.calls) == 3
        helper = fake_exec.calls[1]
        assert helper[:5] == ["/usr/bin/setpriv", "--reuid", "41", "--regid", "42"]
        assert helper[-6:-1] == ["source", "41", "42", str(home / "admin"), source]


@pytest.mark.parametrize(
    "line",
    [
        # plausible prefix, garbage base64
        "ssh-ed25519 not-a-base64-blob robin@laptop",
        # valid base64, wrong wire type (ssh-rsa blob with ssh-ed25519 prefix)
        "ssh-ed25519 AAAAC3NzaC1yc2EAAAADAQABAAABgQC robin@laptop",
        # sk-/ecdsa- prefix with no blob at all
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256 AAAAnonsense",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH0l robin@laptop",
    ],
)
def test_pubkey_strict_validation(
    line: str, fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert not ssh.is_pubkey_line(line)
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text(line + "\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []
    assert not (home / "robin").exists()


def test_strict_validation_accepts_real_keys() -> None:
    assert ssh.is_pubkey_line(PUBKEY)
    assert ssh.is_pubkey_line(PUBKEY + " extra comment words")
    assert ssh.is_pubkey_line("\t " + PUBKEY.replace(" ", "\t", 1) + "\r")
    assert not ssh.is_pubkey_line("# " + PUBKEY)
    assert not ssh.is_pubkey_line("\f" + PUBKEY)
    assert not ssh.is_pubkey_line("\u00a0" + PUBKEY)
    assert not ssh.is_pubkey_line(PUBKEY.replace(" ", "\u00a0", 1))


@pytest.mark.parametrize("suffix", [b"x" * 32, struct.pack(">I", 31) + b"x" * 31])
def test_key_with_matching_type_but_malformed_material_is_refused(suffix: bytes) -> None:
    kind = b"ssh-ed25519"
    raw = struct.pack(">I", len(kind)) + kind + suffix
    assert not ssh.is_pubkey_line("ssh-ed25519 " + base64.b64encode(raw).decode("ascii"))


def test_key_with_trailing_wire_data_is_refused() -> None:
    key_type, blob, _ = PUBKEY.split()
    raw = base64.b64decode(blob) + b"trailing"
    assert not ssh.is_pubkey_line(f"{key_type} {base64.b64encode(raw).decode('ascii')}")


# SEC 2 public generator points in uncompressed SEC 1 form.
P256_GENERATOR = (
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
P384_GENERATOR = (
    "04"
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
)
P521_GENERATOR = (
    "04"
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de"
    "3348b3c1856a429bf97e7e31c2e5bd66"
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761"
    "353c7086a272c24088be94769fd16650"
)


def ecdsa_key_line(curve: str, point: bytes, *, security_key: bool = False) -> str:
    key_type = f"ecdsa-sha2-{curve}"
    if security_key:
        key_type = f"sk-{key_type}@openssh.com"
    fields = [key_type.encode(), curve.encode(), point]
    if security_key:
        fields.append(b"ssh:")
    raw = b"".join(struct.pack(">I", len(field)) + field for field in fields)
    return f"{key_type} {base64.b64encode(raw).decode('ascii')}"


@pytest.mark.parametrize(
    ("curve", "generator", "security_key"),
    [
        ("nistp256", P256_GENERATOR, False),
        ("nistp384", P384_GENERATOR, False),
        ("nistp521", P521_GENERATOR, False),
        ("nistp256", P256_GENERATOR, True),
    ],
)
def test_ecdsa_key_requires_point_on_declared_curve(
    curve: str, generator: str, security_key: bool
) -> None:
    point = bytes.fromhex(generator)
    off_curve = point[:-1] + bytes([point[-1] ^ 1])
    assert ssh.is_pubkey_line(ecdsa_key_line(curve, point, security_key=security_key))
    assert not ssh.is_pubkey_line(ecdsa_key_line(curve, off_curve, security_key=security_key))
    assert not ssh.is_pubkey_line(ecdsa_key_line(curve, b"\0", security_key=security_key))


def test_ecdsa_key_rejects_out_of_range_coordinate_even_when_on_curve_modulo_field() -> None:
    point = bytes.fromhex(P521_GENERATOR)
    x = int.from_bytes(point[1:67])
    noncanonical_x = (x + (1 << 521) - 1).to_bytes(66)
    assert not ssh.is_pubkey_line(ecdsa_key_line("nistp521", b"\x04" + noncanonical_x + point[67:]))


def test_ssh_user_creates_user_and_installs_key(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    accounts = KeyExec(home / "custom", fake_exec)
    accounts.home.mkdir()
    results = ssh.apply_user(Runner(exec_fn=accounts), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    keys = accounts.home / "robin" / ".ssh" / "authorized_keys"
    assert names["create user robin"] is Status.CHANGED
    assert names[f"install {keys}"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert keys.read_text(encoding="utf-8") == PUBKEY + "\n"
    assert keys.stat().st_mode & 0o777 == 0o600
    assert [cmd[0] for cmd in accounts.calls] == [
        "/usr/bin/getent", "useradd", "/usr/bin/getent",
        "/usr/bin/setpriv", "/usr/bin/setpriv", "/usr/bin/getent",
    ]
    assert fake_exec.calls == []


def test_ssh_user_skips_existing_key(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    results = ssh.apply_user(home_runner(home, fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    keys = home / "robin" / ".ssh" / "authorized_keys"
    assert names["create user robin"] is Status.SKIPPED
    assert names[f"install {keys}"] is Status.SKIPPED
    assert Status.CHANGED not in names.values()
    assert keys.read_text(encoding="utf-8") == PUBKEY + "\n"


def test_ssh_user_sudo_group(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    accounts = KeyExec(home, fake_exec)
    results = ssh.apply_user(
        Runner(exec_fn=accounts), user="robin", key_file=str(key_file), sudo=True
    )
    names = {r.name: r.status for r in results}
    assert names["add robin to sudo"] is Status.CHANGED
    assert [cmd[0] for cmd in accounts.calls] == [
        "/usr/bin/getent", "/usr/bin/getent", "/usr/bin/setpriv", "/usr/bin/setpriv",
        "/usr/bin/getent", "id", "usermod", "id",
    ]


@pytest.mark.parametrize(
    ("rc", "record", "detail"),
    [
        (3, "", "account lookup failed"),
        (0, "robin", "invalid passwd record"),
        (0, "other:x:1:2::/home/other:/bin/bash\n", "account identity mismatch"),
        (0, "robin:x:1001:2000::relative:/bin/bash\n", "invalid non-root account identity"),
    ],
)
def test_ssh_user_refuses_bad_lookup_without_useradd(
    fake_exec: Any, home: Path, tmp_path: Path, rc: int, record: str, detail: str
) -> None:
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY, encoding="utf-8")
    fake_exec.responses.append(("/usr/bin/getent passwd robin", rc, record, PUBKEY))
    result = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))[0]
    assert result.status is Status.FAIL
    assert detail in result.detail
    assert PUBKEY not in result.detail
    assert fake_exec.calls == [["/usr/bin/getent", "passwd", "robin"]]


def test_ssh_user_rechecks_new_identity_before_install(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY, encoding="utf-8")
    fake_exec.responses.append(("/usr/bin/getent passwd robin", 2, "", ""))
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.CHANGED
    assert results[-1].status is Status.FAIL
    assert "missing after useradd" in results[-1].detail
    assert [cmd[0] for cmd in fake_exec.calls] == ["/usr/bin/getent", "useradd", "/usr/bin/getent"]


@pytest.mark.parametrize(
    ("ready", "mode", "content"),
    [
        (1, "0600", "#" + PUBKEY),
        (1, "0600", "\f" + PUBKEY),
        (0, "0600", PUBKEY),
        (1, "0644", PUBKEY),
    ],
)
def test_ssh_user_never_grants_sudo_on_mismatched_probe(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ready: int, mode: str, content: str,
) -> None:
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY, encoding="utf-8")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    calls: list[str] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[0] == "/usr/bin/getent":
            name = cmd[-1]
            calls.append("getent")
            return subprocess.CompletedProcess(
                cmd, 0, f"{name}:x:543:21::{home / name}:/bin/bash\n", ""
            )
        assert cmd[:5] == ["/usr/bin/setpriv", "--reuid", "543", "--regid", "21"]
        op = cmd[cmd.index("lhm-userkeys") + 1]
        calls.append(op)
        if op == "ensure":
            frame = "CHANGED 0"
        else:
            assert op == "probe"
            frame = f"STATE {ready} {mode} {encode_keys(content)}"
        return subprocess.CompletedProcess(cmd, 0, f"LHM_USERKEYS_V1 {frame}\n", "")

    results = ssh.apply_user(
        Runner(exec_fn=execute), user="robin", key_file=str(key_file), sudo=True
    )
    assert results[-1].name == "verify"
    assert results[-1].status is Status.FAIL
    assert calls == ["getent", "getent", "ensure", "probe"]


def test_hardening_refuses_without_authorized_keys(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    assert results[0].status is Status.FAIL
    assert "no authorized_keys" in results[0].detail
    assert fake_exec.calls == []
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_refuses_when_requested_user_has_no_valid_key(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin", "junk\f" + PUBKEY)
    results = ssh.apply_hardening(home_runner(home, fake_exec), allow_users=["robin"])
    assert results[0].status is Status.FAIL
    assert "robin" in results[0].detail
    assert "no valid authorized_keys" in results[0].detail
    assert fake_exec.calls == []
    assert not ssh.SSHD_DROPIN.exists()


def test_inspect_skips_failed_probes_and_nonstandard_discovery_homes(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "geteuid", lambda: 0)
    for name in ("valid", "failed", "outside"):
        (home / name).mkdir()
    (home / "link").symlink_to(home / "valid", target_is_directory=True)
    for name in ("valid", "failed", "outside"):
        passwd_home = home / name if name != "outside" else home.parent / name
        record = f"{name}:x:1223:1229::{passwd_home}:/bin/bash\n"
        fake_exec.responses.append((f"/usr/bin/getent passwd {name}", 0, record, ""))
    probes: list[Path] = []
    valid_frame = f"LHM_USERKEYS_V1 STATE 1 0600 {encode_keys(PUBKEY)}\n"

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[0] != "/usr/bin/setpriv":
            return fake_exec(cmd, timeout)
        assert cmd[-6] == "probe"
        assert cmd[1:5] == ["--reuid", "1223", "--regid", "1229"]
        probes.append(Path(cmd[-3]))
        # A failed command cannot provide evidence of a valid key even with a valid frame.
        return subprocess.CompletedProcess(cmd, int(probes[-1].name == "failed"), valid_frame, "")

    state = ssh.inspect(Runner(exec_fn=execute))
    assert state["authorized_users"] == ["valid"]
    assert probes == [home / "failed", home / "valid"]
    assert all(cmd[-1] != "link" for cmd in fake_exec.calls)

    results = ssh.apply_hardening(Runner(exec_fn=execute), allow_users=["failed", "valid"])
    assert results[0].status is Status.FAIL
    assert "probe helper failed" in results[0].detail
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_can_explicitly_allow_a_nonstandard_passwd_home(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom = tmp_path / "custom"
    seed_user(custom, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: False)
    accounts = KeyExec(custom, fake_exec)
    results = ssh.apply_hardening(Runner(exec_fn=accounts), allow_users=["robin"])
    assert results[0].status is Status.ABORTED
    assert accounts.calls[1][-3] == str(custom / "robin")
    assert fake_exec.calls == []


def test_hardening_rolls_back_when_sshd_t_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    stale = ssh.SSHD_DROPIN.with_suffix(".conf.bak")
    stale.write_text("stale backup\n", encoding="utf-8")
    fake_exec.responses.extend(SSH_SERVICE_ACTIVE)
    fake_exec.responses.append(("ss -tlnp", 0, SS_TLN_OLD_PORT, ""))

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["sshd", "-t"] and ssh.SSHD_DROPIN.exists():
            return subprocess.CompletedProcess(cmd, 1, "", "candidate: bad port")
        if cmd == SSH_SERVICE_RELOAD:
            assert not ssh.SSHD_DROPIN.exists()
        return fake_exec(cmd, timeout)

    results = ssh.apply_hardening(home_runner(home, execute), port=22345)
    names = {r.name: r.status for r in results}
    assert names["sshd -t"] is Status.FAIL
    assert "removed the new drop-in" in {r.name: r.detail for r in results}["restore ssh drop-in"]
    assert not ssh.SSHD_DROPIN.exists()
    assert stale.read_text(encoding="utf-8") == "stale backup\n"
    assert fake_exec.calls.count(SSH_SERVICE_RELOAD) == 1
    assert watchdog.clears == 1 and watchdog.pending is None


def test_hardening_rolls_back_to_previous_content(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")
    fake_exec.responses.extend(SSH_SERVICE_ACTIVE)
    fake_exec.responses.append(("ss -tlnp", 0, SS_TLN_OLD_PORT, ""))
    fake_exec.responses.append(("sshd -t", 1, "", "bad config"))
    results = ssh.apply_hardening(home_runner(home, fake_exec), port=22345)
    assert results[1].status is Status.FAIL
    assert "restored" in results[-1].detail
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == "Port 22\n"


@pytest.mark.parametrize("previous", [None, b"Port 22\r\n# local settings\r\n"])
def test_hardening_recovers_interrupt_after_atomic_replace(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, previous: bytes | None
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    target = ssh.SSHD_DROPIN
    stale = target.with_suffix(".conf.bak")
    stale.write_bytes(b"stale backup")
    if previous is not None:
        target.write_bytes(previous)
        target.chmod(0o600)
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])
    replace = os.replace
    interrupted = False

    def replace_then_interrupt(src: str | Path, dst: str | Path) -> None:
        nonlocal interrupted
        replace(src, dst)
        if dst == target and not interrupted:
            interrupted = True
            assert target.read_bytes() == ssh.desired_conf(22345, ["robin"]).encode()
            raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", replace_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        ssh.apply_hardening(home_runner(home, fake_exec))
    assert interrupted
    if previous is None:
        assert not target.exists()
    else:
        assert target.read_bytes() == previous
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stale.read_bytes() == b"stale backup"
    assert fake_exec.calls.count(SSH_SERVICE_RELOAD) == 1


def test_hardening_does_not_rewrite_prechange_dropin_when_replace_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    target = ssh.SSHD_DROPIN
    previous = b"Port 22\r\n"
    target.write_bytes(previous)
    inode = target.stat().st_ino
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])

    def fail_replace(src: str | Path, dst: str | Path) -> None:
        raise OSError("replace failed before changing the file")

    monkeypatch.setattr(os, "replace", fail_replace)
    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, fake_exec))}
    assert "replace failed" in steps["ssh-hardening"].detail
    assert steps["restore ssh drop-in"].status is Status.SKIPPED
    assert target.read_bytes() == previous and target.stat().st_ino == inode
    assert fake_exec.calls.count(SSH_SERVICE_RELOAD) == 1


@pytest.mark.parametrize(
    "change", ["contents", "symlink", "missing backup", "backup contents", "read failure"]
)
def test_hardening_never_overwrites_unverified_recovery_state(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    target = ssh.SSHD_DROPIN
    target.write_bytes(b"Port 22\n")
    displaced = home / "unrelated"
    third_party = b"Port 2200\n"
    displaced.write_bytes(third_party)
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])

    def fail_snapshot(path: Path | None = None) -> bytes | None:
        raise PermissionError("cannot read snapshot")

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["sshd", "-t"]:
            if change == "contents":
                target.write_bytes(third_party)
            elif change == "symlink":
                target.unlink()
                target.symlink_to(displaced)
            elif change == "missing backup":
                target.with_suffix(".conf.bak").unlink()
            elif change == "read failure":
                monkeypatch.setattr(ssh, "_dropin_snapshot", fail_snapshot)
            else:
                target.with_suffix(".conf.bak").write_bytes(third_party)
            return subprocess.CompletedProcess(cmd, 1, "", "original gate failure")
        return fake_exec(cmd, timeout)

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert "original gate failure" in steps["sshd -t"].detail
    assert steps["restore ssh drop-in"].status is Status.FAIL
    assert target.is_symlink() is (change == "symlink")
    assert displaced.read_bytes() == third_party
    if change in {"contents", "symlink"}:
        assert target.read_bytes() == third_party
    else:
        assert target.read_bytes() == ssh.desired_conf(22345, ["robin"]).encode()
    assert fake_exec.calls == SSH_SERVICE_PREFLIGHT_CALLS


SS_TLN_OK = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22345      0.0.0.0:*     users:(("sshd",pid=1,fd=3))
"""

SS_TLN_OLD_PORT = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1,fd=3))
"""

SSH_SOCKETS_INACTIVE = [
    ("systemctl is-active ssh.socket", 3, "inactive\n", ""),
    ("systemctl is-active sshd.socket", 4, "inactive\n", ""),
]


def loaded_service(unit: str) -> tuple[str, int, str, str]:
    return (
        f"systemctl show --property=Id --property=LoadState {unit}",
        0,
        f"Id={unit}\nLoadState=loaded\n",
        "",
    )


SSH_SERVICE_ACTIVE = [
    *SSH_SOCKETS_INACTIVE,
    ("systemctl is-active ssh.service", 0, "active\n", ""),
    loaded_service("ssh.service"),
    ("systemctl is-enabled ssh.service", 0, "enabled\n", ""),
]
SSH_SERVICE_JOBS = ["systemctl", "list-jobs", "--no-legend", "--no-pager", "ssh.service"]
SSH_SERVICE_RELOAD = ["systemctl", "reload", "--job-mode=fail", "ssh.service"]
SSH_SERVICE_PREFLIGHT_CALLS = [
    *(cmd.split() for cmd, *_ in SSH_SERVICE_ACTIVE),
    ["ss", "-tlnp"],
    SSH_SERVICE_JOBS,
]


@pytest.mark.parametrize(
    ("unit", "rc", "state", "detail"),
    [
        ("ssh.socket", 124, "", "cannot determine whether ssh.socket is active"),
        ("sshd.socket", 0, "", "cannot determine whether sshd.socket is active"),
        ("ssh.service", 124, "", "cannot determine whether ssh.service is active"),
        ("sshd.service", 3, "activating", "cannot determine whether sshd.service is active"),
        ("sshd.service", 3, "failed", "no active SSH service"),
    ],
)
@pytest.mark.parametrize("missing_parent", [False, True])
def test_hardening_refuses_unconfirmed_activation_despite_live_sshd(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    unit: str,
    rc: int,
    state: str,
    detail: str,
    missing_parent: bool,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    if missing_parent:
        ssh.SSHD_DROPIN.parent.rmdir()
    fake_exec.responses.extend(
        [
            (f"systemctl is-active {unit}", rc, state, ""),
            *SSH_SOCKETS_INACTIVE,
            ("systemctl is-active ssh.service", 4, "inactive\n", ""),
            ("systemctl is-active sshd.service", 0, "active\n", ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert all(cmd[:2] == ["systemctl", "is-active"] for cmd in fake_exec.calls)
    assert results[0].status is Status.FAIL
    assert detail in results[0].detail
    assert not ssh.SSHD_DROPIN.exists()
    assert ssh.SSHD_DROPIN.parent.exists() is not missing_parent
    assert not ssh.PRIVSEP_DIR.exists()


def test_hardening_writes_dropin_then_reloads_and_verifies(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("sshd -t", 0, "", ""),
            ("systemctl reload --job-mode=fail ssh.service", 0, "", ""),
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec), port=22345, allow_users=["robin"])
    names = {r.name: r.status for r in results}
    assert names["reload sshd"] is Status.CHANGED
    assert results[-1].status is Status.OK
    content = ssh.SSHD_DROPIN.read_text(encoding="utf-8")
    assert "Port 22345" in content
    assert "AllowUsers robin" in content
    assert "AuthorizedKeysFile .ssh/authorized_keys" in content
    order = [" ".join(call) for call in fake_exec.calls]
    gate = next(i for i, c in enumerate(order) if c == "sshd -t")
    reload_index = next(i for i, c in enumerate(order) if c.startswith("systemctl reload"))
    assert gate < reload_index
    # The effective-config gate must also run before the reload.
    effective_gate = next(i for i, c in enumerate(order) if c == "sshd -T")
    scoped = [i for i, cmd in enumerate(order) if cmd == ROBIN_ADMIN_PROBE[0]]
    assert len(scoped) == 2
    assert gate < effective_gate < scoped[0] < reload_index < scoped[1]
    assert "loopback (localhost)" in results[-1].detail
    assert "not a login test" in results[-1].detail


@pytest.mark.parametrize("blocker", ["ssh.socket", "ssh.service", "unknown"])
@pytest.mark.parametrize("before_write", [True, False])
def test_hardening_refuses_observed_forward_jobs(
    home: Path, monkeypatch: pytest.MonkeyPatch, blocker: str, before_write: bool
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    old = "Port 22\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    socket = SocketRecoveryExec(socket_unit="sshd.socket", restart_failure=None)
    expected = old if before_write else ssh.desired_conf(22345, ["robin"])

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["systemctl", "list-jobs"]:
            assert cmd[-2:] == ["sshd.socket", "ssh.service"]
            if ssh.SSHD_DROPIN.read_text(encoding="utf-8") == expected:
                if blocker == "unknown":
                    return subprocess.CompletedProcess(cmd, 124, "", "timed out")
                unit = "sshd.socket" if blocker == "ssh.socket" else blocker
                return subprocess.CompletedProcess(cmd, 0, f"1 {unit} stop waiting\n", "")
        return socket(cmd, timeout)

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["ssh-hardening"].status is Status.FAIL
    assert "pending jobs" in steps["ssh-hardening"].detail
    assert ("restore ssh drop-in" in steps) is not before_write
    assert not any(
        cmd[1] in {"disable", "enable", "stop", "start", "restart", "reload", "cancel"}
        for cmd in socket.calls
    )
    assert socket.socket_active and socket.enabled_state == (0, "enabled")
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old


@pytest.mark.parametrize(
    ("rc", "override", "problem"),
    [
        (0, ("authorizedkeysfile", "/etc/ssh/keys/%u"), "exactly to the managed key file"),
        (0, ("authorizedkeysfile", "none"), "single unambiguous path"),
        (0, ("authorizedkeysfile", ".ssh/authorized_keys\r"), "single unambiguous path"),
        (0, ("pubkeyauthentication", "no"), "PubkeyAuthentication must be yes"),
        (0, ("passwordauthentication", "yes"), "passwordauthentication yes"),
        (0, ("allowusers", "robin"), "allowusers missing deploy"),
        (1, None, "probe failed (rc=1)"),
        (0, None, "probe returned empty output"),
    ],
)
@pytest.mark.parametrize("current", [False, True])
def test_hardening_checks_every_admin_match_before_activation_or_skipping_write(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    rc: int,
    override: tuple[str, str] | None,
    problem: str,
    current: bool,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.1 54321 198.51.100.2 22")
    for name in ("robin", "deploy"):
        seed_user(home, name)
    old = ssh.desired_conf(22345, ["robin", "deploy"]) if current else "Port 22\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    scope = "host=192.0.2.1,addr=192.0.2.1,laddr=198.51.100.2,lport=22345"
    robin_cmd = f"sshd -T -C user=robin,{scope}"
    deploy_cmd = f"sshd -T -C user=deploy,{scope}"
    both_allowed = "allowusers robin\nallowusers deploy\n"
    admin_fields = SSHD_T_OK + "authorizedkeysfile .ssh/authorized_keys\n"
    # A Match may supply a user-specific AllowUsers set. Do not require that
    # robin's context admit deploy, but require deploy in deploy's own context.
    robin_config = admin_fields + "allowusers robin\n"
    deploy_config = admin_fields + both_allowed
    if override is None:
        deploy_config = ""
    elif override[0] == "allowusers":
        deploy_config = admin_fields + f"allowusers {override[1]}\n"
    else:
        option, value = override
        deploy_config = "".join(
            f"{option} {value}\n" if line.startswith(f"{option} ") else line
            for line in deploy_config.splitlines(keepends=True)
        )
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
            (robin_cmd, 0, robin_config, ""),
            (deploy_cmd, rc, deploy_config, ""),
            ("sshd -T", 0, SSHD_T_OK + both_allowed, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec), allow_users=["robin", "deploy"])
    steps = {step.name: step for step in results}
    failed = steps["verify" if current else "sshd -T admin keys"]
    assert failed.status is Status.FAIL
    assert "deploy:" in failed.detail
    assert problem in failed.detail
    assert "SSH_CONNECTION addresses and target port" in failed.detail
    assert "not a login test" in failed.detail
    order = [" ".join(call) for call in fake_exec.calls]
    assert [cmd for cmd in order if cmd.startswith("sshd -T -C")] == [robin_cmd, deploy_cmd]
    probes = {"is-active", "is-enabled", "show", "list-jobs"}
    actions = [cmd for cmd in fake_exec.calls if cmd[0] == "systemctl" and cmd[1] not in probes]
    assert actions == ([] if current else [SSH_SERVICE_RELOAD])
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old
    if not current:
        assert steps["restore ssh drop-in"].status is Status.CHANGED


def test_hardening_accepts_multiple_admins_in_repeated_allowusers_rows(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    for name in ("robin", "deploy"):
        seed_user(home, name)
    global_config = SSHD_T_OK + "allowusers robin\nallowusers deploy\n"
    scoped_config = global_config + "authorizedkeysfile .ssh/authorized_keys\n"
    deploy_cmd = ROBIN_ADMIN_PROBE[0].replace("user=robin,", "user=deploy,", 1)
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            (ROBIN_ADMIN_PROBE[0], 0, scoped_config, ""),
            (deploy_cmd, 0, scoped_config, ""),
            ("sshd -T", 0, global_config, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[-1].status is Status.OK
    assert "managed key path and settings match for deploy, robin" in results[-1].detail
    order = [" ".join(cmd) for cmd in fake_exec.calls if cmd[:3] == ["sshd", "-T", "-C"]]
    assert order == [deploy_cmd, ROBIN_ADMIN_PROBE[0]] * 2


def test_hardening_scoped_gate_uses_probed_nss_home_and_uid_and_allows_mfa(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    custom = tmp_path / str(KeyExec.uid)
    seed_user(custom, "robin")
    config = (
        SSHD_T_OK.replace("kbdinteractiveauthentication no", "kbdinteractiveauthentication yes")
        .replace(
            "authenticationmethods any", "authenticationmethods publickey,keyboard-interactive:pam"
        )
        + f"usepam yes\nauthorizedkeysfile {tmp_path}/%U/%u/.ssh/authorized_keys\n"
    )
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            (ROBIN_ADMIN_PROBE[0], 0, config, ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    accounts = KeyExec(custom, fake_exec)
    results = ssh.apply_hardening(Runner(exec_fn=accounts), allow_users=["robin"])
    assert accounts.calls[1][-3] == str(custom / "robin")
    assert [step.status for step in results if step.name in {"sshd -T admin keys", "verify"}] == [
        Status.OK,
        Status.OK,
    ]


@pytest.mark.parametrize("identity", ["missing", "changed", "ambiguous"])
def test_hardening_fails_if_discovered_account_no_longer_matches_key_snapshot(
    identity: str, fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
        ]
    )
    account_exec = KeyExec(home, fake_exec)
    lookup = ["/usr/bin/getent", "passwd", "robin"]
    resolved = account_exec(lookup, 10).stdout
    getent_count = 0

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal getent_count
        if cmd == lookup:
            getent_count += 1
            if getent_count == 2:
                if identity == "missing":
                    return subprocess.CompletedProcess(cmd, 2, "", "")
                record = (
                    resolved + resolved
                    if identity == "ambiguous"
                    else resolved.replace(f":{KeyExec.uid}:", ":2222:")
                )
                return subprocess.CompletedProcess(cmd, 0, record, "")
        return account_exec(cmd, timeout)

    results = ssh.apply_hardening(Runner(exec_fn=execute))
    steps = {step.name: step for step in results}
    gate = steps["sshd -T admin keys"]
    assert gate.status is Status.FAIL
    assert "robin:" in gate.detail
    expected = "invalid passwd record" if identity == "ambiguous" else "identity changed"
    assert expected in gate.detail
    assert getent_count == 2
    assert not any(cmd[:3] == ["sshd", "-T", "-C"] for cmd in fake_exec.calls)
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_targets_only_the_confirmed_active_service(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SOCKETS_INACTIVE,
            ("systemctl is-active ssh.service", 4, "inactive\n", ""),
            ("systemctl is-active sshd.service", 0, "active\n", ""),
            loaded_service("sshd.service"),
            ("systemctl is-enabled sshd.service", 0, "enabled\n", ""),
            ("systemctl reload --job-mode=fail sshd.service", 0, "", ""),
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert [cmd for cmd in fake_exec.calls if cmd[:2] == ["systemctl", "reload"]] == [
        ["systemctl", "reload", "--job-mode=fail", "sshd.service"]
    ]
    reload_step = next(r for r in results if r.name == "reload sshd")
    assert reload_step.detail == "reloaded sshd.service"
    assert results[-1].status is Status.OK


def test_hardening_does_not_replace_stop_job_racing_standalone_reload(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    stop_pending = False
    reloads: list[list[str]] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal stop_pending
        if cmd[:2] == ["systemctl", "list-jobs"]:
            assert cmd == SSH_SERVICE_JOBS
            if stop_pending:
                return subprocess.CompletedProcess(cmd, 0, "1 ssh.service stop waiting\n", "")
        if cmd[:2] == ["systemctl", "reload"]:
            reloads.append(cmd)
            stop_pending = True  # Queues after the job check, just before ReloadUnit.
            if "--job-mode=fail" in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "conflicting job")
            stop_pending = False  # Stock default job mode replaces the queued stop.
        return fake_exec(cmd, timeout)

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["reload sshd"].status is Status.FAIL
    assert steps["restore ssh listener"].status is Status.FAIL
    assert "jobs pending" in steps["restore ssh listener"].detail
    assert len(reloads) == 1 and stop_pending
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_stops_then_disables_socket_before_restarting_service(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debian 12 ssh.socket owns the listener: reload would keep port 22."""
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    execute = SocketRecoveryExec(restart_failure=None, migrated_listeners=(0, SS_TLN_OK))
    results = ssh.apply_hardening(home_runner(home, execute), port=22345)
    order = [" ".join(call) for call in execute.calls]
    stop = order.index("systemctl stop --job-mode=fail ssh.socket")
    disable = order.index("systemctl disable ssh.socket")
    restart = order.index("systemctl restart --job-mode=fail ssh.service")
    assert stop < disable < restart
    assert not any(call.startswith("systemctl reload") for call in order)
    assert results[-1].status is Status.OK
    steps = {r.name: r.status for r in results}
    assert steps["disable ssh.socket"] is Status.CHANGED
    assert execute.service_persistent
    assert not execute.service_runtime


@pytest.mark.parametrize(
    ("socket_state", "service_state", "service_enable"),
    [
        ("enabled-runtime", (1, "disabled"), "enable --runtime"),
        ("enabled-runtime", (0, "enabled"), None),
        ("enabled", (0, "enabled"), None),
        ("enabled", (0, "enabled-runtime"), "enable"),
    ],
)
def test_hardening_preserves_socket_boot_scope_without_removing_existing_service_enablement(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    socket_state: str,
    service_state: tuple[int, str],
    service_enable: str | None,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    execute = SocketRecoveryExec(
        enabled_state=(0, socket_state),
        service_state=service_state,
        restart_failure=None,
        migrated_listeners=(0, SS_TLN_OK),
    )
    results = ssh.apply_hardening(home_runner(home, execute))
    assert results[-1].status is Status.OK
    assert execute.service_persistent is (
        socket_state == "enabled" or service_state == (0, "enabled")
    )
    assert execute.service_runtime is (
        service_enable == "enable --runtime" or service_state == (0, "enabled-runtime")
    )
    mutations = [
        " ".join(cmd)
        for cmd in execute.calls
        if cmd[1] in {"enable", "disable"} and cmd[-1] == execute.service_unit
    ]
    assert mutations == ([f"systemctl {service_enable} ssh.service"] if service_enable else [])


def test_hardening_verify_reports_actual_listening_port_mismatch(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sshd -T says 22345 (socket activation hides it) but only 22 listens."""
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("sshd -t", 0, "", ""),
            ("systemctl reload --job-mode=fail ssh.service", 0, "", ""),
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec), port=22345)
    verify = next(step for step in results if step.name == "verify")
    assert verify.status is Status.FAIL
    assert "not listening" in verify.detail
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_does_not_verify_an_unrelated_listener(fake_exec: Any, home: Path) -> None:
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK.replace('"sshd"', '"not-sshd"'), ""),
        ]
    )
    ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, ["robin"]), encoding="utf-8")
    result = ssh.apply_hardening(home_runner(home, fake_exec))[-1]
    assert result.status is Status.FAIL
    assert "not listening via sshd" in result.detail


def test_identical_hardening_verifies_under_lock_and_may_skip_unavailable_probe(
    fake_exec: Any, home: Path
) -> None:
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, ["robin"]), encoding="utf-8")
    fake_exec.responses.extend(
        [
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 127, "", "command not found"),
        ]
    )

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        with pytest.raises(BlockingIOError, match="managed target is locked"):
            with locked_target(ssh.SSHD_DROPIN):
                pytest.fail("SSH target was unlocked")
        return fake_exec(cmd, timeout)

    results = ssh.apply_hardening(home_runner(home, execute))
    assert [step.status for step in results] == [Status.SKIPPED, Status.SKIPPED]
    assert "not verified" in results[-1].detail
    assert fake_exec.calls == [
        ["sshd", "-T"],
        ["sshd", "-T", "-C", ROBIN_LOOPBACK],
        ["ss", "-tlnp"],
    ]


def test_hardening_recovers_service_when_post_mutation_listener_probe_is_unavailable(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    old = "Port 22\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    reloads: list[str] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        for command, rc, out, err in SSH_SERVICE_ACTIVE:
            if " ".join(cmd) == command:
                return subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd[:2] == ["systemctl", "reload"] and cmd[-1] == "ssh.service":
            reloads.append(ssh.SSHD_DROPIN.read_text(encoding="utf-8"))
        if cmd == ["ss", "-tlnp"] and len(reloads) == 1:
            return subprocess.CompletedProcess(cmd, 127, "", "command not found")
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            return subprocess.CompletedProcess(cmd, 0, ROBIN_ADMIN_CONFIG, "")
        stdout = {"sshd -T": SSHD_T_OK, "ss -tlnp": SS_TLN_OLD_PORT}.get(" ".join(cmd), "")
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    results = ssh.apply_hardening(home_runner(home, execute))
    steps = {step.name: step for step in results}
    assert steps["verify"].status is Status.FAIL
    assert "not verified" in steps["verify"].detail
    assert steps["restore ssh listener"].status is Status.CHANGED
    assert reloads == [ssh.desired_conf(22345, ["robin"]), old]
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old


@pytest.mark.parametrize("recovery_blocker", [None, "pending job", "failed reload", "bad config"])
def test_hardening_requires_successful_reload_to_verify_same_port_recovery(
    home: Path, monkeypatch: pytest.MonkeyPatch, recovery_blocker: str | None
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    old = "Port 22345\nPasswordAuthentication yes\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    validated: list[str] = []
    reloads: list[str] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        for command, rc, out, err in SSH_SERVICE_ACTIVE:
            if " ".join(cmd) == command:
                return subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd == ["sshd", "-t"]:
            validated.append(ssh.SSHD_DROPIN.read_text(encoding="utf-8"))
            if reloads and recovery_blocker == "bad config":
                return subprocess.CompletedProcess(cmd, 1, "", "bad config")
        if cmd == SSH_SERVICE_JOBS and reloads and recovery_blocker == "pending job":
            return subprocess.CompletedProcess(cmd, 0, "1 ssh.service reload running\n", "")
        if cmd[:2] == ["systemctl", "reload"]:
            reloads.append(ssh.SSHD_DROPIN.read_text(encoding="utf-8"))
            if len(reloads) == 2:
                assert cmd == ["systemctl", "reload", "--job-mode=fail", "ssh.service"]
                assert validated[-1] == old
                if recovery_blocker == "failed reload":
                    return subprocess.CompletedProcess(cmd, 1, "", "could not reload")
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            if reloads:
                return subprocess.CompletedProcess(cmd, 124, "", "timed out")
            return subprocess.CompletedProcess(cmd, 0, ROBIN_ADMIN_CONFIG, "")
        stdout = {"sshd -T": SSHD_T_OK, "ss -tlnp": SS_TLN_OK}.get(" ".join(cmd), "")
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    steps = {step.name: step for step in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["verify"].status is Status.FAIL
    expected_status = Status.FAIL if recovery_blocker else Status.CHANGED
    assert steps["restore ssh listener"].status is expected_status
    expected_reloads = [ssh.desired_conf(22345, ["robin"])]
    if recovery_blocker in {None, "failed reload"}:
        expected_reloads.append(old)
    assert reloads == expected_reloads
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old


@pytest.mark.parametrize("recovery_action", ["reload", "start", None])
def test_hardening_recovers_only_previously_active_service(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    recovery_action: str | None,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    old = "Port 22\n# local settings\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    actions: list[tuple[str, str]] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        for command, rc, out, err in SSH_SOCKETS_INACTIVE:
            if " ".join(cmd) == command:
                return subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd == ["systemctl", "is-active", "ssh.service"]:
            return subprocess.CompletedProcess(cmd, 4, "inactive\n", "")
        if cmd == ["systemctl", "is-active", "sshd.service"]:
            if not actions or len(actions) > 1 or recovery_action == "reload":
                return subprocess.CompletedProcess(cmd, 0, "active\n", "")
            if recovery_action == "start":
                return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
            return subprocess.CompletedProcess(cmd, 124, "", "timed out")
        command, rc, out, err = loaded_service("sshd.service")
        if " ".join(cmd) == command:
            return subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd == ["systemctl", "is-enabled", "sshd.service"]:
            return subprocess.CompletedProcess(cmd, 0, "enabled-runtime\n", "")
        if cmd[0] == "systemctl" and cmd[1] in {"reload", "start"}:
            contents = ssh.SSHD_DROPIN.read_text(encoding="utf-8")
            actions.append((f"{cmd[1]} {cmd[-1]}", contents))
            return subprocess.CompletedProcess(cmd, 0 if contents == old else 1, "", "")
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            return subprocess.CompletedProcess(cmd, 0, ROBIN_ADMIN_CONFIG, "")
        stdout = {"sshd -T": SSHD_T_OK, "ss -tlnp": SS_TLN_OLD_PORT}.get(" ".join(cmd), "")
        if cmd == ["ss", "-tlnp"] and recovery_action == "reload" and len(actions) == 1:
            stdout = SS_TLN_OK
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    results = ssh.apply_hardening(home_runner(home, execute))
    steps = {step.name: step for step in results}
    assert steps["reload sshd"].status is Status.FAIL
    assert actions[0] == ("reload sshd.service", ssh.desired_conf(22345, ["robin"]))
    if recovery_action is None:
        assert steps["restore ssh listener"].status is Status.FAIL
        assert "use the local console to check sshd.service" in capsys.readouterr().err
        assert len(actions) == 1
    else:
        assert steps["restore ssh listener"].status is Status.CHANGED
        assert actions[1:] == [(f"{recovery_action} sshd.service", old)]
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old


def test_hardening_leaves_standalone_service_untouched_after_dropin_rollback_exception(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")

    def fail_rollback(path: Path, *, backup: Path) -> Path:
        raise OSError("rollback failed")

    monkeypatch.setattr(ssh, "rollback_file", fail_rollback)
    calls: list[list[str]] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        for command, rc, out, err in SSH_SERVICE_ACTIVE:
            if " ".join(cmd) == command:
                return subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd[:2] == ["systemctl", "reload"]:
            return subprocess.CompletedProcess(cmd, 1, "", "activation failed")
        if cmd == ["ss", "-tlnp"]:
            return subprocess.CompletedProcess(cmd, 0, SS_TLN_OLD_PORT, "")
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            return subprocess.CompletedProcess(cmd, 0, ROBIN_ADMIN_CONFIG, "")
        stdout = SSHD_T_OK if cmd == ["sshd", "-T"] else ""
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["reload sshd"].status is Status.FAIL
    assert steps["restore ssh drop-in"].status is Status.FAIL
    assert "rollback failed" in steps["restore ssh drop-in"].detail
    assert steps["restore ssh listener"].status is Status.FAIL
    assert "old config not verified" in steps["restore ssh listener"].detail
    assert [cmd for cmd in calls if cmd[1] in {"reload", "start", "stop"}] == [
        ["systemctl", "reload", "--job-mode=fail", "ssh.service"]
    ]


def test_hardening_effective_conflict_rolls_back_and_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """50-cloud-init.conf wins (first obtained value): detect, roll back, FAIL."""
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    conflicting = ssh.SSHD_DROPIN.parent / "50-cloud-init.conf"
    conflicting.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("sshd -t", 0, "", ""),
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
            (
                "sshd -T",
                0,
                SSHD_T_OK.replace("passwordauthentication no", "passwordauthentication yes"),
                "",
            ),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec), port=22345)
    gate = next(r for r in results if r.name == "sshd -T effective")
    assert gate.status is Status.FAIL
    assert "passwordauthentication yes" in gate.detail
    assert "50-cloud-init.conf" in gate.detail
    assert "PasswordAuthentication yes" in gate.detail
    rollback = next(r for r in results if r.name == "restore ssh drop-in")
    assert "removed the new drop-in" in rollback.detail
    assert not ssh.SSHD_DROPIN.exists()
    order = [" ".join(call) for call in fake_exec.calls]
    assert fake_exec.calls.count(SSH_SERVICE_RELOAD) == 1
    assert not any(call.startswith("systemctl restart") for call in order)


def test_hardening_dry_run_prints_plan_and_writes_nothing(
    fake_exec: Any, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_user(home, "robin")
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = ssh.apply_hardening(runner, port=22345)
    out = capsys.readouterr().out
    assert "Port 22345" in out
    assert "per-admin authorized_keys" in out
    assert not ssh.SSHD_DROPIN.exists()
    assert all(r.status is Status.PLANNED for r in results)
    assert fake_exec.calls == []
    assert not any(cmd[:2] == ["sshd", "-T"] for cmd in runner.planned)
    assert not any(cmd[:2] == ["/usr/bin/getent", "passwd"] for cmd in runner.planned)
    assert [cmd for cmd in runner.planned if cmd[0] == "systemctl"] == [
        ["systemctl", "stop", "--job-mode=fail", "ssh.socket"],
        ["systemctl", "disable", "ssh.socket"],
        ["systemctl", "restart", "--job-mode=fail", "ssh.service"],
    ]


def test_hardening_creates_missing_privsep_dir(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Socket-activated ssh.service never ran, so /run/sshd is missing and
    sshd -t refuses the config before lhm can gate on it."""
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    assert not ssh.PRIVSEP_DIR.exists()
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("sshd -t", 0, "", ""),
            ("systemctl reload --job-mode=fail ssh.service", 0, "", ""),
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    ssh.apply_hardening(home_runner(home, fake_exec), port=22345, allow_users=["robin"])
    assert ssh.SSHD_DROPIN.is_file()
    assert ssh.PRIVSEP_DIR.is_dir()
    assert ssh.PRIVSEP_DIR.stat().st_mode & 0o777 == 0o755
    order = [" ".join(call) for call in fake_exec.calls]
    assert order.index("sshd -t") > -1  # the gate still ran


def test_ensure_privsep_dir_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", tmp_path / "run" / "sshd")
    assert ssh.ensure_privsep_dir() is True
    assert ssh.ensure_privsep_dir() is True
    assert ssh.PRIVSEP_DIR.is_dir()


@pytest.mark.parametrize("unsafe", ["symlink", "file", "owner", "writable"])
def test_ensure_privsep_dir_refuses_unsafe_leaves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    path = tmp_path / "sshd"
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    if unsafe == "symlink":
        path.symlink_to(other, target_is_directory=True)
    elif unsafe == "file":
        path.touch(mode=0o600)
    else:
        path.mkdir(mode=0o700)
        if unsafe == "owner":
            uid = os.geteuid()
            monkeypatch.setattr(os, "geteuid", lambda: uid + 1)
        else:
            path.chmod(0o777)
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", path)
    before = path.lstat().st_mode
    assert not ssh.ensure_privsep_dir()
    assert path.lstat().st_mode == before and stat.S_IMODE(other.stat().st_mode) == 0o700


@pytest.mark.parametrize(("dir_mode", "keys_mode"), [(0o755, 0o600), (0o700, 0o644)])
def test_ssh_user_reports_mode_only_change(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    dir_mode: int, keys_mode: int,
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    keys = home / "robin" / ".ssh" / "authorized_keys"
    keys.parent.chmod(dir_mode)
    keys.chmod(keys_mode)
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    results = ssh.apply_user(home_runner(home, fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    assert names[f"install {keys}"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert keys.read_text(encoding="utf-8") == PUBKEY + "\n"
    assert fake_exec.calls == []


def test_rollback_delete_prints_red_minus(home: Path) -> None:
    import io

    ssh.SSHD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    ssh.SSHD_DROPIN.write_text("Port 22345\n", encoding="utf-8")
    stream = io.StringIO()
    colors.configure("always")
    colors.set_output(stream)
    try:
        assert ssh._rollback_dropin(None, b"Port 22345\n", None).detail == "removed the new drop-in"
    finally:
        colors.set_output(None)
    assert stream.getvalue() == f"\033[31m- {ssh.SSHD_DROPIN}\033[0m\n"
    assert not ssh.SSHD_DROPIN.exists()


SSHD_T_ALLOW_OTHER = SSHD_T_OK + "allowusers bob\n"


def test_effective_problems_flags_allowusers_missing_admin() -> None:
    config = {
        "port": "22345",
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "allowusers": "bob carol",
    }
    problems = ssh._effective_problems(config, 22345, ["robin", "bob"])
    assert len(problems) == 1
    assert "allowusers missing robin" in problems[0]


def test_effective_problems_accepts_allowusers_superset() -> None:
    config = {
        "port": "22345",
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "allowusers": "robin bob",
    }
    assert ssh._effective_problems(config, 22345, ["robin"]) == []


def test_effective_problems_ignores_empty_allowusers() -> None:
    config = {
        "port": "22345",
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "allowusers": "",
    }
    assert ssh._effective_problems(config, 22345, ["robin"]) == []


def test_hardening_allowusers_gate_rolls_back_and_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier drop-in's AllowUsers wins: the admin would be locked out."""
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ("sshd -t", 0, "", ""),
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
            ("sshd -T", 0, SSHD_T_ALLOW_OTHER, ""),
        ]
    )
    results = ssh.apply_hardening(home_runner(home, fake_exec), port=22345, allow_users=["robin"])
    gate = next(r for r in results if r.name == "sshd -T effective")
    assert gate.status is Status.FAIL
    assert "allowusers missing robin" in gate.detail
    assert not ssh.SSHD_DROPIN.exists()
    order = [" ".join(call) for call in fake_exec.calls]
    assert fake_exec.calls.count(SSH_SERVICE_RELOAD) == 1
    assert not any(call.startswith("systemctl restart") for call in order)


class SocketRecoveryExec:
    """An active socket and a conversion that fails restart or listener verification."""

    def __init__(
        self,
        *,
        socket_reenables: bool = True,
        enabled_state: tuple[int, str] = (0, "enabled"),
        service_state: tuple[int, str] = (1, "disabled"),
        socket_unit: str = "ssh.socket",
        service_unit: str = "ssh.service",
        service_alias: bool = False,
        restart_failure: str | None = "failed",
        initial_listeners: tuple[int, str] | None = None,
        initial_socket_listen: str = "0.0.0.0:22 (Stream)\n",
        restored_socket_listen: str = "0.0.0.0:22 (Stream)\n",
        restored_listeners: str = SS_TLN_OLD_PORT,
        migrated_listeners: tuple[int, str] = (0, SS_TLN_OLD_PORT),
        enable_is_noop: bool = False,
        stop_rc: int = 0,
        reload_rc: int = 0,
        pending_after_stop: bool = False,
        socket_start_pending: bool = False,
        cached_listen: str | None = None,
        racing_stop_job: bool = False,
    ) -> None:
        self.calls: list[list[str]] = []
        self.socket_reenables = socket_reenables
        self.enabled_state = enabled_state
        self.service_state = service_state
        self.service_persistent = service_state == (0, "enabled")
        self.service_runtime = service_state == (0, "enabled-runtime")
        self.socket_unit = socket_unit
        self.service_unit = service_unit
        self.service_alias = service_alias
        self.restart_failure = restart_failure
        self.initial_listeners = initial_listeners
        self.initial_socket_listen = initial_socket_listen
        self.restored_socket_listen = restored_socket_listen
        self.restored_listeners = restored_listeners
        self.migrated_listeners = migrated_listeners
        self.enable_is_noop = enable_is_noop
        self.stop_rc = stop_rc
        self.reload_rc = reload_rc
        self.pending_after_stop = pending_after_stop
        self.socket_start_pending = socket_start_pending
        self.cached_listen = cached_listen
        self.racing_stop_job = racing_stop_job
        self.socket_active = True
        self.service_active = False
        self.restoring = False
        self.pending_restart = False
        self.pending_service_stop = False
        self.pending_socket = False

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd == ["sshd", "-t"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, SSHD_T_OK + "allowusers robin\n", "")
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            return subprocess.CompletedProcess(cmd, 0, ROBIN_ADMIN_CONFIG, "")
        if cmd[:2] == ["systemctl", "is-active"] and cmd[-1] in {"ssh.socket", self.socket_unit}:
            if self.socket_active:
                return subprocess.CompletedProcess(cmd, 0, "active\n", "")
            return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
        if cmd == ["systemctl", "is-active", self.service_unit]:
            rc, state = (0, "active") if self.service_active else (3, "inactive")
            return subprocess.CompletedProcess(cmd, rc, state + "\n", "")
        if cmd[:2] == ["systemctl", "list-jobs"]:
            assert timeout > 0
            assert cmd[-2:] == [self.socket_unit, self.service_unit]
            jobs = f"1 {self.service_unit} restart running\n" if self.pending_restart else ""
            if self.pending_service_stop:
                jobs += f"3 {self.service_unit} stop waiting\n"
            if self.pending_socket:
                jobs += f"2 {self.socket_unit} start waiting\n"
            return subprocess.CompletedProcess(cmd, 0, jobs, "")
        if cmd == ["systemctl", "is-enabled", self.socket_unit]:
            rc, state = self.enabled_state
            return subprocess.CompletedProcess(cmd, rc, state + "\n", "")
        if cmd == ["systemctl", "show", "--property=Triggers", "--value", self.socket_unit]:
            unit = "ssh.service" if self.service_alias else self.service_unit
            return subprocess.CompletedProcess(cmd, 0, unit + "\n", "")
        if cmd[:4] == ["systemctl", "show", "--property=Id", "--property=LoadState"]:
            if cmd[-1] in {"ssh.socket", self.socket_unit}:
                return subprocess.CompletedProcess(
                    cmd, 0, f"Id={self.socket_unit}\nLoadState=loaded\n", ""
                )
            loaded = cmd[-1] == self.service_unit or self.service_alias
            unit = self.service_unit if loaded else cmd[-1]
            state = "loaded" if loaded else "not-found"
            return subprocess.CompletedProcess(cmd, 0, f"Id={unit}\nLoadState={state}\n", "")
        if cmd == ["systemctl", "is-enabled", self.service_unit]:
            rc, state = self.service_state
            if self.service_persistent:
                rc, state = 0, "enabled"
            elif self.service_runtime:
                rc, state = 0, "enabled-runtime"
            elif state in {"enabled", "enabled-runtime"}:
                rc, state = 1, "disabled"
            return subprocess.CompletedProcess(cmd, rc, state + "\n", "")
        if cmd == ["systemctl", "show", "--property=Listen", "--value", self.socket_unit]:
            listen = self.restored_socket_listen if self.restoring else self.initial_socket_listen
            if not self.socket_active and not self.restoring and self.cached_listen is not None:
                listen = self.cached_listen
            return subprocess.CompletedProcess(cmd, 0, listen, "")
        if cmd == [
            "systemctl",
            "show",
            "--property=BindToDevice",
            "--property=BindIPv6Only",
            self.socket_unit,
        ]:
            output = "BindToDevice=\nBindIPv6Only=ipv6-only\n"
            return subprocess.CompletedProcess(cmd, 0, output, "")
        if cmd[0] == "systemctl" and cmd[1] in {"disable", "stop"} and cmd[-1] == self.socket_unit:
            implicit_stop = cmd[1] == "disable" and "--now" in cmd
            if cmd[1] == "disable":
                self.enabled_state = (1, "disabled")
                if not implicit_stop:
                    return subprocess.CompletedProcess(cmd, 0, "", "")
            if self.pending_socket and "--job-mode=fail" in cmd:
                if implicit_stop:
                    # Ubuntu Noble forwards the mode but ignores the stop's exit status.
                    return subprocess.CompletedProcess(cmd, 0, "", "conflicting job")
                return subprocess.CompletedProcess(cmd, 1, "", "conflicting job")
            self.pending_socket = False
            self.socket_active = False
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if (
            cmd[0] == "systemctl"
            and cmd[1] in {"enable", "disable"}
            and cmd[-1] == self.service_unit
        ):
            if not self.enable_is_noop:
                if "--runtime" in cmd:
                    self.service_runtime = cmd[1] == "enable"
                else:
                    self.service_persistent = cmd[1] == "enable"
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["systemctl", "restart"]:
            if cmd[-1] != self.service_unit:
                return subprocess.CompletedProcess(cmd, 5, "", "Unit not found.")
            if self.pending_service_stop and "--job-mode=fail" in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "conflicting job")
            self.pending_service_stop = False
            if self.restart_failure in {"timeout", "interrupt"}:
                self.pending_restart = True
                if self.restart_failure == "interrupt":
                    raise KeyboardInterrupt
                return subprocess.CompletedProcess(cmd, 124, "", "timed out")
            self.service_active = self.restart_failure is None
            return subprocess.CompletedProcess(cmd, int(not self.service_active), "", "")
        if cmd[:2] == ["systemctl", "stop"] and cmd[-1] == self.service_unit:
            if self.racing_stop_job:
                self.pending_restart = True
            if self.pending_restart and "--job-mode=fail" in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "conflicting job")
            self.pending_restart = self.pending_after_stop
            self.service_active = False
            return subprocess.CompletedProcess(cmd, self.stop_rc, "", "")
        if cmd == ["systemctl", "daemon-reload"]:
            self.restoring = self.reload_rc == 0
            return subprocess.CompletedProcess(cmd, self.reload_rc, "", "")
        if cmd[:3] == ["systemctl", "enable", "--no-reload"] and cmd[-1] == self.socket_unit:
            self.enabled_state = (0, "enabled-runtime" if "--runtime" in cmd else "enabled")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["systemctl", "start", "--job-mode=fail", self.socket_unit]:
            assert not self.pending_restart and not self.service_active
            self.pending_socket = self.socket_start_pending
            if self.socket_reenables:
                self.socket_active = True
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "Failed to start unit")
        if cmd == ["systemctl", "start", "--job-mode=fail", self.service_unit]:
            assert not self.pending_socket and not self.socket_active and not self.pending_restart
            self.service_active = True
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["ss", "-tlnp"]:
            if self.socket_active and not self.restoring and self.initial_listeners is not None:
                rc, stdout = self.initial_listeners
                return subprocess.CompletedProcess(cmd, rc, stdout, "")
            if self.socket_active:
                return subprocess.CompletedProcess(
                    cmd, 0, self.restored_listeners.replace('"sshd"', '"systemd"'), ""
                )
            rc, stdout = self.migrated_listeners
            return subprocess.CompletedProcess(cmd, rc, stdout, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.mark.parametrize("race", ["stop", "enable", "restart"])
def test_hardening_does_not_replace_job_racing_socket_conversion(
    home: Path, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    socket = SocketRecoveryExec(
        enabled_state=(0, "enabled-runtime"),
        restart_failure=None,
        migrated_listeners=(0, SS_TLN_OK),
    )

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if race == "stop" and cmd[-1] == socket.socket_unit:
            if cmd[:2] == ["systemctl", "stop"] or "--now" in cmd:
                socket.pending_socket = True
        if cmd[-1] == socket.service_unit and cmd[:2] == ["systemctl", race]:
            socket.pending_service_stop = True
        return socket(cmd, timeout)

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    failed = steps["reload sshd" if race == "restart" else "ssh-hardening"]
    assert failed.status is Status.FAIL
    assert ("pending jobs" if race == "enable" else "conflicting job") in failed.detail
    assert not any(cmd[1] in {"start", "cancel", "daemon-reload"} for cmd in socket.calls)
    assert any(cmd[1] == "restart" for cmd in socket.calls) is (race == "restart")
    assert socket.pending_socket is (race == "stop")
    assert socket.pending_service_stop is (race != "stop")
    assert socket.socket_active is (race == "stop")
    if race == "stop":
        assert not any(cmd[1] in {"disable", "enable"} for cmd in socket.calls)
    assert socket.enabled_state == (0, "enabled-runtime") and not socket.service_runtime
    assert not ssh.SSHD_DROPIN.exists()


@pytest.mark.parametrize("reactivated_at", ["stop", "disable"])
def test_hardening_refuses_restart_when_socket_is_still_active(
    home: Path, monkeypatch: pytest.MonkeyPatch, reactivated_at: str
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    socket = SocketRecoveryExec(restart_failure=None, migrated_listeners=(0, SS_TLN_OK))

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = socket(cmd, timeout)
        if cmd[-1] == socket.socket_unit and (cmd[1] == reactivated_at or "--now" in cmd):
            assert result.returncode == 0
            # An external start completed before our state probe, leaving no pending job.
            socket.socket_active = True
        return result

    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["ssh-hardening"].status is Status.FAIL
    assert "inactive" in steps["ssh-hardening"].detail
    assert steps["restore ssh.socket"].status is Status.CHANGED
    assert not any(cmd[1] == "restart" for cmd in socket.calls)
    assert any(cmd[1] == "disable" for cmd in socket.calls) is (reactivated_at == "disable")
    assert socket.socket_active and socket.enabled_state == (0, "enabled")
    assert not socket.service_active and not socket.service_persistent
    assert not ssh.SSHD_DROPIN.exists()


@pytest.mark.parametrize("failure", ["timeout", "interrupt"])
def test_hardening_recovers_partial_socket_disablement(
    home: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    socket = SocketRecoveryExec(enabled_state=(0, "enabled-runtime"), restart_failure=None)

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = socket(cmd, timeout)
        if cmd[:2] == ["systemctl", "disable"] and cmd[-1] == socket.socket_unit:
            assert socket.enabled_state == (1, "disabled") and not socket.socket_active
            if failure == "interrupt":
                raise KeyboardInterrupt
            return subprocess.CompletedProcess(cmd, 124, "", "timed out")
        return result

    runner = home_runner(home, execute)
    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            ssh.apply_hardening(runner)
    else:
        steps = {r.name: r for r in ssh.apply_hardening(runner)}
        assert steps["ssh-hardening"].status is Status.FAIL
        assert steps["restore ssh.socket"].status is Status.CHANGED
    assert not any(cmd[1] == "restart" for cmd in socket.calls)
    assert socket.socket_active and socket.enabled_state == (0, "enabled-runtime")
    assert not socket.service_active and not socket.service_runtime
    assert not ssh.SSHD_DROPIN.exists()


@pytest.mark.parametrize(
    "state",
    [(0, "enabled"), (0, "enabled-runtime"), (1, "disabled"), (0, "static")],
)
def test_hardening_restores_socket_after_restart_failure(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: tuple[int, str]
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    exec_fn = SocketRecoveryExec(enabled_state=state)
    results = ssh.apply_hardening(home_runner(home, exec_fn), port=22345, allow_users=["robin"])
    order = [" ".join(call) for call in exec_fn.calls]
    expected = ["systemctl stop --job-mode=fail ssh.socket"]
    scope = " --runtime" if state[1] == "enabled-runtime" else ""
    if state[1] in {"enabled", "enabled-runtime"}:
        expected.append(f"systemctl disable{scope} ssh.socket")
        expected.append(f"systemctl enable{scope} ssh.service")
    expected.extend(
        [
            "systemctl restart --job-mode=fail ssh.service",
            "systemctl daemon-reload",
            "systemctl start --job-mode=fail ssh.socket",
        ]
    )
    if state[1] in {"enabled", "enabled-runtime"}:
        expected.extend(
            [
                f"systemctl enable --no-reload{scope} ssh.socket",
                f"systemctl disable --no-reload{scope} ssh.service",
            ]
        )
    assert [
        cmd
        for cmd in order
        if cmd.split()[1] in {"stop", "disable", "enable", "start", "restart", "daemon-reload"}
    ] == expected
    assert exec_fn.enabled_state == state
    assert not exec_fn.service_persistent and not exec_fn.service_runtime
    steps = {r.name: r for r in results}
    assert steps["restore ssh.socket"].status is Status.CHANGED
    assert "22" in steps["restore ssh.socket"].detail
    assert steps["reload sshd"].status is Status.FAIL
    assert "removed the new drop-in" in steps["restore ssh drop-in"].detail
    assert not ssh.SSHD_DROPIN.exists()  # drop-in rolled back


def test_hardening_recovers_socket_after_final_admin_probe_failure(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    old = "Port 22\n"
    ssh.SSHD_DROPIN.write_text(old, encoding="utf-8")
    socket = SocketRecoveryExec(restart_failure=None, migrated_listeners=(0, SS_TLN_OK))
    probes = 0

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal probes
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            probes += 1
            if probes == 2:
                assert socket.service_active and not socket.socket_active
                return subprocess.CompletedProcess(cmd, 124, "", "timed out")
        if cmd == ["systemctl", "start", "--job-mode=fail", "ssh.socket"]:
            assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old
        return socket(cmd, timeout)

    steps = {step.name: step for step in ssh.apply_hardening(home_runner(home, execute))}
    assert probes == 2
    assert steps["sshd -T admin keys"].status is Status.OK
    assert steps["reload sshd"].status is Status.CHANGED
    assert steps["verify"].status is Status.FAIL
    assert "probe failed (rc=124)" in steps["verify"].detail
    assert steps["restore ssh drop-in"].status is Status.CHANGED
    assert steps["restore ssh.socket"].status is Status.CHANGED
    assert socket.socket_active and not socket.service_active
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == old


def test_hardening_preserves_only_live_daemon_when_disk_and_socket_recovery_are_unsafe(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")
    socket = SocketRecoveryExec(
        restart_failure=None,
        migrated_listeners=(0, SS_TLN_OK),
        cached_listen="[::]:22100 (Stream)\n",
    )

    def fail_rollback(path: Path, *, backup: Path) -> Path:
        raise OSError("rollback failed")

    monkeypatch.setattr(ssh, "rollback_file", fail_rollback)
    probes = 0

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal probes
        if cmd == ["sshd", "-T", "-C", ROBIN_LOOPBACK]:
            probes += 1
            if probes == 2:
                return subprocess.CompletedProcess(cmd, 124, "", "timed out")
        return socket(cmd, timeout)

    steps = {step.name: step for step in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["verify"].status is Status.FAIL
    assert steps["restore ssh drop-in"].status is Status.FAIL
    assert steps["restore ssh.socket"].status is Status.FAIL
    assert socket.service_active and not socket.socket_active
    assert [cmd for cmd in socket.calls if cmd[1] in {"stop", "start", "daemon-reload"}] == [
        ["systemctl", "stop", "--job-mode=fail", "ssh.socket"]
    ]
    assert socket.enabled_state == (0, "enabled") and not socket.service_persistent


@pytest.mark.parametrize("pending", ["observed", "racing", "unknown"])
def test_hardening_does_not_replace_unowned_recovery_job(
    home: Path, monkeypatch: pytest.MonkeyPatch, pending: str
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    socket = SocketRecoveryExec(
        restart_failure=None, migrated_listeners=(0, ""), racing_stop_job=pending == "racing"
    )

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["systemctl", "list-jobs"] and socket.service_active:
            if pending == "observed":
                socket.pending_restart = True
            elif pending == "unknown":
                return subprocess.CompletedProcess(cmd, 124, "", "timed out")
        return socket(cmd, timeout)

    steps = {step.name: step for step in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["verify"].status is Status.FAIL
    assert steps["restore ssh.socket"].status is Status.FAIL
    assert "jobs pending or unverifiable" in steps["restore ssh.socket"].detail
    assert socket.service_active and not socket.socket_active
    assert [cmd for cmd in socket.calls if cmd[1] in {"stop", "start", "cancel"}] == [
        ["systemctl", "stop", "--job-mode=fail", "ssh.socket"]
    ] + (
        [["systemctl", "stop", "--job-mode=fail", "ssh.service"]] if pending == "racing" else []
    )
    assert socket.enabled_state == (0, "enabled") and not socket.service_persistent


def test_hardening_double_failure_prints_manual_recovery(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    seed_user(home, "robin")
    exec_fn = SocketRecoveryExec(socket_reenables=False)
    results = ssh.apply_hardening(home_runner(home, exec_fn), port=22345, allow_users=["robin"])
    order = [" ".join(call) for call in exec_fn.calls]
    assert "systemctl start --job-mode=fail ssh.service" in order
    steps = {r.name: r for r in results}
    assert steps["restore ssh.socket"].status is Status.FAIL
    assert steps["reload sshd"].status is Status.FAIL
    assert "fallback service start requested" in steps["restore ssh.socket"].detail
    assert "listening on the original endpoints" in steps["restore ssh.socket"].detail
    assert not ssh.SSHD_DROPIN.exists()
    err = capsys.readouterr().err
    assert "SSH may be DOWN" in err
    assert "systemctl enable --now ssh.socket" in err


@pytest.mark.parametrize(
    ("faults", "expected_start", "recovered"),
    [
        ({"stop_rc": 1}, "ssh.socket", True),
        ({"reload_rc": 1}, "ssh.socket", True),
        ({"reload_rc": 1, "cached_listen": "[::]:22100 (Stream)\n"}, None, False),
        ({"reload_rc": 1, "cached_listen": "127.0.0.1:22 (Stream)\n"}, None, False),
        ({"stop_rc": 1, "pending_after_stop": True}, None, False),
        ({"socket_reenables": False, "socket_start_pending": True}, "ssh.socket", False),
    ],
)
def test_hardening_socket_recovery_uses_observed_state_after_failures(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    faults: dict[str, object],
    expected_start: str | None,
    recovered: bool,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(
        restart_failure=None, migrated_listeners=(0, SS_TLN_OLD_PORT), **faults
    )
    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["verify"].status is Status.FAIL
    assert steps["restore ssh.socket"].status is (Status.CHANGED if recovered else Status.FAIL)
    calls = execute.calls
    assert all("--job-mode=fail" in cmd for cmd in calls if cmd[1] in {"stop", "start"})
    assert [cmd[-1] for cmd in calls if cmd[:2] == ["systemctl", "start"]] == (
        [expected_start] if expected_start else []
    )
    if faults.get("reload_rc"):
        reload_cmd = calls.index(["systemctl", "daemon-reload"])
        assert reload_cmd < calls.index(
            ["systemctl", "show", "--property=Listen", "--value", "ssh.socket"], reload_cmd
        )
    assert execute.enabled_state == (0, "enabled") and not execute.service_persistent


@pytest.mark.parametrize("cached_safe", [False, True])
def test_hardening_checks_socket_despite_dropin_rollback_exception(
    home: Path, monkeypatch: pytest.MonkeyPatch, cached_safe: bool
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")

    def fail_rollback(path: Path, *, backup: Path) -> Path:
        raise OSError("rollback failed")

    monkeypatch.setattr(ssh, "rollback_file", fail_rollback)
    listen = None if cached_safe else "[::]:22100 (Stream)\n"
    execute = SocketRecoveryExec(cached_listen=listen)
    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["reload sshd"].status is Status.FAIL
    assert steps["restore ssh drop-in"].status is Status.FAIL
    assert steps["restore ssh.socket"].status is (Status.CHANGED if cached_safe else Status.FAIL)
    assert ["systemctl", "is-active", "ssh.service"] in execute.calls
    assert ["systemctl", "daemon-reload"] not in execute.calls
    assert [cmd[-1] for cmd in execute.calls if cmd[:2] == ["systemctl", "start"]] == (
        ["ssh.socket"] if cached_safe else []
    )
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == ssh.desired_conf(22345, ["robin"])


def test_hardening_checks_jobs_on_the_canonical_socket_unit(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(
        socket_unit="sshd.socket", socket_reenables=False, socket_start_pending=True
    )
    steps = {r.name: r for r in ssh.apply_hardening(home_runner(home, execute))}
    assert steps["restore ssh.socket"].status is Status.FAIL
    assert "jobs pending" in steps["restore ssh.socket"].detail
    assert [cmd[-1] for cmd in execute.calls if cmd[:2] == ["systemctl", "start"]] == [
        "sshd.socket"
    ]


@pytest.mark.parametrize(
    ("failure", "socket_state", "service_state", "service_alias"),
    [
        ("timeout", "enabled", (0, "enabled-runtime"), True),
        ("interrupt", "enabled-runtime", (1, "disabled"), False),
        (None, "enabled", (0, "enabled"), False),
    ],
)
def test_hardening_recovers_boot_scope_without_replacing_pending_restart(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
    socket_state: str,
    service_state: tuple[int, str],
    service_alias: bool,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(
        enabled_state=(0, socket_state),
        service_state=service_state,
        service_unit="sshd.service",
        service_alias=service_alias,
        restart_failure=failure,
        migrated_listeners=(127, ""),
    )
    runner = home_runner(home, execute)
    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            ssh.apply_hardening(runner)
    else:
        results = ssh.apply_hardening(runner)
        steps = {step.name: step for step in results}
        failed_step = "reload sshd" if failure == "timeout" else "verify"
        assert steps[failed_step].status is Status.FAIL
        assert steps["restore ssh.socket"].status is (Status.FAIL if failure else Status.CHANGED)
    order = [" ".join(cmd) for cmd in execute.calls]
    assert order.index("systemctl is-enabled sshd.service") < order.index("sshd -t")
    assert [cmd for cmd in order if cmd.startswith("systemctl restart ")] == [
        "systemctl restart --job-mode=fail sshd.service"
    ]
    runtime_prefixes = ("systemctl stop ", "systemctl cancel", "systemctl start ")
    runtime = [cmd for cmd in order if cmd.startswith(runtime_prefixes)]
    assert runtime == ["systemctl stop --job-mode=fail ssh.socket"] + (
        [
            "systemctl stop --job-mode=fail sshd.service",
            "systemctl start --job-mode=fail ssh.socket",
        ]
        if failure is None
        else []
    )
    assert execute.pending_restart is (failure is not None)
    assert execute.socket_active is (failure is None)
    assert execute.enabled_state == (0, socket_state)
    assert execute.service_persistent is (service_state == (0, "enabled"))
    assert execute.service_runtime is (service_state == (0, "enabled-runtime"))
    assert not ssh.SSHD_DROPIN.exists()


@pytest.mark.parametrize("state", [(0, "alias"), (1, "masked"), (0, "static")])
def test_hardening_refuses_service_without_known_boot_enablement(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: tuple[int, str]
) -> None:
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.parent.rmdir()
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(service_state=state)
    results = ssh.apply_hardening(home_runner(home, execute))
    assert results[0].status is Status.FAIL
    assert "ssh.service" in results[0].detail
    assert not ssh.SSHD_DROPIN.parent.exists()
    assert not ssh.PRIVSEP_DIR.exists()
    assert not any(cmd[1] in {"enable", "disable", "stop", "restart"} for cmd in execute.calls)


def test_hardening_does_not_claim_migration_when_service_enable_has_no_effect(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(
        enable_is_noop=True, restart_failure=None, migrated_listeners=(0, SS_TLN_OK)
    )
    results = ssh.apply_hardening(home_runner(home, execute))
    assert any(step.status is Status.FAIL and "enablement" in step.detail for step in results)
    assert results[-1].name == "restore ssh.socket"
    assert results[-1].status is Status.CHANGED
    assert execute.enabled_state == (0, "enabled") and execute.socket_active
    assert not ssh.SSHD_DROPIN.exists()


@pytest.mark.parametrize("state", [(1, ""), (1, "masked"), (0, "generated"), (124, "enabled")])
def test_hardening_refuses_unknown_socket_enablement_before_mutating(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: tuple[int, str]
) -> None:
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.parent.rmdir()
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(enabled_state=state)
    results = ssh.apply_hardening(home_runner(home, execute))
    assert results[0].status is Status.FAIL
    assert "cannot determine ssh.socket enablement" in results[0].detail
    assert not ssh.SSHD_DROPIN.parent.exists()
    assert not ssh.PRIVSEP_DIR.exists()
    assert execute.calls == [
        ["systemctl", "is-active", "ssh.socket"],
        ["systemctl", "show", "--property=Id", "--property=LoadState", "ssh.socket"],
        ["systemctl", "is-enabled", "ssh.socket"],
    ]


@pytest.mark.parametrize("initial_listeners", [(127, ""), (0, "")])
def test_hardening_refuses_unavailable_or_empty_original_ports(
    home: Path, monkeypatch: pytest.MonkeyPatch, initial_listeners: tuple[int, str]
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(initial_listeners=initial_listeners)
    results = ssh.apply_hardening(home_runner(home, execute))
    assert results[0].status is Status.FAIL
    assert "current SSH listening ports" in results[0].detail
    assert not ssh.SSHD_DROPIN.exists()
    assert not ssh.PRIVSEP_DIR.exists()
    assert not any(
        cmd[1] in {"-t", "enable", "disable", "stop", "restart"} for cmd in execute.calls
    )


@pytest.mark.parametrize("local", ["0.0.0.0:22", "127.0.0.1:22"])
def test_hardening_does_not_claim_recovery_without_all_original_endpoints(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    local: str,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    execute = SocketRecoveryExec(
        initial_listeners=(0, (SS_TLN_OLD_PORT + SS_TLN_OK).replace('"sshd"', '"systemd"')),
        initial_socket_listen="0.0.0.0:22 (Stream)\n0.0.0.0:22345 (Stream)\n",
        restored_socket_listen="0.0.0.0:22 (Stream)\n0.0.0.0:22345 (Stream)\n",
        restored_listeners=(
            SS_TLN_OLD_PORT
            if local == "0.0.0.0:22"
            else SS_TLN_OLD_PORT.replace("0.0.0.0:22", local) + SS_TLN_OK
        ),
    )
    results = ssh.apply_hardening(home_runner(home, execute))
    assert results[-1].name == "restore ssh.socket"
    assert results[-1].status is Status.FAIL
    assert "previous listener not verified" in results[-1].detail
    assert "from the console" in capsys.readouterr().err
    assert ["systemctl", "start", "--job-mode=fail", "ssh.service"] not in execute.calls


def test_hardening_locks_through_verification_and_stops_only_new_daemon_on_rollback(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    exec_fn = SocketRecoveryExec(service_unit="sshd.service", restart_failure=None)

    def confirm(plan: list[str]) -> bool:
        with locked_target(ssh.SSHD_DROPIN):
            return True

    def notify(kind: str, path: Path, **kwargs: object) -> None:
        if kind == "deleted":
            raise BrokenPipeError()

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        with pytest.raises(BlockingIOError, match="managed target is locked"):
            with locked_target(ssh.SSHD_DROPIN):
                pytest.fail("SSH target was unlocked")
        if cmd == ["systemctl", "daemon-reload"]:
            assert not ssh.SSHD_DROPIN.exists()
        return exec_fn(cmd, timeout)

    monkeypatch.setattr(ssh, "confirm_once", confirm)
    monkeypatch.setattr(colors, "file_change", notify)
    results = ssh.apply_hardening(home_runner(home, execute))
    steps = {step.name: step for step in results}
    assert steps["verify"].status is Status.FAIL
    assert steps["restore ssh.socket"].status is Status.CHANGED
    order = [" ".join(call) for call in exec_fn.calls]
    stop = "systemctl stop --job-mode=fail sshd.service"
    assert [call for call in order if call.startswith("systemctl stop ")] == [
        "systemctl stop --job-mode=fail ssh.socket",
        stop,
    ]
    assert order.index("systemctl restart --job-mode=fail sshd.service") < order.index(stop)
    assert order.index(stop) < order.index("systemctl start --job-mode=fail ssh.socket")
    with locked_target(ssh.SSHD_DROPIN):
        assert not ssh.SSHD_DROPIN.exists()


def test_hardening_does_not_stop_daemon_when_socket_is_active_again(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    exec_fn = SocketRecoveryExec(restart_failure=None)

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = exec_fn(cmd, timeout)
        if cmd == ["systemctl", "restart", "--job-mode=fail", "ssh.service"]:
            exec_fn.socket_active = True
        return result

    results = ssh.apply_hardening(home_runner(home, execute))
    assert next(step for step in results if step.name == "verify").status is Status.FAIL
    assert results[-1].name == "restore ssh.socket"
    assert results[-1].status is Status.CHANGED
    assert [cmd for cmd in exec_fn.calls if cmd[:2] == ["systemctl", "stop"]] == [
        ["systemctl", "stop", "--job-mode=fail", "ssh.socket"]
    ]


@pytest.mark.parametrize("identical", [False, True])
def test_hardening_refuses_contended_config(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, identical: bool
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    if identical:
        ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, ["robin"]), encoding="utf-8")
    with locked_target(ssh.SSHD_DROPIN):
        results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert "managed target is locked" in results[0].detail
    assert ssh.SSHD_DROPIN.exists() is identical
    assert fake_exec.calls == []


def test_hardening_refuses_identical_symlink(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    target = home / "ssh.conf"
    target.write_text(ssh.desired_conf(22345, ["robin"]), encoding="utf-8")
    ssh.SSHD_DROPIN.symlink_to(target)

    read_bytes = Path.read_bytes

    def read(path: Path) -> bytes:
        assert path != ssh.SSHD_DROPIN
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert "symlink" in results[0].detail
    assert ssh.SSHD_DROPIN.is_symlink()
    assert fake_exec.calls == []


def test_hardening_refuses_stale_identical_snapshot_without_verifying(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.write_text(ssh.desired_conf(22345, ["robin"]), encoding="utf-8")
    concurrent_config = "Port 22\n"

    @contextmanager
    def concurrent_write_then_lock(path: Path) -> Iterator[None]:
        with locked_target(path):
            path.write_text(concurrent_config, encoding="utf-8")
        with locked_target(path):
            yield

    monkeypatch.setattr(ssh, "locked_target", concurrent_write_then_lock)
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == concurrent_config
    assert fake_exec.calls == []


def test_hardening_refuses_stale_config_after_confirmation(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")
    concurrent_config = ssh.desired_conf(22346, ["robin"])

    def confirm(plan: list[str]) -> bool:
        with locked_target(ssh.SSHD_DROPIN):
            ssh.SSHD_DROPIN.write_text(concurrent_config, encoding="utf-8")
        return True

    monkeypatch.setattr(ssh, "confirm_once", confirm)
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert "changed during confirmation" in results[0].detail
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == concurrent_config
    assert not ssh.PRIVSEP_DIR.exists()
    assert fake_exec.calls == []


def test_hardening_does_not_recover_config_changed_before_write(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    candidate = ssh.desired_conf(22345, ["robin"])
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["ss", "-tlnp"]:
            ssh.SSHD_DROPIN.write_text(candidate, encoding="utf-8")
        return fake_exec(cmd, timeout)

    results = ssh.apply_hardening(home_runner(home, execute))
    assert len(results) == 1
    assert results[0].status is Status.FAIL and "changed before write" in results[0].detail
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == candidate
    assert fake_exec.calls == SSH_SERVICE_PREFLIGHT_CALLS


def test_hardening_never_writes_without_a_verified_watchdog(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])
    watchdog.arm_error = True
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert "not armed" in results[0].detail
    assert watchdog.arms == 1 and watchdog.pending is None
    assert not ssh.SSHD_DROPIN.exists() and not ssh.PRIVSEP_DIR.exists()
    assert fake_exec.calls == SSH_SERVICE_PREFLIGHT_CALLS


def test_hardening_requires_the_existing_dropin_lock_directory(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])
    ssh.SSHD_DROPIN.parent.rmdir()
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert "directory must already exist" in results[0].detail
    assert not ssh.SSHD_DROPIN.parent.exists() and not ssh.PRIVSEP_DIR.exists()
    assert watchdog.arms == 0


@pytest.fixture
def awaiting_watchdog(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    capsys: pytest.CaptureFixture[str],
    request: pytest.FixtureRequest,
) -> tuple[Runner, str]:
    seed_user(home, "robin")
    seed_user(home, "other")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    if getattr(request, "param", True):
        monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 41111 127.0.0.1 22345")
    monkeypatch.setenv("SUDO_USER", "robin")
    monkeypatch.setenv("SUDO_UID", str(KeyExec.uid))
    monkeypatch.setenv("SUDO_GID", str(KeyExec.gid))
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    write = ssh.write_dropin

    def write_after_notice(*args: Any, **kwargs: Any) -> str:
        pending = watchdog.pending
        assert pending is not None
        assert not ssh.SSHD_DROPIN.exists()
        early = capsys.readouterr()
        assert "60s until automatic rollback" in early.err
        assert f"lhm ssh-confirm {pending.id}" in early.err
        assert f"lhm ssh-confirm {pending.id}" not in early.out
        return write(*args, **kwargs)

    runner = home_runner(home, fake_exec)
    with monkeypatch.context() as context:
        context.setattr(ssh, "write_dropin", write_after_notice)
        results = ssh.apply_hardening(runner, allow_users=["robin"])
    assert results[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None and pending.phase == "awaiting-confirm"
    assert pending.data["freshness"] == [BOOT_ID, watchdog.cutoff_tick]
    assert any(
        f"lhm ssh-confirm {pending.id}" in result.detail
        and "60s until automatic rollback" in result.detail
        for result in results
    )
    assert watchdog.arms == 1 and watchdog.clears == 0
    return runner, pending.id


def test_watchdog_confirmation_only_commits_the_matching_transaction(
    awaiting_watchdog: tuple[Runner, str],
    watchdog: WatchdogFake,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, txid = awaiting_watchdog
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 42222 127.0.0.1 22345")
    dry = ssh.confirm_watchdog(Runner(dry_run=True), txid)
    assert dry[0].status is Status.FAIL
    assert "dry-run" in dry[0].detail
    assert ssh.confirm_watchdog(runner, "b" * 32)[0].status is Status.FAIL
    assert ssh.expire_watchdog("b" * 32) == 0
    assert watchdog.clears == 0
    assert ssh.confirm_watchdog(runner, txid)[-1].status is Status.CHANGED
    assert watchdog.freshness_checks == [(BOOT_ID, watchdog.cutoff_tick, "robin")]
    assert watchdog.pending is None and watchdog.clears == 1
    assert ssh.expire_watchdog(txid) == 0
    assert ssh.SSHD_DROPIN.read_text() == ssh.desired_conf(22345, ["robin"])
    assert ssh.apply_hardening(runner, allow_users=["robin"])[0].status is Status.SKIPPED
    assert watchdog.arms == 1


@pytest.mark.parametrize(
    ("case", "detail"),
    [
        ("original", "new SSH connection"),
        ("port", "new SSH connection"),
        ("multiple-spaces", "new SSH connection"),
        ("unauthorized", "original authorized"),
        ("edited", "changed after activation"),
        ("unbound", "not listening"),
        ("already-expired", "deadline reached"),
        ("expired", "deadline reached"),
    ],
)
def test_watchdog_confirmation_rejects_unverified_sessions_or_state(
    awaiting_watchdog: tuple[Runner, str],
    fake_exec: Any,
    watchdog: WatchdogFake,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    detail: str,
) -> None:
    runner, txid = awaiting_watchdog
    target = 22 if case == "port" else 22345
    source = 41111 if case == "original" else 42222
    separator = "  " if case == "multiple-spaces" else " "
    monkeypatch.setenv("SSH_CONNECTION", f"127.0.0.1{separator}{source} 127.0.0.1 {target}")
    if case == "unauthorized":
        monkeypatch.setenv("SUDO_USER", "other")
    if case == "edited":
        ssh.SSHD_DROPIN.write_text("Port 2200\n")
    if case == "unbound":
        fake_exec.responses.insert(
            0, ("ss -tlnp", 0, SS_TLN_OK.replace("0.0.0.0:22345", "192.0.2.2:22345"), "")
        )
    if case == "already-expired":
        assert watchdog.pending is not None
        watchdog.now = watchdog.pending.deadline
    if case == "expired":
        # Expire during the listener check, after successfully running the per-admin checks.
        def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
            if cmd == ["ss", "-tlnp"]:
                assert watchdog.pending is not None
                watchdog.now = watchdog.pending.deadline
            return fake_exec(cmd, timeout)

        runner = Runner(exec_fn=KeyExec(ssh.HOME_ROOT, execute))
    history = len(runner.history)
    results = ssh.confirm_watchdog(runner, txid)
    assert results[0].status is Status.FAIL and detail in results[0].detail
    assert watchdog.pending is not None and watchdog.clears == 0
    if case in {"already-expired", "multiple-spaces"}:
        assert len(runner.history) == history  # No NSS, sshd or listener probes.
        assert not watchdog.freshness_checks


@pytest.mark.parametrize("awaiting_watchdog", [False], indirect=True)
def test_watchdog_rejects_old_transport_even_if_original_ssh_connection_was_missing(
    awaiting_watchdog: tuple[Runner, str], watchdog: WatchdogFake, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, txid = awaiting_watchdog
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 42222 127.0.0.1 22345")
    watchdog.transport_tick = watchdog.cutoff_tick - 1
    results = ssh.confirm_watchdog(runner, txid)
    assert results[0].status is Status.FAIL and "predates" in results[0].detail
    assert watchdog.freshness_checks == [(BOOT_ID, watchdog.cutoff_tick, "robin")]
    assert watchdog.pending is not None and watchdog.clears == 0
    watchdog.transport_tick = watchdog.cutoff_tick + 1
    assert ssh.confirm_watchdog(runner, txid)[-1].status is Status.CHANGED
    assert watchdog.pending is None


@pytest.mark.parametrize("cutoff", [None, ["not-a-boot-id", 1000], [BOOT_ID, True]])
def test_watchdog_confirmation_requires_a_valid_stored_cutoff(
    awaiting_watchdog: tuple[Runner, str],
    watchdog: WatchdogFake,
    monkeypatch: pytest.MonkeyPatch,
    cutoff: object,
) -> None:
    runner, txid = awaiting_watchdog
    pending = watchdog.pending
    assert pending is not None
    data = pending.data
    if cutoff is None:
        del data["freshness"]
    else:
        data["freshness"] = cutoff
    watchdog.pending = ssh.ssh_watchdog.Pending(txid, pending.deadline, pending.phase, data)
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 42222 127.0.0.1 22345")
    results = ssh.confirm_watchdog(runner, txid)
    assert results[0].status is Status.FAIL and "cutoff" in results[0].detail
    assert watchdog.pending is not None and watchdog.clears == 0
    assert not watchdog.freshness_checks
    watchdog.now = pending.deadline
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    assert ssh.expire_watchdog(txid) == 0
    assert not ssh.SSHD_DROPIN.exists()


def test_pending_watchdog_blocks_live_hardening_even_if_identical(
    awaiting_watchdog: tuple[Runner, str],
    watchdog: WatchdogFake,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, txid = awaiting_watchdog
    with monkeypatch.context() as context:

        def no_prompt(_plan: list[str]) -> bool:
            pytest.fail("pending transaction must block before prompting")

        context.setattr(ssh, "confirm_once", no_prompt)
        for port in (22345, 2200):
            results = ssh.apply_hardening(runner, port=port, allow_users=["robin"])
            assert results[0].status is Status.FAIL and txid in results[0].detail
        planned = ssh.apply_hardening(Runner(dry_run=True), port=2200)
        assert all(step.status is Status.PLANNED for step in planned)
    assert watchdog.arms == 1 and watchdog.clears == 0


@pytest.mark.parametrize("corrupt", [False, True])
def test_inert_prepared_watchdog_can_be_replaced_but_a_corrupt_record_blocks(
    awaiting_watchdog: tuple[Runner, str],
    watchdog: WatchdogFake,
    monkeypatch: pytest.MonkeyPatch,
    corrupt: bool,
) -> None:
    runner, txid = awaiting_watchdog
    assert watchdog.prepared is not None
    ssh.SSHD_DROPIN.unlink()  # The interrupted arm never wrote its candidate.
    watchdog.pending = watchdog.prepared
    if corrupt:
        watchdog.update(watchdog.prepared, write_attempted=True)
        watchdog.now = watchdog.prepared.deadline
        monkeypatch.setattr(ssh, "Runner", lambda: runner)
        assert ssh.expire_watchdog(txid) == 1
    results = ssh.apply_hardening(runner, allow_users=["robin"])
    assert watchdog.pending is not None
    if corrupt:
        assert results[0].status is Status.FAIL
        assert watchdog.pending.id == txid and watchdog.clears == 0 and watchdog.arms == 1
        assert not ssh.SSHD_DROPIN.exists()
    else:
        assert results[-1].status is Status.OK
        assert watchdog.pending.id != txid and watchdog.clears == 1 and watchdog.arms == 2
        assert ssh.expire_watchdog(txid) == 0
        assert watchdog.pending is not None and ssh.SSHD_DROPIN.is_file()


class ProcessLost(BaseException):
    """Bypass in-process cleanup as when the foreground process is killed."""


@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize("original", [None, b"Port 22\r\n# local settings\r\n"])
def test_watchdog_recovers_a_crash_after_atomic_dropin_replace(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    original: bytes | None,
    active: bool,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    target = ssh.SSHD_DROPIN
    stale = target.with_suffix(".conf.bak")
    stale.write_bytes(b"unrelated backup")
    if original is not None:
        target.write_bytes(original)
        target.chmod(0o600)
    runner = home_runner(home, fake_exec)
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])
    replace = os.replace

    def replace_then_crash(src: str | Path, dst: str | Path) -> None:
        replace(src, dst)
        if dst == target:
            raise ProcessLost

    with monkeypatch.context() as context:
        context.setattr(os, "replace", replace_then_crash)
        with pytest.raises(ProcessLost):
            ssh.apply_hardening(runner)
    pending = watchdog.pending
    assert pending is not None and target.exists()
    assert pending.data["write_attempted"] is True and pending.data["action"] == "none"
    daemon_config = target.read_bytes()  # An independent restart picked up the candidate.
    if not active:
        ssh.PRIVSEP_DIR.rmdir()  # RuntimeDirectory was removed when the service stopped.
    action = "reload" if active else "start"
    runtime_actions: list[list[str]] = []
    validations: list[bytes | None] = []

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal active, daemon_config
        if cmd == ["sshd", "-t"]:
            assert stat.S_IMODE(ssh.PRIVSEP_DIR.stat().st_mode) == 0o755
            validations.append(target.read_bytes() if target.exists() else None)
        if cmd == ["systemctl", "is-active", "ssh.service"] and not active:
            return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
        if cmd[0] == "systemctl" and cmd[1] in {"start", "reload", "restart", "stop"}:
            assert validations == [original]
            runtime_actions.append(cmd)
            daemon_config = target.read_bytes() if target.exists() else None
            active = True
        if cmd == ["ss", "-tlnp"] and daemon_config != original:
            return subprocess.CompletedProcess(cmd, 0, SS_TLN_OK, "")
        return fake_exec(cmd, timeout)

    monkeypatch.setattr(ssh, "Runner", lambda: Runner(exec_fn=recover))
    assert ssh.expire_watchdog(pending.id) == 75  # timer ran before the deadline
    watchdog.now = pending.deadline
    with locked_target(target):
        assert ssh.expire_watchdog(pending.id) == 75
    assert target.exists() and watchdog.clears == 0
    assert ssh.expire_watchdog(pending.id) == 0
    if original is None:
        assert not target.exists()
    else:
        assert target.read_bytes() == original
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stale.read_bytes() == b"unrelated backup"
    assert watchdog.clears == 1 and watchdog.pending is None
    assert daemon_config == original
    assert runtime_actions == [["systemctl", action, "--job-mode=fail", "ssh.service"]]


@pytest.mark.parametrize("interrupted", ["stop", "restart"])
def test_watchdog_recovers_socket_after_foreground_is_lost(
    home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake, interrupted: str
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    socket = SocketRecoveryExec(enabled_state=(0, "enabled-runtime"), restart_failure="timeout")
    old = b"Port 22\n# local settings\n"
    ssh.SSHD_DROPIN.write_bytes(old)

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = socket(cmd, timeout)
        if cmd[:2] == ["systemctl", interrupted]:
            raise ProcessLost
        return result

    with pytest.raises(ProcessLost):
        ssh.apply_hardening(home_runner(home, execute))
    pending = watchdog.pending
    assert pending is not None and not socket.socket_active
    if interrupted == "stop":
        ssh.PRIVSEP_DIR.rmdir()

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if interrupted == "stop":
            assert cmd != ["sshd", "-t"]  # Restoring the cached socket needs no daemon gate.
        return socket(cmd, timeout)

    runner = Runner(exec_fn=recover)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    watchdog.now = pending.deadline
    if interrupted == "restart":
        assert socket.pending_restart
        assert ssh.expire_watchdog(pending.id) == 75
        assert not any(
            cmd[1] in {"start", "cancel"} for cmd in socket.calls if cmd[0] == "systemctl"
        )
        assert watchdog.pending is not None and watchdog.clears == 0
        socket.pending_restart = False
        socket.service_active = True
    assert ssh.expire_watchdog(pending.id) == 0
    assert watchdog.pending is None and watchdog.clears == 1
    assert ssh.SSHD_DROPIN.read_bytes() == old
    assert socket.socket_active and not socket.service_active
    assert socket.enabled_state == (0, "enabled-runtime") and not socket.service_runtime
    if interrupted == "stop":
        assert not ssh.PRIVSEP_DIR.exists()


@pytest.mark.parametrize(("error", "status"), [(errno.EIO, 75), (errno.EPERM, 1)])
def test_watchdog_does_not_touch_daemon_if_privsep_chmod_fails(
    awaiting_watchdog: tuple[Runner, str],
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    error: int,
    status: int,
) -> None:
    runner, txid = awaiting_watchdog
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    ssh.PRIVSEP_DIR.chmod(0o700)

    def fail_chmod(fd: int, mode: int) -> None:
        raise OSError(error, "injected chmod failure")

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert cmd[0] != "sshd" and cmd[1] not in {"start", "reload", "restart", "stop"}
        return runner.exec_fn(cmd, timeout)

    monkeypatch.setattr(os, "fchmod", fail_chmod)
    monkeypatch.setattr(ssh, "Runner", lambda: Runner(exec_fn=recover))
    assert ssh.expire_watchdog(txid) == status
    assert watchdog.pending is not None and watchdog.clears == 0
    assert stat.S_IMODE(ssh.PRIVSEP_DIR.stat().st_mode) == 0o700


def test_watchdog_retains_failed_recovery_until_old_endpoints_are_verified(
    home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    socket = SocketRecoveryExec(restart_failure=None, migrated_listeners=(0, SS_TLN_OK))
    assert ssh.apply_hardening(home_runner(home, socket))[-1].status is Status.OK
    socket.restored_listeners = SS_TLN_OK
    pending = watchdog.pending
    assert pending is not None
    runner = Runner(exec_fn=socket)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    watchdog.now = pending.deadline
    assert ssh.expire_watchdog(pending.id) == 75
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert watchdog.clears == 0
    assert not ssh.SSHD_DROPIN.exists()
    assert ssh.apply_hardening(home_runner(home, socket))[0].status is Status.FAIL
    socket.restored_listeners = SS_TLN_OLD_PORT
    assert ssh.expire_watchdog(pending.id) == 0
    assert watchdog.clears == 1 and watchdog.pending is None


@pytest.mark.parametrize(
    "failure", ["I/O", "identity", "activity", "enablement", "extra listener", "config probe"]
)
def test_watchdog_retries_unverified_standalone_recovery(
    awaiting_watchdog: tuple[Runner, str],
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    failure: str,
) -> None:
    runner, txid = awaiting_watchdog
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    first_attempt = True
    remove = ssh.remove_file

    def remove_dropin(path: Path) -> bool:
        if first_attempt and failure == "I/O":
            raise OSError(errno.EIO, "injected filesystem error")
        return remove(path)

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if first_attempt:
            if cmd == ["ss", "-tlnp"] and failure == "extra listener":
                return subprocess.CompletedProcess(cmd, 0, SS_TLN_OK + SS_TLN_OLD_PORT, "")
            if cmd == ["sshd", "-t"] and failure == "config probe":
                return subprocess.CompletedProcess(cmd, 255, "", "injected host key read error")
            probes = {"identity": "show", "activity": "is-active", "enablement": "is-enabled"}
            if cmd[:2] == ["systemctl", probes.get(failure)]:
                return subprocess.CompletedProcess(cmd, 1, "", "injected probe failure")
        return runner.exec_fn(cmd, timeout)

    recovery = Runner(exec_fn=recover)
    monkeypatch.setattr(ssh, "Runner", lambda: recovery)
    monkeypatch.setattr(ssh, "remove_file", remove_dropin)
    assert ssh.expire_watchdog(txid) == 75
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert watchdog.clears == 0
    assert ssh.SSHD_DROPIN.exists() is (failure == "I/O")
    assert sum(result.cmd == SSH_SERVICE_RELOAD for result in recovery.history) == int(
        failure == "extra listener"
    )
    first_attempt = False
    assert ssh.expire_watchdog(txid) == 0
    assert not ssh.SSHD_DROPIN.exists() and watchdog.clears == 1 and watchdog.pending is None
    assert recovery.history[-1].cmd == SSH_SERVICE_JOBS


@pytest.mark.parametrize("conflict", ["drop-in", "unit", "enablement"])
def test_watchdog_stops_on_permanent_standalone_conflict(
    awaiting_watchdog: tuple[Runner, str],
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    conflict: str,
) -> None:
    runner, txid = awaiting_watchdog
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    foreign = b"Port 2200\n"
    if conflict == "drop-in":
        ssh.SSHD_DROPIN.write_bytes(foreign)

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert cmd[1] not in {"start", "reload", "restart", "stop", "cancel"}
        if conflict == "unit" and cmd[:2] == ["systemctl", "show"]:
            return subprocess.CompletedProcess(cmd, 0, "Id=sshd.service\nLoadState=loaded\n", "")
        if conflict == "enablement" and cmd[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(cmd, 1, "masked\n", "")
        return runner.exec_fn(cmd, timeout)

    recovery = Runner(exec_fn=recover)
    monkeypatch.setattr(ssh, "Runner", lambda: recovery)
    assert ssh.expire_watchdog(txid) == 1
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert watchdog.clears == 0
    if conflict == "drop-in":
        assert ssh.SSHD_DROPIN.read_bytes() == foreign and not recovery.history


@pytest.mark.parametrize("foreign_unit", [False, True])
def test_watchdog_defers_stale_cached_socket_after_disk_io_failure(
    home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake, foreign_unit: bool
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    socket = SocketRecoveryExec(
        restart_failure=None,
        migrated_listeners=(0, SS_TLN_OK),
        cached_listen="0.0.0.0:22345 (Stream)\n",
    )
    assert ssh.apply_hardening(home_runner(home, socket))[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    socket.service_active = False
    assert not socket.socket_active
    socket.calls.clear()
    candidate = ssh.SSHD_DROPIN.read_bytes()
    if foreign_unit:
        socket.enabled_state = (0, "enabled-runtime")

    def fail_remove(path: Path) -> bool:
        raise OSError(errno.EIO, "injected filesystem error")

    monkeypatch.setattr(ssh, "Runner", lambda: Runner(exec_fn=socket))
    with monkeypatch.context() as patch:
        patch.setattr(ssh, "remove_file", fail_remove)
        assert ssh.expire_watchdog(pending.id) == (1 if foreign_unit else 75)
    assert watchdog.pending is not None and watchdog.pending.phase == "failed"
    assert ssh.SSHD_DROPIN.read_bytes() == candidate and watchdog.clears == 0
    assert not any(cmd[1] in {"start", "stop", "reload", "daemon-reload"} for cmd in socket.calls)
    if not foreign_unit:
        assert ssh.expire_watchdog(pending.id) == 0
        assert socket.socket_active and not socket.service_active
        assert not ssh.SSHD_DROPIN.exists() and watchdog.pending is None
        assert watchdog.clears == 1


def test_watchdog_recreates_privsep_before_each_socket_daemon_gate(
    home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    socket = SocketRecoveryExec(
        restart_failure=None, socket_reenables=False, migrated_listeners=(0, SS_TLN_OK)
    )
    assert ssh.apply_hardening(home_runner(home, socket))[-1].status is Status.OK
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    ssh.PRIVSEP_DIR.rmdir()
    validations = 0

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal validations
        if cmd == ["sshd", "-t"]:
            assert ssh.PRIVSEP_DIR.is_dir()
            validations += 1
        result = socket(cmd, timeout)
        if cmd == ["systemctl", "stop", "--job-mode=fail", "ssh.service"]:
            ssh.PRIVSEP_DIR.rmdir()
        return result

    monkeypatch.setattr(ssh, "Runner", lambda: Runner(exec_fn=recover))
    assert ssh.expire_watchdog(pending.id) == 75
    assert validations == 2 and socket.service_active and not socket.socket_active
    assert watchdog.pending is not None and watchdog.pending.data["fallback_attempted"] is True


def test_hardening_does_not_replace_a_disappeared_backup_source(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    ssh.SSHD_DROPIN.write_text("Port 22\n")
    fake_exec.responses.extend([*SSH_SERVICE_ACTIVE, ("ss -tlnp", 0, SS_TLN_OLD_PORT, "")])
    write = ssh.write_dropin

    def write_after_removal(path: Path, content: str, **kwargs: Any) -> str:
        path.unlink()
        return write(path, content, **kwargs)

    monkeypatch.setattr(ssh, "write_dropin", write_after_removal)
    results = ssh.apply_hardening(home_runner(home, fake_exec))
    assert results[0].status is Status.FAIL
    assert not ssh.SSHD_DROPIN.exists()
    assert not list(ssh.SSHD_DROPIN.parent.glob("*.bak*"))
    assert fake_exec.calls == SSH_SERVICE_PREFLIGHT_CALLS
    assert watchdog.pending is None and watchdog.clears == 1


@pytest.mark.parametrize("crash_at", ["replace", "stop-intent"])
@pytest.mark.parametrize(
    "guard",
    ["ok", "jobs", "coverage-after", "foreign-trigger", "foreign-endpoints", "config probe"],
)
def test_watchdog_only_reloads_the_guarded_socket_triggered_service(
    home: Path, monkeypatch: pytest.MonkeyPatch, watchdog: WatchdogFake, crash_at: str, guard: str
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    socket = SocketRecoveryExec()
    original = b"Port 22\n# old authentication settings\n"
    ssh.SSHD_DROPIN.write_bytes(original)
    replace = os.replace
    update = watchdog.update

    def crash() -> None:
        assert socket.socket_active
        socket.service_active = True  # Incoming connection triggered sshd on the candidate.
        raise ProcessLost

    def replace_then_crash(src: str | Path, dst: str | Path) -> None:
        replace(src, dst)
        if dst == ssh.SSHD_DROPIN and crash_at == "replace":
            crash()

    def update_then_crash(
        pending: ssh.ssh_watchdog.Pending, *, phase: str | None = None, **data: object
    ) -> ssh.ssh_watchdog.Pending:
        updated = update(pending, phase=phase, **data)
        if data.get("action") == "stop" and crash_at == "stop-intent":
            crash()  # The intent is durable, but the foreground did not submit the job.
        return updated

    with monkeypatch.context() as context:
        context.setattr(os, "replace", replace_then_crash)
        context.setattr(ssh.ssh_watchdog, "update", update_then_crash)
        with pytest.raises(ProcessLost):
            ssh.apply_hardening(home_runner(home, socket))
    pending = watchdog.pending
    assert pending is not None
    assert pending.data["action"] == ("stop" if crash_at == "stop-intent" else "none")
    watchdog.now = pending.deadline
    daemon_config = ssh.SSHD_DROPIN.read_bytes()
    ssh.PRIVSEP_DIR.rmdir()
    reloads = 0
    validations = 0
    first_attempt = True
    socket.pending_restart = guard == "jobs"
    if guard == "foreign-endpoints":
        socket.initial_socket_listen = "127.0.0.1:22 (Stream)\n"

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal reloads, validations, daemon_config
        assert socket.socket_active and socket.service_active
        assert ssh.SSHD_DROPIN.read_bytes() == original
        assert watchdog.pending is not None
        assert cmd[1] not in {"stop", "start", "restart", "cancel"}
        if cmd == ["sshd", "-t"]:
            validations += 1
            assert ssh.PRIVSEP_DIR.is_dir()
            if guard == "config probe" and first_attempt:
                return subprocess.CompletedProcess(cmd, 255, "", "injected host key read error")
        if cmd == SSH_SERVICE_RELOAD:
            assert validations == reloads + 1 + int(guard == "config probe")
            assert not socket.pending_restart
            reloads += 1
            daemon_config = ssh.SSHD_DROPIN.read_bytes()
        if cmd == ["ss", "-tlnp"] and guard == "coverage-after" and first_attempt and reloads:
            return subprocess.CompletedProcess(cmd, 1, "", "probe unavailable")
        if cmd == ["systemctl", "show", "--property=Triggers", "--value", "ssh.socket"]:
            if guard == "foreign-trigger":
                return subprocess.CompletedProcess(cmd, 0, "other.service\n", "")
        return socket(cmd, timeout)

    runner = Runner(exec_fn=recover)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    if guard in {"foreign-trigger", "foreign-endpoints"}:
        assert ssh.expire_watchdog(pending.id) == 1
        assert reloads == 0 and watchdog.pending is not None and watchdog.clears == 0
        return
    if guard in {"jobs", "coverage-after", "config probe"}:
        assert ssh.expire_watchdog(pending.id) == 75
        assert watchdog.pending is not None and watchdog.pending.phase == "failed"
        assert watchdog.clears == 0 and reloads == int(guard == "coverage-after")
        first_attempt = False
        socket.pending_restart = False
    assert ssh.expire_watchdog(pending.id) == 0
    assert reloads == (2 if guard == "coverage-after" else 1) and daemon_config == original
    assert socket.socket_active and socket.service_active
    assert watchdog.pending is None and watchdog.clears == 1


@pytest.mark.parametrize("mode", ["socket", "service"])
@pytest.mark.parametrize("job_state_known", [True, False])
def test_watchdog_retries_if_the_job_that_blocked_recovery_is_already_gone(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    mode: str,
    job_state_known: bool,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    socket = SocketRecoveryExec()
    base_exec = socket if mode == "socket" else fake_exec
    operation = "stop" if mode == "socket" else "reload"

    def crash_on_activation(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = base_exec(cmd, timeout)
        if cmd[:2] == ["systemctl", operation]:
            raise ProcessLost
        return result

    with pytest.raises(ProcessLost):
        ssh.apply_hardening(home_runner(home, crash_on_activation))
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    jobs_probes = 0
    recovery_actions: list[list[str]] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal jobs_probes
        if cmd[:2] == ["systemctl", "list-jobs"]:
            jobs_probes += 1
            if jobs_probes == 1:
                if not job_state_known:
                    return subprocess.CompletedProcess(cmd, 1, "", "systemd unavailable")
                return subprocess.CompletedProcess(cmd, 0, "29 ssh.service start waiting\n", "")
        if cmd[0] == "systemctl" and cmd[1] in {"reload", "start", "stop", "cancel"}:
            recovery_actions.append(cmd)
        return base_exec(cmd, timeout)

    runner = Runner(exec_fn=execute)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    assert ssh.expire_watchdog(pending.id) == 75
    assert not recovery_actions
    assert watchdog.pending is not None and watchdog.clears == 0
    assert ssh.expire_watchdog(pending.id) == 0
    assert len(recovery_actions) == 1 and "--job-mode=fail" in recovery_actions[0]
    assert watchdog.pending is None and watchdog.clears == 1


@pytest.mark.parametrize("mode", ["reload", "stop", "start"])
def test_watchdog_retries_rejected_runtime_operation_even_if_jobs_are_now_idle(
    fake_exec: Any,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    watchdog: WatchdogFake,
    mode: str,
) -> None:
    seed_user(home, "robin")
    monkeypatch.setattr(ssh, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            *SSH_SERVICE_ACTIVE,
            ROBIN_ADMIN_PROBE,
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    socket = SocketRecoveryExec(restart_failure=None)
    original_exec = fake_exec if mode == "reload" else socket
    activation = "reload" if mode == "reload" else "restart"

    def crash_on_activation(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = original_exec(cmd, timeout)
        if cmd[:2] == ["systemctl", activation]:
            raise ProcessLost
        return result

    with pytest.raises(ProcessLost):
        ssh.apply_hardening(home_runner(home, crash_on_activation))
    pending = watchdog.pending
    assert pending is not None
    watchdog.now = pending.deadline
    actions: list[list[str]] = []
    recovery_unit = "ssh.socket" if mode == "start" else "ssh.service"

    def recover(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd[0] == "systemctl" and cmd[1] in {"reload", "stop", "start", "cancel"}:
            assert "--job-mode=fail" in cmd and "cancel" not in cmd
            actions.append(cmd)
            if cmd == ["systemctl", mode, "--job-mode=fail", recovery_unit]:
                if actions.count(cmd) == 1:
                    # The conflicting job starts after the idle probe and
                    # finishes before the next probe; all list-jobs are empty.
                    return subprocess.CompletedProcess(cmd, 1, "", "")
        return original_exec(cmd, timeout)

    runner = Runner(exec_fn=recover)
    monkeypatch.setattr(ssh, "Runner", lambda: runner)
    assert ssh.expire_watchdog(pending.id) == 75
    assert watchdog.pending is not None and watchdog.clears == 0
    assert not ssh.SSHD_DROPIN.exists()
    if mode == "start":
        assert socket.service_active and not socket.socket_active
        # A verified fallback is already reachable; do not tear it down for a retry.
        snapshot = list(actions)
        assert ssh.expire_watchdog(pending.id) == 1
        assert actions == snapshot and socket.service_active
    else:
        assert ssh.expire_watchdog(pending.id) == 0
        assert watchdog.pending is None and watchdog.clears == 1
