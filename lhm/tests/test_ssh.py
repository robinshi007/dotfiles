import subprocess
from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
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
"""


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "home"
    root.mkdir()
    monkeypatch.setattr(ssh, "HOME_ROOT", root)
    dropin = tmp_path / "etc" / "ssh" / "sshd_config.d" / "99-lhm.conf"
    monkeypatch.setattr(ssh, "SSHD_DROPIN", dropin)
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", tmp_path / "run" / "sshd")
    return root


def seed_user(home: Path, name: str, key: str = PUBKEY) -> None:
    keys = home / name / ".ssh" / "authorized_keys"
    keys.parent.mkdir(parents=True)
    keys.write_text(key + "\n", encoding="utf-8")
    keys.chmod(0o600)


def test_invalid_pubkey_is_refused(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text("not-a-key at all\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert "does not look like an SSH public key" in results[0].detail
    assert fake_exec.calls == []
    assert not (home / "robin").exists()


def test_private_key_pem_is_refused(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []


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
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text(line + "\n", encoding="utf-8")
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []
    assert not (home / "robin").exists()


def test_strict_validation_accepts_real_keys() -> None:
    assert ssh.is_pubkey_line(PUBKEY)
    assert ssh.is_pubkey_line(PUBKEY + " extra comment words")
    assert not ssh.is_pubkey_line("# " + PUBKEY)


def test_ssh_user_creates_user_and_installs_key(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    fake_exec.responses.extend(
        [
            ("getent passwd robin", 2, "", ""),
            ("id -nG robin", 0, "robin\n", ""),
        ]
    )
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    assert names["create user robin"] is Status.CHANGED
    assert names["install " + str(ssh.authorized_keys_path("robin"))] is Status.CHANGED
    keys = ssh.authorized_keys_path("robin")
    assert keys.read_text(encoding="utf-8") == PUBKEY + "\n"
    assert keys.stat().st_mode & 0o777 == 0o600
    executed = [" ".join(call) for call in fake_exec.calls]
    assert any(call.startswith("useradd --create-home") for call in executed)
    assert any(call.startswith("install -d -m 0700") for call in executed)


def test_ssh_user_skips_existing_key(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    fake_exec.responses.extend(
        [("getent passwd robin", 0, "robin:x:1000:1000::/home/robin:/bin/bash\n", "")]
    )
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    assert names["create user robin"] is Status.SKIPPED
    assert names["install " + str(ssh.authorized_keys_path("robin"))] is Status.SKIPPED
    assert ssh.authorized_keys_path("robin").read_text(encoding="utf-8") == PUBKEY + "\n"


def test_ssh_user_sudo_group(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    fake_exec.responses.extend(
        [
            ("getent passwd robin", 0, "robin:x:1000:1000::/home/robin:/bin/bash\n", ""),
            ("id -nG robin", 0, "robin\n", ""),
        ]
    )
    results = ssh.apply_user(
        Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file), sudo=True
    )
    names = {r.name: r.status for r in results}
    assert names["add robin to sudo"] is Status.CHANGED
    assert ["usermod", "-aG", "sudo", "robin"] in fake_exec.calls


def test_hardening_refuses_without_authorized_keys(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    assert results[0].status is Status.FAIL
    assert "no authorized_keys" in results[0].detail
    assert fake_exec.calls == []
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_refuses_when_requested_user_has_no_valid_key(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    keys = home / "robin" / ".ssh" / "authorized_keys"
    keys.parent.mkdir(parents=True)
    keys.write_text("junk\n", encoding="utf-8")
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), allow_users=["robin"])
    assert results[0].status is Status.FAIL
    assert "robin" in results[0].detail
    assert not ssh.SSHD_DROPIN.exists()


def test_hardening_rolls_back_when_sshd_t_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.append(("sshd -t", 1, "", "/etc/ssh/sshd_config.d/99-lhm.conf: bad port"))
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    names = {r.name: r.status for r in results}
    assert names["sshd -t"] is Status.FAIL
    assert "removed the new drop-in" in dict((r.name, r.detail) for r in results)["sshd -t"]
    assert not ssh.SSHD_DROPIN.exists()
    executed = [" ".join(call) for call in fake_exec.calls]
    assert not any(call.startswith("systemctl reload") for call in executed)


def test_hardening_rolls_back_to_previous_content(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.parent.mkdir(parents=True)
    ssh.SSHD_DROPIN.write_text("Port 22\n", encoding="utf-8")
    fake_exec.responses.append(("sshd -t", 1, "", "bad config"))
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    assert results[1].status is Status.FAIL
    assert "restored" in results[1].detail
    assert ssh.SSHD_DROPIN.read_text(encoding="utf-8") == "Port 22\n"


SS_TLN_OK = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22345      0.0.0.0:*     users:(("sshd",pid=1,fd=3))
"""

SS_TLN_OLD_PORT = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1,fd=3))
"""


def test_hardening_writes_dropin_then_reloads_and_verifies(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            ("systemctl reload ssh", 0, "", ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345, allow_users=["robin"])
    names = {r.name: r.status for r in results}
    assert names["reload sshd"] is Status.CHANGED
    assert results[-1].status is Status.OK
    content = ssh.SSHD_DROPIN.read_text(encoding="utf-8")
    assert "Port 22345" in content
    assert "AllowUsers robin" in content
    order = [" ".join(call) for call in fake_exec.calls]
    gate = next(i for i, c in enumerate(order) if c == "sshd -t")
    reload_index = next(i for i, c in enumerate(order) if c.startswith("systemctl reload"))
    assert gate < reload_index
    # The effective-config gate must also run before the reload.
    effective_gate = next(i for i, c in enumerate(order) if c == "sshd -T")
    assert gate < effective_gate < reload_index


class UnitAwareExec:
    """Answers sshd -t/-T, fails reload of the ssh unit, accepts the sshd unit."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd == ["systemctl", "reload", "ssh"]:
            return subprocess.CompletedProcess(cmd, 5, "", "Unit ssh.service not found.")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, SSHD_T_OK, "")
        if cmd == ["ss", "-tlnp"]:
            return subprocess.CompletedProcess(cmd, 0, SS_TLN_OK, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_hardening_falls_back_to_sshd_unit(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    results = ssh.apply_hardening(Runner(exec_fn=UnitAwareExec()))
    reload_step = next(r for r in results if r.name == "reload sshd")
    assert reload_step.detail == "reloaded sshd"


def test_hardening_socket_activation_is_disabled_then_restarted(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debian 12 ssh.socket owns the listener: reload would keep port 22."""
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            ("systemctl is-active ssh.socket", 0, "active\n", ""),
            ("systemctl restart ssh", 0, "", ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    runner = Runner(exec_fn=fake_exec)
    results = ssh.apply_hardening(runner, port=22345)
    order = [" ".join(call) for call in fake_exec.calls]
    disable = order.index("systemctl disable --now ssh.socket")
    restart = order.index("systemctl restart ssh")
    assert disable < restart
    assert not any(call.startswith("systemctl reload") for call in order)
    assert results[-1].status is Status.OK
    steps = {r.name: r.status for r in results}
    assert steps["disable ssh.socket"] is Status.CHANGED


def test_hardening_verify_reports_actual_listening_port_mismatch(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sshd -T says 22345 (socket activation hides it) but only 22 listens."""
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            ("systemctl reload ssh", 0, "", ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OLD_PORT, ""),
        ]
    )
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    assert results[-1].status is Status.FAIL
    assert "not listening" in results[-1].detail


def test_hardening_effective_conflict_rolls_back_and_fails(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """50-cloud-init.conf wins (first obtained value): detect, roll back, FAIL."""
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    ssh.SSHD_DROPIN.parent.mkdir(parents=True)
    conflicting = ssh.SSHD_DROPIN.parent / "50-cloud-init.conf"
    conflicting.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            (
                "sshd -T",
                0,
                SSHD_T_OK.replace("passwordauthentication no", "passwordauthentication yes"),
                "",
            ),
        ]
    )
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345)
    gate = next(r for r in results if r.name == "sshd -T effective")
    assert gate.status is Status.FAIL
    assert "passwordauthentication yes" in gate.detail
    assert "50-cloud-init.conf" in gate.detail
    assert "PasswordAuthentication yes" in gate.detail
    assert "removed the new drop-in" in gate.detail
    assert not ssh.SSHD_DROPIN.exists()
    order = [" ".join(call) for call in fake_exec.calls]
    assert not any(call.startswith("systemctl reload") for call in order)
    assert not any(call.startswith("systemctl restart") for call in order)


def test_hardening_dry_run_prints_plan_and_writes_nothing(
    fake_exec: Any, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_user(home, "robin")
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = ssh.apply_hardening(runner, port=22345)
    out = capsys.readouterr().out
    assert "Port 22345" in out
    assert not ssh.SSHD_DROPIN.exists()
    assert all(r.status is Status.PLANNED for r in results)
    assert fake_exec.calls == []


def test_hardening_creates_missing_privsep_dir(
    fake_exec: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Socket-activated ssh.service never ran, so /run/sshd is missing and
    sshd -t refuses the config before lhm can gate on it."""
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    assert not ssh.PRIVSEP_DIR.exists()
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            ("systemctl reload ssh", 0, "", ""),
            ("sshd -T", 0, SSHD_T_OK, ""),
            ("ss -tlnp", 0, SS_TLN_OK, ""),
        ]
    )
    ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345, allow_users=["robin"])
    assert ssh.PRIVSEP_DIR.is_dir()
    assert ssh.PRIVSEP_DIR.stat().st_mode & 0o777 == 0o755
    order = [" ".join(call) for call in fake_exec.calls]
    assert order.index("sshd -t") > -1  # the gate still ran


def test_ensure_privsep_dir_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh, "PRIVSEP_DIR", tmp_path / "run" / "sshd")
    assert ssh.ensure_privsep_dir() is True
    assert ssh.ensure_privsep_dir() is True
    assert ssh.PRIVSEP_DIR.is_dir()


def test_ssh_user_reports_skipped_when_dir_already_correct(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`install -d` always succeeds; a re-run must not claim a CHANGED it did not make."""
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    (home / "robin" / ".ssh").chmod(0o700)
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    stat = (home / "robin" / ".ssh").stat()
    fake_exec.responses.append(
        (
            "getent passwd robin",
            0,
            f"robin:x:{stat.st_uid}:{stat.st_gid}::/home/robin:/bin/bash\n",
            "",
        )
    )
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    assert names["ensure " + str(ssh.authorized_keys_path("robin").parent)] is Status.SKIPPED
    assert Status.CHANGED not in names.values()


def test_ssh_user_reports_changed_when_dir_mode_wrong(
    fake_exec: Any, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    (home / "robin" / ".ssh").chmod(0o755)
    key_file = tmp_path / "id.pub"
    key_file.write_text(PUBKEY + "\n", encoding="utf-8")
    stat = (home / "robin" / ".ssh").stat()
    fake_exec.responses.append(
        (
            "getent passwd robin",
            0,
            f"robin:x:{stat.st_uid}:{stat.st_gid}::/home/robin:/bin/bash\n",
            "",
        )
    )
    results = ssh.apply_user(Runner(exec_fn=fake_exec), user="robin", key_file=str(key_file))
    names = {r.name: r.status for r in results}
    assert names["ensure " + str(ssh.authorized_keys_path("robin").parent)] is Status.CHANGED


def test_rollback_delete_prints_red_minus(home: Path) -> None:
    import io

    from lhm.core import colors

    ssh.SSHD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    ssh.SSHD_DROPIN.write_text("Port 22345\n", encoding="utf-8")
    stream = io.StringIO()
    colors.configure("always")
    colors.set_output(stream)
    try:
        assert ssh._rollback_dropin() == "removed the new drop-in"
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
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    fake_exec.responses.extend(
        [
            ("sshd -t", 0, "", ""),
            ("sshd -T", 0, SSHD_T_ALLOW_OTHER, ""),
        ]
    )
    results = ssh.apply_hardening(Runner(exec_fn=fake_exec), port=22345, allow_users=["robin"])
    gate = next(r for r in results if r.name == "sshd -T effective")
    assert gate.status is Status.FAIL
    assert "allowusers missing robin" in gate.detail
    assert not ssh.SSHD_DROPIN.exists()
    order = [" ".join(call) for call in fake_exec.calls]
    assert not any(call.startswith("systemctl reload") for call in order)
    assert not any(call.startswith("systemctl restart") for call in order)


class SocketRestartFailsExec:
    """ssh.socket active; disabling it then restarting ssh/sshd both fail."""

    def __init__(self, *, socket_reenables: bool = True) -> None:
        self.calls: list[list[str]] = []
        self.socket_reenables = socket_reenables

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd == ["sshd", "-t"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["sshd", "-T"]:
            return subprocess.CompletedProcess(cmd, 0, SSHD_T_OK + "allowusers robin\n", "")
        if cmd == ["systemctl", "is-active", "ssh.socket"]:
            return subprocess.CompletedProcess(cmd, 0, "active\n", "")
        if cmd[:3] == ["systemctl", "disable", "--now"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["systemctl", "restart"]:
            return subprocess.CompletedProcess(cmd, 1, "", "Unit not found.")
        if cmd[:3] == ["systemctl", "enable", "--now"]:
            if self.socket_reenables:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "Failed to enable unit")
        if cmd == ["systemctl", "start", "ssh"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["ss", "-tlnp"]:
            return subprocess.CompletedProcess(cmd, 0, SS_TLN_OLD_PORT, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_hardening_restores_socket_after_restart_failure(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    exec_fn = SocketRestartFailsExec()
    results = ssh.apply_hardening(Runner(exec_fn=exec_fn), port=22345, allow_users=["robin"])
    order = [" ".join(call) for call in exec_fn.calls]
    assert "systemctl disable --now ssh.socket" in order
    assert "systemctl restart ssh" in order and "systemctl restart sshd" in order
    enable = order.index("systemctl enable --now ssh.socket")
    assert enable > order.index("systemctl restart sshd")
    assert order[enable + 1] == "systemctl is-active ssh.socket"
    assert order[enable + 2] == "ss -tlnp"
    steps = {r.name: r for r in results}
    assert steps["restore ssh.socket"].status is Status.CHANGED
    assert "22/tcp" in steps["restore ssh.socket"].detail
    assert steps["reload sshd"].status is Status.FAIL
    assert "previous socket-activated listener was restored" in steps["reload sshd"].detail
    assert not ssh.SSHD_DROPIN.exists()  # drop-in rolled back
    assert "rollback hint" in capsys.readouterr().out


def test_hardening_double_failure_prints_manual_recovery(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ssh, "confirm_twice", lambda plan: True)
    seed_user(home, "robin")
    exec_fn = SocketRestartFailsExec(socket_reenables=False)
    results = ssh.apply_hardening(Runner(exec_fn=exec_fn), port=22345, allow_users=["robin"])
    order = [" ".join(call) for call in exec_fn.calls]
    assert "systemctl start ssh" in order
    steps = {r.name: r for r in results}
    assert steps["restore ssh.socket"].status is Status.FAIL
    assert steps["reload sshd"].status is Status.FAIL
    assert "systemctl start ssh` succeeded" in steps["reload sshd"].detail
    assert not ssh.SSHD_DROPIN.exists()
    err = capsys.readouterr().err
    assert "SSH may be DOWN" in err
    assert "systemctl enable --now ssh.socket" in err
