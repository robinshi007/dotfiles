"""SSH module: admin user with authorized_keys, then the hardened sshd drop-in."""

import base64
import binascii
import os
import re
import struct
import sys
from collections.abc import Sequence
from pathlib import Path

from lhm.core import checks, colors
from lhm.core.backup import newest_backup, rollback_file
from lhm.core.confirm import confirm_twice
from lhm.core.files import render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

TEMPLATE = "ssh-hardening.conf.tmpl"
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/99-lhm.conf")
HOME_ROOT = Path("/home")
# sshd(8) refuses to run (-t/-T) when its privilege-separation directory is
# missing. ssh.service creates it via RuntimeDirectory, but with socket
# activation (Ubuntu 24.04 default) ssh.service has never run, so /run/sshd
# does not exist yet and every gate would fail on a fresh server.
PRIVSEP_DIR = Path("/run/sshd")
DEFAULT_PORT = 22345
KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
SOCKET_UNITS = ("ssh.socket", "sshd.socket")


class SshError(ValueError):
    """Raised when the user name or public key is not acceptable."""


def authorized_keys_path(user: str) -> Path:
    return HOME_ROOT / user / ".ssh" / "authorized_keys"


def _key_blob_ok(key_type: str, blob: str) -> bool:
    """True when ``blob`` is base64 and its SSH wire type matches ``key_type``."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) < 32:
        return False
    try:
        (type_len,) = struct.unpack(">I", raw[:4])
    except struct.error:
        return False
    if not 0 < type_len or 4 + type_len > len(raw):
        return False
    try:
        return raw[4 : 4 + type_len].decode("ascii") == key_type
    except UnicodeDecodeError:
        return False


def is_pubkey_line(line: str) -> bool:
    """Validate ``type base64 [comment]`` including a decodable key blob."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    parts = stripped.split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        return False
    return _key_blob_ok(parts[0], parts[1])


def read_pubkey(path: str | Path) -> str:
    """Return the first usable key line from ``path`` or raise ``SshError``."""
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not is_pubkey_line(stripped):
            raise SshError(
                f"refusing: {path} does not look like an SSH public key "
                f"(starts with {stripped[:32]!r})"
            )
        return stripped
    raise SshError(f"refusing: {path} contains no public key")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def valid_key_lines(path: str | Path) -> list[str]:
    text = _read_text(Path(path))
    if text is None:
        return []
    return [line.strip() for line in text.splitlines() if is_pubkey_line(line)]


def users_with_keys() -> list[str]:
    """Home users that already have at least one valid key in authorized_keys."""
    try:
        homes = sorted(path for path in HOME_ROOT.iterdir() if path.is_dir())
    except OSError:
        return []
    return [home.name for home in homes if valid_key_lines(home / ".ssh" / "authorized_keys")]


def desired_conf(port: int = DEFAULT_PORT, allow_users: Sequence[str] = ()) -> str:
    return render_template(TEMPLATE, port=str(port), allow_users=" ".join(allow_users))


def _with_key(existing: str, key_line: str) -> str:
    base = existing.rstrip("\n")
    if base:
        base += "\n"
    return base + key_line + "\n"


def _verify_user(runner: Runner, user: str, key_line: str, want_sudo: bool) -> StepResult:
    problems: list[str] = []
    if not runner.run(["getent", "passwd", user], check=False).ok:
        problems.append("user missing")
    ak_path = authorized_keys_path(user)
    try:
        if not ak_path.is_file():
            problems.append("authorized_keys missing")
        else:
            mode = ak_path.stat().st_mode & 0o777
            if mode != 0o600:
                problems.append(f"authorized_keys mode {mode:04o}")
            installed = ak_path.read_text(encoding="utf-8").splitlines()
            if key_line not in {line.strip() for line in installed}:
                problems.append("key not in authorized_keys")
    except OSError as exc:
        problems.append(f"authorized_keys unreadable: {exc}")
    if want_sudo and "sudo" not in runner.run(["id", "-nG", user], check=False).stdout.split():
        problems.append("not in sudo group")
    if problems:
        return StepResult("verify", Status.FAIL, "; ".join(problems))
    return StepResult("verify", Status.OK, f"{user} ready for key-only login")


def _passwd_ids(line: str) -> tuple[int, int] | None:
    """uid/gid from one ``getent passwd`` line (``name:x:uid:gid:...``)."""
    fields = line.strip().split(":")
    if len(fields) < 4:
        return None
    try:
        return int(fields[2]), int(fields[3])
    except ValueError:
        return None


def _dir_ready(path: Path, ids: tuple[int, int] | None) -> bool:
    """True when ``path`` is already a 0700 directory owned by ``ids``.

    ``install -d`` succeeds whether or not it changed anything, so this probe is
    what keeps a re-run from reporting a CHANGED it did not make.
    """
    if ids is None:
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    return path.is_dir() and stat.st_mode & 0o777 == 0o700 and (stat.st_uid, stat.st_gid) == ids


def apply_user(runner: Runner, *, user: str, key_file: str, sudo: bool = False) -> list[StepResult]:
    if not USER_RE.fullmatch(user):
        return [StepResult("ssh-user", Status.FAIL, f"invalid user name: {user!r}")]
    try:
        key_line = read_pubkey(key_file)
    except (OSError, SshError) as exc:
        return [StepResult("ssh-user", Status.FAIL, str(exc))]

    ak_path = authorized_keys_path(user)
    existing = _read_text(ak_path) or ""
    key_present = key_line in {line.strip() for line in existing.splitlines()}
    account = None if runner.dry_run else runner.run(["getent", "passwd", user], check=False)
    exists = bool(account is not None and account.ok)
    dir_ids = _passwd_ids(account.stdout) if exists else None
    dir_was_ready = False if runner.dry_run else _dir_ready(ak_path.parent, dir_ids)

    plan = ["Plan (ssh-user):"]
    plan.append(
        f"  - user {user} exists (skip useradd)"
        if exists
        else f"  - create user {user} (home + /bin/bash)"
    )
    plan.append(f"  - ensure {ak_path.parent} exists with mode 0700, owner {user}")
    plan.append(
        "  - authorized_keys already contains the key (skip)"
        if key_present
        else f"  - install public key into {ak_path} (0600, owner {user})"
    )
    if sudo:
        plan.append(f"  - add {user} to the sudo group")

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        if not exists:
            runner.run(["useradd", "--create-home", "--shell", "/bin/bash", user])
            results.append(StepResult(f"create user {user}", Status.PLANNED))
        runner.run(["install", "-d", "-m", "0700", "-o", user, "-g", user, str(ak_path.parent)])
        results.append(StepResult(f"ensure {ak_path.parent}", Status.PLANNED, "mode 0700"))
        if not key_present:
            runner.run(["chown", f"{user}:{user}", str(ak_path)])
            results.append(StepResult(f"install {ak_path}", Status.PLANNED))
        if sudo:
            runner.run(["usermod", "-aG", "sudo", user])
            results.append(StepResult(f"add {user} to sudo", Status.PLANNED))
        return results

    if not confirm_twice(plan):
        return [StepResult("ssh-user", Status.ABORTED, "aborted; no changes made")]

    results = []
    try:
        if exists:
            results.append(StepResult(f"create user {user}", Status.SKIPPED, "exists"))
        else:
            runner.run(["useradd", "--create-home", "--shell", "/bin/bash", user])
            results.append(StepResult(f"create user {user}", Status.CHANGED))
        runner.run(["install", "-d", "-m", "0700", "-o", user, "-g", user, str(ak_path.parent)])
        # `install -d` always succeeds: report SKIPPED when the directory was
        # already correct, otherwise a re-run claims a change it did not make.
        changed = not (exists and dir_was_ready)
        results.append(
            StepResult(
                f"ensure {ak_path.parent}",
                Status.CHANGED if changed else Status.SKIPPED,
                "mode 0700" if changed else "already 0700, owner correct",
            )
        )
        if key_present:
            results.append(StepResult(f"install {ak_path}", Status.SKIPPED, "key present"))
        else:
            write_dropin(ak_path, _with_key(existing, key_line))
            os.chmod(ak_path, 0o600)
            runner.run(["chown", f"{user}:{user}", str(ak_path)])
            results.append(StepResult(f"install {ak_path}", Status.CHANGED, "0600"))
        if sudo:
            groups = runner.run(["id", "-nG", user], check=False).stdout.split()
            if "sudo" in groups:
                results.append(StepResult(f"add {user} to sudo", Status.SKIPPED, "already member"))
            else:
                runner.run(["usermod", "-aG", "sudo", user])
                results.append(StepResult(f"add {user} to sudo", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("ssh-user", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {ak_path}", flush=True)
        return results

    results.append(_verify_user(runner, user, key_line, sudo))
    return results


def _rollback_dropin() -> str:
    backup = newest_backup(SSHD_DROPIN)
    if backup is not None:
        rollback_file(SSHD_DROPIN)
        return f"restored {backup.name}"
    old = _read_text(SSHD_DROPIN)
    SSHD_DROPIN.unlink(missing_ok=True)
    if old is not None:
        colors.file_change("deleted", SSHD_DROPIN, old=old)
    return "removed the new drop-in"


def _socket_active(runner: Runner) -> str | None:
    """Active ssh socket unit (Debian 12 socket activation), or None."""
    for unit in SOCKET_UNITS:
        result = runner.run(["systemctl", "is-active", unit], check=False)
        if result.ok and result.stdout.strip() == "active":
            return unit
    return None


def _reload(runner: Runner) -> str | None:
    for unit in ("ssh", "sshd"):
        if runner.run(["systemctl", "reload", unit], check=False).ok:
            return unit
    return None


def _restart(runner: Runner) -> str | None:
    for unit in ("ssh", "sshd"):
        if runner.run(["systemctl", "restart", unit], check=False).ok:
            return unit
    return None


def _recover_socket_after_restart_failure(
    runner: Runner, socket_unit: str, results: list[StepResult]
) -> None:
    """Restore the listener after both ``restart ssh`` and ``restart sshd`` failed.

    On Debian 12 the listener comes from the socket unit's ListenStream (default
    22), not from sshd_config: a socket-activated sshd uses the passed fd and
    ignores Port drop-ins. Re-enabling the socket therefore restores the
    previously working listener even while the new drop-in is still present.
    """
    enabled = runner.run(["systemctl", "enable", "--now", socket_unit], check=False).ok
    active = (
        enabled
        and runner.run(["systemctl", "is-active", socket_unit], check=False).stdout.strip()
        == "active"
    )
    ports = checks.current_ssh_ports(runner) if active else []
    if active and ports:
        restored = _rollback_dropin()
        results.append(
            StepResult(
                "restore ssh.socket",
                Status.CHANGED,
                f"enabled --now {socket_unit}; listening again on "
                + ", ".join(f"{port}/tcp" for port in ports),
            )
        )
        results.append(
            StepResult(
                "reload sshd",
                Status.FAIL,
                "restart failed for ssh and sshd; the previous socket-activated "
                f"listener was restored and the new drop-in was rolled back ({restored})",
            )
        )
        print(f"lhm: rollback hint: lhm rollback {SSHD_DROPIN}", flush=True)
        return

    restored = _rollback_dropin()
    fallback = runner.run(["systemctl", "start", "ssh"], check=False).ok
    results.append(
        StepResult(
            "restore ssh.socket",
            Status.FAIL,
            f"could not re-enable {socket_unit}",
        )
    )
    detail = (
        "restart failed for ssh and sshd and re-enabling the socket also failed; "
        f"drop-in rolled back ({restored}); "
        + ("`systemctl start ssh` succeeded" if fallback else "`systemctl start ssh` also failed")
    )
    results.append(StepResult("reload sshd", Status.FAIL, detail))
    print(
        "lhm: SSH may be DOWN: from the console run "
        f"`systemctl enable --now {socket_unit}` (or `systemctl start ssh`), "
        "then `ss -tlnp` to confirm a listener",
        file=sys.stderr,
        flush=True,
    )
    print(f"lhm: rollback hint: lhm rollback {SSHD_DROPIN}", flush=True)


def _conflict_hint(keyword: str, expected: str) -> str:
    """Name earlier sshd_config.d drop-ins that set ``keyword`` to something else."""
    names: list[str] = []
    try:
        siblings = sorted(SSHD_DROPIN.parent.glob("*.conf"))
    except OSError:
        return ""
    for path in siblings:
        if path == SSHD_DROPIN:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0].lower() == keyword and parts[1].lower() != expected:
                names.append(f"{path} ({stripped})")
                break
    if not names:
        return ""
    return (
        "conflicting earlier drop-in(s) "
        + ", ".join(names)
        + " (sshd takes the first obtained value): remove or fix them"
    )


def _effective_problems(
    config: dict[str, str], port: int, required_users: Sequence[str] = ()
) -> list[str]:
    problems: list[str] = []
    if config.get("port") != str(port):
        problems.append(f"port {config.get('port', 'unknown')}")
    if config.get("permitrootlogin") != "no":
        problems.append(f"permitrootlogin {config.get('permitrootlogin', 'unknown')}")
    if config.get("passwordauthentication") != "no":
        problems.append(f"passwordauthentication {config.get('passwordauthentication', 'unknown')}")
    # The template writes AllowUsers, but an earlier drop-in wins first-match. An
    # empty effective AllowUsers means "everyone may log in" (no problem).
    allowed = set(config.get("allowusers", "").split())
    missing = [name for name in required_users if name not in allowed]
    if allowed and missing:
        effective = " ".join(sorted(allowed))
        problems.append(f"allowusers missing {', '.join(missing)} (effective: {effective})")
    return problems


def _conflict_detail(problems: list[str]) -> str:
    hints = []
    expected = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
    }
    for problem in problems:
        keyword, _, value = problem.partition(" ")
        if keyword in expected and value != expected[keyword]:
            hint = _conflict_hint(keyword, expected[keyword])
            if hint:
                hints.append(hint)
    detail = "sshd -T effective config conflicts with the 99-lhm drop-in: " + ", ".join(problems)
    if hints:
        detail += "; " + "; ".join(dict.fromkeys(hints))
    else:
        detail += (
            "; an earlier sshd_config.d/*.conf or sshd_config line wins"
            " (first obtained value): remove or fix it"
        )
    detail += "; drop-in rolled back, sshd not reloaded"
    return detail


def ensure_privsep_dir() -> bool:
    """Create ``/run/sshd`` (0755 root:root) if missing; True when it exists.

    Idempotent and cheap: sshd needs it before ``-t``/``-T`` will even parse
    the config, and socket-activated units never created it.
    """
    try:
        PRIVSEP_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(PRIVSEP_DIR, 0o755)
    except OSError:
        return PRIVSEP_DIR.is_dir()
    return True


def _verify_hardening(
    runner: Runner, port: int, required_users: Sequence[str] = ()
) -> StepResult:
    ensure_privsep_dir()
    config = checks.sshd_effective_config(runner)
    problems = _effective_problems(config, port, required_users)
    if problems:
        return StepResult("verify", Status.FAIL, "sshd -T: " + ", ".join(problems))
    listening = checks.listening_tcp_ports(runner)
    if port not in listening:
        return StepResult(
            "verify",
            Status.FAIL,
            f"port {port} is not listening (ss -tlnp: "
            + (", ".join(str(value) for value in listening) or "no TCP listeners")
            + ")",
        )
    return StepResult(
        "verify",
        Status.OK,
        f"sshd -T: port {port}, root/password login off; listening on {port}/tcp",
    )


def apply_hardening(
    runner: Runner, *, port: int = DEFAULT_PORT, allow_users: Sequence[str] = ()
) -> list[StepResult]:
    if not 1 <= port <= 65535:
        return [StepResult("ssh-hardening", Status.FAIL, f"invalid port: {port}")]
    requested = list(allow_users)
    invalid = [name for name in requested if not USER_RE.fullmatch(name)]
    if invalid:
        return [
            StepResult("ssh-hardening", Status.FAIL, "invalid user name(s): " + ", ".join(invalid))
        ]

    if requested:
        missing = [name for name in requested if not valid_key_lines(authorized_keys_path(name))]
        if missing:
            return [
                StepResult(
                    "ssh-hardening",
                    Status.FAIL,
                    "refusing: no valid authorized_keys for "
                    + ", ".join(missing)
                    + " (run apply ssh-user first)",
                )
            ]
        names = list(dict.fromkeys(requested))
    else:
        names = users_with_keys()
        if not names:
            return [
                StepResult(
                    "ssh-hardening",
                    Status.FAIL,
                    "refusing: no authorized_keys with a valid public key under /home "
                    "(run apply ssh-user first)",
                )
            ]

    desired = desired_conf(port, names)
    needed = _read_text(SSHD_DROPIN) != desired
    plan = [
        "Plan (ssh-hardening):",
        f"  - allowed users: {' '.join(names)}",
        (
            f"  - write {SSHD_DROPIN} (Port {port}, PermitRootLogin no, "
            "PasswordAuthentication no)"
            if needed
            else f"  - {SSHD_DROPIN} already current (skip)"
        ),
        "  - gate: sshd -t must accept the drop-in before any reload",
        "  - gate: sshd -T effective values must match (earlier drop-ins win)",
        "  - if ssh.socket/sshd.socket is active: disable --now it, then restart ssh",
        "  - else reload ssh (fallback unit: sshd)",
        "  - verify: port must actually listen (ss -tlnp), not just sshd -T",
        "  - risk: password logins stop; keep this session open and test key login first",
    ]

    if runner.dry_run:
        for line in plan:
            print(line)
        runner.run(["sshd", "-t"])
        # Detection is impossible in dry-run: show the worst case (socket unit).
        runner.run(["systemctl", "disable", "--now", SOCKET_UNITS[0]])
        runner.run(["systemctl", "restart", "ssh"])
        runner.run(["ss", "-tlnp"])
        return [
            StepResult(
                f"write {SSHD_DROPIN}",
                Status.PLANNED if needed else Status.SKIPPED,
                "" if needed else "already current",
            ),
            StepResult("sshd -t", Status.PLANNED, "gate"),
            StepResult("sshd -T effective", Status.PLANNED, "gate"),
            StepResult("socket activation", Status.PLANNED, "disable --now if active"),
            StepResult("reload sshd", Status.PLANNED),
        ]

    if not needed:
        ensure_privsep_dir()
        return [
            StepResult(f"write {SSHD_DROPIN}", Status.SKIPPED, "already current"),
            _verify_hardening(runner, port, names),
        ]

    if not confirm_twice(plan):
        return [StepResult("ssh-hardening", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        ensure_privsep_dir()
        outcome = write_dropin(SSHD_DROPIN, desired)
        results.append(
            StepResult(
                f"write {SSHD_DROPIN}",
                Status.CHANGED if outcome == "written" else Status.SKIPPED,
            )
        )
        gate = runner.run(["sshd", "-t"], check=False)
        if not gate.ok:
            restored = _rollback_dropin()
            detail = f"rejected the drop-in (rc={gate.returncode}); {restored}; sshd not reloaded"
            if gate.stderr.strip():
                detail += f"\n{gate.stderr.strip()}"
            results.append(StepResult("sshd -t", Status.FAIL, detail))
            print(f"lhm: rollback hint: lhm rollback {SSHD_DROPIN}", flush=True)
            return results
        results.append(StepResult("sshd -t", Status.OK, "config accepted"))

        # first-obtained-value-wins: an earlier 50-cloud-init.conf can silently
        # override the 99- drop-in, so gate on the effective config BEFORE reload.
        effective = checks.sshd_effective_config(runner)
        conflicts = _effective_problems(effective, port, names)
        if conflicts:
            restored = _rollback_dropin()
            detail = _conflict_detail(conflicts) + f"; {restored}"
            results.append(StepResult("sshd -T effective", Status.FAIL, detail))
            print(f"lhm: rollback hint: lhm rollback {SSHD_DROPIN}", flush=True)
            return results
        results.append(StepResult("sshd -T effective", Status.OK, "port/root/password match"))

        # Debian 12 socket activation: ssh.socket owns the listener (Port 22), so
        # the Port drop-in only takes effect once the socket unit is disabled.
        socket_unit = _socket_active(runner)
        if socket_unit is not None:
            runner.run(["systemctl", "disable", "--now", socket_unit])
            results.append(
                StepResult("disable ssh.socket", Status.CHANGED, f"disabled --now {socket_unit}")
            )
            unit = _restart(runner)
            action = "restarted"
        else:
            unit = _reload(runner)
            action = "reloaded"
        if unit is None:
            if socket_unit is not None:
                _recover_socket_after_restart_failure(runner, socket_unit, results)
                return results
            results.append(
                StepResult(
                    "reload sshd",
                    Status.FAIL,
                    f"systemctl {action} failed for ssh and sshd",
                )
            )
            return results
        results.append(StepResult("reload sshd", Status.CHANGED, f"{action} {unit}"))
    except (CommandError, OSError) as exc:
        results.append(StepResult("ssh-hardening", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {SSHD_DROPIN}", flush=True)
        return results

    results.append(_verify_hardening(runner, port, names))
    return results


def inspect(runner: Runner, *, port: int = DEFAULT_PORT) -> dict[str, object]:
    """Read-only state used by ``check``."""
    names = users_with_keys()
    effective = checks.sshd_effective_config(runner)
    return {
        "dropin": str(SSHD_DROPIN),
        "dropin_present": _read_text(SSHD_DROPIN) is not None,
        "dropin_current": _read_text(SSHD_DROPIN) == desired_conf(port, names),
        "authorized_users": names,
        "effective": {
            key: effective.get(key, "unavailable")
            for key in ("port", "permitrootlogin", "passwordauthentication")
        },
    }


class SshModule:
    name = "ssh"
    description = "Create admin user, authorized_keys, sshd drop-in on port 22345"
    implemented = True

    def apply(
        self,
        runner: Runner,
        *,
        command: str = "",
        user: str = "",
        key: str = "",
        sudo: bool = False,
        port: int = DEFAULT_PORT,
        allow_users: Sequence[str] = (),
    ) -> list[StepResult]:
        if command == "ssh-user":
            return apply_user(runner, user=user, key_file=key, sudo=sudo)
        if command == "ssh-hardening":
            return apply_hardening(runner, port=port, allow_users=allow_users)
        return [
            StepResult(
                "ssh",
                Status.FAIL,
                "choose 'lhm apply ssh-user NAME --key FILE' or 'lhm apply ssh-hardening'",
            )
        ]
