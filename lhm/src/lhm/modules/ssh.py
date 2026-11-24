"""SSH module: admin user with authorized_keys, then the hardened sshd drop-in."""

import base64
import binascii
import errno
import os
import re
import stat
import struct
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from os import geteuid
from pathlib import Path
from time import monotonic

from lhm.core import checks, userkeys
from lhm.core.backup import rollback_file
from lhm.core.confirm import confirm_once
from lhm.core.files import (
    ensure_dir,
    locked_target,
    notify_file_change,
    remove_file,
    render_template,
    write_dropin,
)
from lhm.core.mutations import mutations_allowed
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner
from lhm.modules import ssh_auth, ssh_session, ssh_watchdog

TEMPLATE = "ssh-hardening.conf.tmpl"
# First shipped layout, before the explicit authentication and key-path settings.
_LEGACY_TEMPLATE = """# ===== lhm ssh hardening drop-in =====
# Managed by lhm. Remove this file to revert. sshd_config.d drop-ins take
# precedence over the main sshd_config (first obtained value wins).
Port {port}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 4
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
AllowUsers {allow_users}
"""
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/99-lhm.conf")
_SSHD_DROPIN_UID = 0
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
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_KEY_LINE_BYTES = 16 * 1024
_KEY_WHITESPACE = " \t"
SOCKET_UNITS = ("ssh.socket", "sshd.socket")
SERVICE_UNITS = ("ssh.service", "sshd.service")
_UNIT_STATES = ("enabled", "enabled-runtime", "static", "disabled")
_RETRY = 75

# SEC 2 NIST domain parameters: coordinate size, field prime, and coefficient b (a = -3).
_ECDSA_CURVES = {
    "nistp256": (
        32,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    ),
    "nistp384": (
        48,
        (1 << 384) - (1 << 128) - (1 << 96) + (1 << 32) - 1,
        int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC6"
            "56398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
    ),
    "nistp521": (
        66,
        (1 << 521) - 1,
        int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109"
            "E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            16,
        ),
    ),
}


class SshError(ValueError):
    """Raised when the user name or public key is not acceptable."""


class _RecoveryDeferred(SshError):
    """Recovery could not safely complete on this attempt."""


def _retryable_recovery_error(exc: Exception) -> bool:
    if isinstance(exc, ssh_watchdog.WatchdogError) and isinstance(exc.__cause__, OSError):
        exc = exc.__cause__
    return isinstance(exc, _RecoveryDeferred) or (
        isinstance(exc, OSError)
        and exc.errno
        not in {
            errno.EACCES,
            errno.EPERM,
            errno.ELOOP,
            errno.ENOTDIR,
            errno.EISDIR,
            errno.EINVAL,
            errno.EROFS,
        }
    )


def _ecdsa_point_ok(curve: str, point: bytes) -> bool:
    size, p, b = _ECDSA_CURVES[curve]
    if len(point) != 2 * size + 1 or point[0] != 4:
        return False
    x = int.from_bytes(point[1 : 1 + size])
    y = int.from_bytes(point[1 + size :])
    # These curves have cofactor 1; any finite point on the curve is in the subgroup.
    return x < p and y < p and (y * y - x * x * x + 3 * x - b) % p == 0


def _key_blob_ok(key_type: str, blob: str) -> bool:
    """Parse the complete RFC 4251 length-prefixed OpenSSH public key."""
    if len(blob) > 8192:
        return False
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return False
    offset = 0

    def field() -> bytes:
        nonlocal offset
        (size,) = struct.unpack_from(">I", raw, offset)
        offset += 4
        end = offset + size
        if end > len(raw):
            raise ValueError("truncated SSH string")
        value = raw[offset:end]
        offset = end
        return value

    def positive_mpint() -> int:
        value = field()
        if not value or value[0] & 0x80:
            raise ValueError("not a positive SSH integer")
        if value[0] == 0 and (len(value) == 1 or not value[1] & 0x80):
            raise ValueError("non-canonical SSH integer")
        return int.from_bytes(value)

    try:
        if field() != key_type.encode("ascii"):
            return False
        if key_type == "ssh-rsa":
            exponent, modulus = positive_mpint(), positive_mpint()
            if not (3 <= exponent < modulus and exponent % 2 and modulus % 2):
                return False
            if not 1024 <= modulus.bit_length() <= 16384:
                return False
        elif "ed25519" in key_type:
            key = field()
            if len(key) != 32 or not any(key):
                return False
        else:
            curve = key_type.removesuffix("@openssh.com").rsplit("-", 1)[-1]
            if field() != curve.encode("ascii"):
                return False
            if not _ecdsa_point_ok(curve, field()):
                return False
        if key_type.startswith("sk-"):
            application = field()
            if not application or b"\0" in application:
                return False
        return offset == len(raw)
    except (struct.error, ValueError):
        return False


def _strip_key_line(line: str) -> str:
    return line.removesuffix("\r").strip(_KEY_WHITESPACE)


def is_pubkey_line(line: str) -> bool:
    """Validate an OpenSSH ``type base64 [comment]`` record and its key blob."""
    stripped = _strip_key_line(line)
    if not stripped or stripped.startswith("#"):
        return False
    if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in stripped):
        return False
    parts = re.split(r"[ \t]+", stripped, maxsplit=2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        return False
    return _key_blob_ok(parts[0], parts[1])


def _parse_pubkey(text: str) -> str:
    for line in text.split("\n"):
        stripped = _strip_key_line(line)
        if not stripped or stripped.startswith("#"):
            continue
        if not is_pubkey_line(line):
            raise SshError("refusing: --key does not look like an SSH public key")
        if len(stripped.encode("utf-8")) > _MAX_KEY_LINE_BYTES:
            raise SshError("refusing: public key line exceeds the size limit")
        return stripped
    raise SshError("refusing: --key contains no public key")


def _sudo_invoker(runner: Runner, *, operation: str = "--key") -> userkeys.Account | None:
    name = os.environ.get("SUDO_USER")
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if (name, uid, gid) in {(None, None, None), ("root", "0", "0")}:
        return None
    if not name or not uid or not gid or not all(
        re.fullmatch(r"[0-9]{1,10}", value) for value in (uid, gid)
    ):
        raise SshError(f"refusing {operation}: incomplete or invalid sudo invoker identity")
    account = userkeys.lookup_account(runner, name)
    if account is None or (account.uid, account.gid) != (int(uid), int(gid)):
        raise SshError(f"refusing {operation}: sudo invoker does not match its passwd record")
    return account


def _read_key_leaf(path: str | Path, *, parent: int | None = None) -> str:
    before = os.stat(path, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise SshError("refusing --key: source must be a regular nonsymlink file")
    if parent is not None and (before.st_uid != 0 or before.st_mode & 0o022):
        raise SshError(
            "refusing --key as root: source must be root-owned and not writable by others"
        )

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise SshError("refusing --key: source changed while opening")
        if opened.st_size > _MAX_SOURCE_BYTES:
            raise SshError("refusing --key: source exceeds the size limit")
        data = source.read(_MAX_SOURCE_BYTES + 1)
        if len(data) > _MAX_SOURCE_BYTES:
            raise SshError("refusing --key: source exceeds the size limit")
    return data.decode("utf-8")


def _read_root_key_source(path: Path) -> str:
    parts = path.absolute().parts[1:]
    if not parts or ".." in parts:
        raise SshError("refusing --key as root: use a file path without '..'")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open("/", flags)
    try:
        for part in (*parts[:-1], None):
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise SshError(
                    "refusing --key as root: source directories must be root-owned "
                    "and not writable by others"
                )
            if part is None:
                break
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return _read_key_leaf(parts[-1], parent=directory)
    finally:
        os.close(directory)


def _import_pubkey(runner: Runner, path: str) -> str:
    try:
        if geteuid() != 0:
            text = _read_key_leaf(path)
        elif (invoker := _sudo_invoker(runner)) is not None:
            text = userkeys.read_public_key_source(runner, invoker, path)
        else:
            text = _read_root_key_source(Path(path))
    except userkeys.UserKeysError as exc:
        raise SshError(f"refusing --key: {exc}") from None
    except SshError:
        raise
    except (OSError, ValueError):
        raise SshError("cannot read --key: use a safe, nonsymlink UTF-8 public key file") from None
    return _parse_pubkey(text)


def _has_login_key(runner: Runner, account: userkeys.Account) -> bool:
    state = userkeys.probe_keys(runner, account)
    return (
        state.ssh_ready
        and state.keys_mode is not None
        and (state.keys_mode & 0o400) != 0
        and (state.keys_mode & 0o022) == 0
        and any(is_pubkey_line(line) for line in (state.content or "").split("\n"))
    )


def _require_account_key(
    runner: Runner, name: str, *, expected: userkeys.Account | None = None
) -> userkeys.Account:
    try:
        account = userkeys.lookup_account(runner, name)
        if expected is not None and account != expected:
            raise SshError("account identity changed")
        if account is None:
            raise SshError("account not found")
        if not _has_login_key(runner, account):
            raise SshError("no valid authorized_keys in a private .ssh directory")
    except (SshError, userkeys.UserKeysError) as exc:
        raise SshError(f"refusing {name}: {exc} (run apply ssh-user first)") from exc
    return account


def _accounts_with_keys(runner: Runner) -> list[userkeys.Account]:
    """Discover passwd accounts at nonsymlink direct children of HOME_ROOT."""
    try:
        with os.scandir(HOME_ROOT) as entries:
            candidates = sorted(
                entry.name
                for entry in entries
                if USER_RE.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False)
            )
    except OSError:
        return []
    accounts: list[userkeys.Account] = []
    for name in candidates:
        try:
            account = userkeys.lookup_account(runner, name)
            if account and account.home == HOME_ROOT / name and _has_login_key(runner, account):
                accounts.append(account)
        except userkeys.UserKeysError:
            continue
    return accounts


def users_with_keys(runner: Runner) -> list[str]:
    return [account.name for account in _accounts_with_keys(runner)]


def desired_conf(port: int = DEFAULT_PORT, allow_users: Sequence[str] = ()) -> str:
    return render_template(TEMPLATE, port=str(port), allow_users=" ".join(allow_users))


def _managed_allow_users(snapshot: bytes) -> list[str]:
    try:
        text = snapshot.decode("utf-8")
    except UnicodeDecodeError:
        raise SshError(f"refusing SSH drop-in with invalid UTF-8: {SSHD_DROPIN}") from None
    port_line = re.search(r"^Port ([0-9]{1,5})$", text, re.MULTILINE)
    users_line = re.search(r"^AllowUsers (.+)$", text, re.MULTILINE)
    if port_line and users_line:
        port = int(port_line[1])
        names = users_line[1].split(" ")
        if 1 <= port <= 65535 and all(USER_RE.fullmatch(name) for name in names):
            # A full comparison rejects extra directives, Match blocks and hand edits.
            if text in (
                desired_conf(port, names),
                _LEGACY_TEMPLATE.format(port=port, allow_users=" ".join(names)),
            ):
                return names
    raise SshError(f"refusing to overwrite unrecognized SSH drop-in: {SSHD_DROPIN}")


def _account_command(runner: Runner, argv: list[str], action: str) -> str:
    try:
        result = runner.run(argv, check=False)
    except (OSError, ValueError):
        raise SshError(f"{action} could not execute") from None
    if not result.ok:
        raise SshError(f"{action} failed (rc={result.returncode})")
    return result.stdout


def _verify_installed_key(runner: Runner, account: userkeys.Account, key_line: str) -> None:
    state = userkeys.probe_keys(runner, account)
    if not state.ssh_ready or state.keys_mode != 0o600:
        raise SshError("could not verify .ssh and authorized_keys modes (0700/0600)")
    installed = (state.content or "").split("\n")
    if not any(_strip_key_line(line) == key_line for line in installed):
        raise SshError("key not in authorized_keys after installation")
    if userkeys.lookup_account(runner, account.name) != account:
        raise SshError("account identity changed during key installation")


def apply_user(runner: Runner, *, user: str, key_file: str, sudo: bool = False) -> list[StepResult]:
    if not USER_RE.fullmatch(user):
        return [StepResult("ssh-user", Status.FAIL, f"invalid user name: {user!r}")]
    if not key_file:
        return [StepResult("ssh-user", Status.FAIL, "--key requires a public key file")]

    create_step = f"create user {user}"
    sudo_step = f"add {user} to sudo"
    if runner.dry_run:
        print("Plan (ssh-user): account and --key validation deferred until live apply")
        results = [
            StepResult(create_step, Status.PLANNED, "if missing"),
            StepResult("install authorized_keys", Status.PLANNED, "passwd home; modes 0700/0600"),
        ]
        if sudo:
            results.append(StepResult(sudo_step, Status.PLANNED, "after key verification"))
        return results

    try:
        key_line = _import_pubkey(runner, key_file)
        prior = userkeys.lookup_account(runner, user)
    except (SshError, userkeys.UserKeysError) as exc:
        return [StepResult("ssh-user", Status.FAIL, str(exc))]

    plan = [
        "Plan (ssh-user):",
        f"  - user {user} exists (skip useradd)"
        if prior
        else f"  - create user {user} (home + /bin/bash)",
        f"  - ensure .ssh/authorized_keys in {prior.home if prior else 'the new passwd home'} "
        f"as {user} (0700/0600)",
    ]
    if sudo:
        plan.append(f"  - add {user} to the sudo group after key verification")
    if not confirm_once(plan):
        return [StepResult("ssh-user", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    step = create_step
    try:
        if prior is None:
            _account_command(
                runner, ["useradd", "--create-home", "--shell", "/bin/bash", user], step
            )
            results.append(StepResult(step, Status.CHANGED))
        step = "verify account"
        account = userkeys.lookup_account(runner, user)
        if account is None:
            detail = "account missing after useradd" if prior is None else "account disappeared"
            raise SshError(detail)
        if prior is not None:
            if account != prior:
                raise SshError("account identity changed during confirmation; rerun to review it")
            results.append(StepResult(create_step, Status.SKIPPED, "exists"))
        step = f"install {account.home / '.ssh' / 'authorized_keys'}"
        changed = userkeys.ensure_key(runner, account, key_line)
        results.append(
            StepResult(step, Status.CHANGED if changed else Status.SKIPPED, "modes 0700/0600")
        )
        step = "verify"
        _verify_installed_key(runner, account, key_line)
        if sudo:
            step = sudo_step
            query = ["id", "-nG", user]
            groups = _account_command(runner, query, "sudo membership check").split()
            if "sudo" in groups:
                results.append(StepResult(step, Status.SKIPPED, "already member"))
            else:
                _account_command(runner, ["usermod", "-aG", "sudo", user], step)
                if "sudo" not in _account_command(runner, query, "sudo membership check").split():
                    raise SshError("sudo membership not verified")
                results.append(StepResult(step, Status.CHANGED))
    except (SshError, userkeys.UserKeysError) as exc:
        results.append(StepResult(step, Status.FAIL, str(exc)))
        return results

    results.append(StepResult("verify", Status.OK, f"verified authorized_keys for {user}"))
    return results


def _rollback_dropin(snapshot: bytes | None, candidate: bytes, backup: Path | None) -> StepResult:
    step = "restore ssh drop-in"
    current = _dropin_snapshot()
    if current == snapshot:
        return StepResult(step, Status.SKIPPED, "pre-change drop-in already in place")
    if current != candidate:
        raise SshError("SSH drop-in differs from this run's candidate; left untouched")
    if snapshot is not None:
        if backup is None or _dropin_snapshot(backup) != snapshot:
            raise SshError("this run's SSH backup is missing or changed; drop-in left untouched")
        if _dropin_snapshot() != candidate:
            raise SshError("SSH drop-in changed during recovery; left untouched")
        rollback_file(SSHD_DROPIN, backup=backup)
        detail = f"restored {backup.name}"
    else:
        remove_file(SSHD_DROPIN)
        notify_file_change("deleted", SSHD_DROPIN, old=candidate.decode("utf-8"))
        detail = "removed the new drop-in"
    if _dropin_snapshot() != snapshot:
        raise SshError("restored SSH drop-in could not be verified")
    return StepResult(step, Status.CHANGED, detail)


def _require_original_dropin(snapshot: bytes | None) -> None:
    if _dropin_snapshot() != snapshot:
        raise SshError("SSH drop-in changed during recovery; left untouched")


def _unit_active(runner: Runner, unit: str, *, absent_is_inactive: bool = False) -> bool | None:
    result = runner.run(["systemctl", "is-active", unit], check=False)
    state = result.stdout.strip()
    if result.ok and state == "active":
        return True
    if result.returncode == 3 and state in {"inactive", "failed"}:
        return False
    # systemctl reports an absent unit as inactive, with LSB exit status 4.
    if absent_is_inactive and result.returncode == 4 and state == "inactive":
        return False
    return None


def _find_active_unit(runner: Runner, units: Sequence[str]) -> str | None:
    for unit in units:
        active = _unit_active(runner, unit, absent_is_inactive=True)
        if active is None:
            raise SshError(f"refusing to change SSH: cannot determine whether {unit} is active")
        if active:
            return unit
    return None


def _unit_enablement(runner: Runner, unit: str) -> str:
    result = runner.run(["systemctl", "is-enabled", unit], check=False)
    state = result.stdout.strip()
    if result.ok and state in {"enabled", "enabled-runtime", "static"}:
        return state
    if result.returncode == 1 and state == "disabled":
        return state
    detail = f"cannot determine {unit} enablement ({state!r})"
    if result.returncode in {0, 1, 4} and state in {
        "alias",
        "bad",
        "generated",
        "indirect",
        "linked",
        "linked-runtime",
        "masked",
        "masked-runtime",
        "not-found",
        "transient",
    }:
        raise SshError(detail)
    raise _RecoveryDeferred(detail)


def _loaded_unit_id(
    runner: Runner, name: str, units: Sequence[str], *, recovery: bool = False
) -> str | None:
    result = runner.run(
        ["systemctl", "show", "--property=Id", "--property=LoadState", name],
        check=False,
    )
    props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    unit = props.get("Id", "")
    load = props.get("LoadState")
    if recovery and not (
        (result.ok and unit and load) or (result.returncode in {1, 4} and load == "not-found")
    ):
        raise _RecoveryDeferred(f"cannot query the loaded unit for {name}")
    return unit if result.ok and load == "loaded" and unit in units else None


def _socket_service(runner: Runner, socket_unit: str, *, recovery: bool = False) -> str:
    trigger = runner.run(
        ["systemctl", "show", "--property=Triggers", "--value", socket_unit], check=False
    )
    if recovery and not trigger.ok:
        raise _RecoveryDeferred(f"cannot query the trigger for {socket_unit}")
    name = trigger.stdout.strip()
    if trigger.ok and name in SERVICE_UNITS:
        unit = _loaded_unit_id(runner, name, SERVICE_UNITS, recovery=recovery)
        if unit is not None:
            return unit
    raise SshError(
        f"refusing socket conversion: cannot identify the loaded SSH service for {socket_unit}"
    )


def _enable_flags(state: str) -> list[str]:
    return ["--runtime"] if state == "enabled-runtime" else []


@dataclass(frozen=True)
class _SocketConversion:
    socket: str
    service: str
    socket_state: str
    service_state: str

    @property
    def socket_enabled(self) -> bool:
        return self.socket_state in {"enabled", "enabled-runtime"}

    @property
    def service_target(self) -> str:
        if self.socket_enabled and self.service_state != "enabled":
            return self.socket_state
        return self.service_state


def _socket_conversion(runner: Runner, socket_unit: str) -> _SocketConversion:
    # list-jobs reports the job's canonical unit ID, not the activation alias.
    canonical_socket = _loaded_unit_id(runner, socket_unit, SOCKET_UNITS)
    if canonical_socket is None:
        raise SshError(f"refusing socket conversion: cannot identify the loaded {socket_unit}")
    socket_unit = canonical_socket
    socket_state = _unit_enablement(runner, socket_unit)
    service = _socket_service(runner, socket_unit)
    service_state = _unit_enablement(runner, service)
    conversion = _SocketConversion(socket_unit, service, socket_state, service_state)
    if conversion.socket_enabled and service_state == "static":
        raise SshError(f"refusing socket conversion: {service} is static and cannot be enabled")
    return conversion


def _endpoints_restored(
    previous: set[checks.SshEndpoint], current: set[checks.SshEndpoint] | None
) -> bool:
    return bool(previous and current and previous <= current)


def _no_unit_jobs(runner: Runner, *units: str) -> bool:
    jobs = runner.run(["systemctl", "list-jobs", "--no-legend", "--no-pager", *units], check=False)
    return jobs.ok and not jobs.stdout.strip()


def _require_idle_ssh_units(
    runner: Runner, unit: str, conversion: _SocketConversion | None
) -> None:
    units = (conversion.socket, unit) if conversion is not None else (unit,)
    if not _no_unit_jobs(runner, *units):
        raise SshError(
            "refusing to change SSH: pending jobs or unverifiable job state for " + ", ".join(units)
        )


def _recovery_hint(detail: str) -> None:
    try:
        print(f"lhm: {detail}", file=sys.stderr, flush=True)
    except OSError:
        pass


def _socket_recovery_enablement(
    runner: Runner,
    conversion: _SocketConversion,
    *,
    socket_disable_attempted: bool,
    service_enable_attempted: bool,
) -> tuple[str, str]:
    socket_unit, service = conversion.socket, conversion.service
    socket_state = _unit_enablement(runner, socket_unit)
    service_state = _unit_enablement(runner, service)
    if socket_state != conversion.socket_state and not (
        socket_disable_attempted and socket_state == "disabled"
    ):
        raise SshError(f"{socket_unit} enablement changed externally; left untouched")
    if service_state != conversion.service_state and not (
        service_enable_attempted and service_state == conversion.service_target
    ):
        raise SshError(f"{service} enablement changed externally; left untouched")
    return socket_state, service_state


def _require_socket_identity(runner: Runner, conversion: _SocketConversion) -> None:
    socket_unit, service = conversion.socket, conversion.service
    if (
        _loaded_unit_id(runner, socket_unit, SOCKET_UNITS, recovery=True) != socket_unit
        or _socket_service(runner, socket_unit, recovery=True) != service
    ):
        raise SshError(f"{socket_unit} or its trigger changed externally; left untouched")


def _require_recovery_idle(runner: Runner, *units: str) -> None:
    if not _no_unit_jobs(runner, *units):
        raise _RecoveryDeferred("SSH jobs pending or unverifiable")


def _recovery_active(runner: Runner, unit: str) -> bool:
    active = _unit_active(runner, unit)
    if active is None:
        raise _RecoveryDeferred(f"cannot determine whether {unit} is active")
    return active


def _validate_restored_sshd(runner: Runner) -> None:
    if not ensure_privsep_dir():
        raise SshError(f"unsafe sshd privilege separation directory: {PRIVSEP_DIR}")
    result = runner.run(["sshd", "-t"], check=False)
    if not result.ok:
        # sshd does not distinguish syntax errors from temporarily unavailable
        # prerequisites in its exit status. Do not touch the daemon on either.
        raise _RecoveryDeferred(f"restored sshd config did not validate (rc={result.returncode})")


def _require_socket_listener(
    runner: Runner, socket_unit: str, expected: set[checks.SshEndpoint]
) -> None:
    endpoints = checks.live_ssh_endpoints(runner, socket_unit=socket_unit)
    if endpoints == expected:
        return
    if endpoints is None:
        endpoints = checks.socket_listen_endpoints(runner, socket_unit)
    if endpoints is not None and endpoints != expected:
        raise SshError(f"{socket_unit} configured endpoints differ from the original listeners")
    raise _RecoveryDeferred(f"{socket_unit} previous listener not verified")


def _restore_socket_runtime(
    runner: Runner,
    conversion: _SocketConversion,
    expected: set[checks.SshEndpoint],
    warnings: list[str],
    *,
    snapshot: bytes | None,
    restart_attempted: bool,
    disk_restored: bool,
    fallback_attempted: bool,
    record_fallback: Callable[[], None],
) -> None:
    socket_unit, service = conversion.socket, conversion.service
    stopped_idle = (False, False)
    standalone_idle = (False, True)

    def state() -> tuple[bool, bool]:
        active = (
            _recovery_active(runner, socket_unit),
            _recovery_active(runner, service),
        )
        _require_recovery_idle(runner, socket_unit, service)
        return active

    def cached_endpoints() -> set[checks.SshEndpoint]:
        endpoints = checks.socket_listen_endpoints(runner, socket_unit)
        if endpoints is None:
            raise _RecoveryDeferred("cached socket endpoints not verified")
        return endpoints

    current = state()
    reload_failed = False
    if disk_restored and current in (stopped_idle, standalone_idle):
        reload_failed = not runner.run(["systemctl", "daemon-reload"], check=False).ok
        if reload_failed:
            warnings.append("daemon-reload failed")
        _require_socket_identity(runner, conversion)
        current = state()
    if current == standalone_idle:
        if fallback_attempted:
            raise SshError(f"left rollback fallback {service} running")
        # Keep the daemon up unless we have a verified disk rollback and a known socket
        # to hand off to. A pending job on either unit is not ours to replace.
        if not restart_attempted:
            raise SshError(f"left standalone {service} running; safe socket handoff not verified")
        if not disk_restored:
            raise _RecoveryDeferred(f"left standalone {service} running; old config not verified")
        if cached_endpoints() != expected:
            error = _RecoveryDeferred if reload_failed else SshError
            raise error(f"left standalone {service} running; socket endpoints differ")
        _validate_restored_sshd(runner)
        _require_socket_identity(runner, conversion)
        if cached_endpoints() != expected:
            raise SshError(f"left standalone {service} running; socket endpoints changed")
        if state() != standalone_idle:
            raise _RecoveryDeferred(f"left {service} untouched; socket handoff state changed")
        _require_original_dropin(snapshot)
        stopped = runner.run(["systemctl", "stop", "--job-mode=fail", service], check=False)
        if not stopped.ok:
            warnings.append(f"could not stop the standalone {service}")
        current = state()
        if not stopped.ok and current != stopped_idle:
            raise _RecoveryDeferred(f"{service} stop not verified")
    if current != stopped_idle:
        return

    # A failed reload (or disk rollback) can leave the original socket cached in PID 1.
    socket_matches = cached_endpoints() == expected
    if not socket_matches:
        # PID 1 may still have candidate endpoints if disk rollback failed and
        # daemon-reload was skipped. That is not evidence of external drift.
        if disk_restored and not reload_failed:
            raise SshError("cached socket endpoints do not match the original listeners")
        warnings.append("cached socket endpoints do not match the original listeners")
    start_failed = False
    if socket_matches and state() == stopped_idle:
        start_failed = not runner.run(
            ["systemctl", "start", "--job-mode=fail", socket_unit], check=False
        ).ok
        if start_failed:
            warnings.append(f"could not start {socket_unit}")
    if disk_restored and state() == stopped_idle:
        _validate_restored_sshd(runner)
        if state() == stopped_idle:
            _require_original_dropin(snapshot)
            # A retry must not confuse this recovery's fallback with a migrated
            # daemon and tear it down while restoring the original socket.
            record_fallback()
            fallback = runner.run(
                ["systemctl", "start", "--job-mode=fail", service], check=False
            ).ok
            outcome = "requested" if fallback else "failed"
            warnings.append(f"fallback service start {outcome}")
            if not fallback:
                raise _RecoveryDeferred(f"fallback service start failed for {service}")
            if _unit_active(runner, service) is True and _endpoints_restored(
                expected, checks.live_ssh_endpoints(runner)
            ):
                warnings.append(f"{service} listening on the original endpoints")
    if start_failed or not socket_matches:
        raise _RecoveryDeferred(f"{socket_unit} start not verified")


def _recover_socket(
    runner: Runner,
    conversion: _SocketConversion,
    expected: set[checks.SshEndpoint],
    results: list[StepResult],
    *,
    snapshot: bytes | None,
    restart_attempted: bool,
    socket_disable_attempted: bool,
    service_enable_attempted: bool,
    disk_restored: bool,
    preactivation: bool,
    fallback_attempted: bool,
    record_fallback: Callable[[], None],
) -> int:
    socket_unit, service = conversion.socket, conversion.service
    warnings: list[str] = []
    problems: list[Exception] = []

    def enablement() -> tuple[str, str]:
        return _socket_recovery_enablement(
            runner,
            conversion,
            socket_disable_attempted=socket_disable_attempted,
            service_enable_attempted=service_enable_attempted,
        )

    def verify_enablement() -> None:
        if enablement() != (conversion.socket_state, conversion.service_state):
            raise _RecoveryDeferred("original SSH socket/service enablement not restored")

    try:
        _require_socket_identity(runner, conversion)
        enablement()
        if not preactivation:
            try:
                _restore_socket_runtime(
                    runner,
                    conversion,
                    expected,
                    warnings,
                    snapshot=snapshot,
                    restart_attempted=restart_attempted,
                    disk_restored=disk_restored,
                    fallback_attempted=fallback_attempted,
                    record_fallback=record_fallback,
                )
            except (CommandError, OSError, ValueError) as exc:
                problems.append(exc)
        # Restore links without an implicit daemon-reload or a runtime job.
        _require_socket_identity(runner, conversion)
        socket_state, service_state = enablement()
        if socket_state != conversion.socket_state:
            runner.run(
                [
                    "systemctl",
                    "enable",
                    "--no-reload",
                    *_enable_flags(conversion.socket_state),
                    socket_unit,
                ],
                check=False,
            )
            socket_state, service_state = enablement()
            if socket_state != conversion.socket_state:
                raise _RecoveryDeferred(f"{socket_unit} original enablement not restored")
        if service_state != conversion.service_state:
            runner.run(
                ["systemctl", "disable", "--no-reload", *_enable_flags(service_state), service],
                check=False,
            )
        verify_enablement()
    except (CommandError, OSError, ValueError) as exc:
        problems.append(exc)

    if not problems:
        try:
            _require_recovery_idle(runner, socket_unit, service)
            if not _recovery_active(runner, socket_unit):
                error = SshError if preactivation else _RecoveryDeferred
                raise error(f"{socket_unit} not active; previous listener not verified")
            _require_socket_listener(runner, socket_unit, expected)
            _require_recovery_idle(runner, socket_unit, service)
            if _recovery_active(runner, service):
                # A connection could have activated sshd while the candidate was on disk.
                # Keep the original socket listening; only reload its positively identified
                # service after verifying the original config and rechecking the guard.
                if not disk_restored:
                    raise _RecoveryDeferred(f"old config not verified; left {service} untouched")
                _validate_restored_sshd(runner)
                _require_socket_identity(runner, conversion)
                verify_enablement()
                if not _recovery_active(runner, socket_unit):
                    raise _RecoveryDeferred(f"{socket_unit} became inactive before reload")
                _require_socket_listener(runner, socket_unit, expected)
                active = _recovery_active(runner, service)
                _require_recovery_idle(runner, socket_unit, service)
                if active:
                    _require_original_dropin(snapshot)
                    if not runner.run(
                        ["systemctl", "reload", "--job-mode=fail", service], check=False
                    ).ok:
                        raise _RecoveryDeferred(f"{service} reload not verified")
                    _require_socket_identity(runner, conversion)
                    if not _recovery_active(runner, socket_unit):
                        raise _RecoveryDeferred(f"{socket_unit} not active after reload")
                    _require_socket_listener(runner, socket_unit, expected)
                    if not _recovery_active(runner, service):
                        raise _RecoveryDeferred(f"{service} not active after reload")
                    verify_enablement()
                    warnings.append(f"reloaded {service}")
            _require_recovery_idle(runner, socket_unit, service)
        except (CommandError, OSError, ValueError) as exc:
            problems.append(exc)
    if not problems:
        ports = sorted({port for _, port in expected})
        detail = f"{socket_unit} active; live SSH port(s): {', '.join(map(str, ports))}"
        detail += "; original enablement verified"
        if not disk_restored:
            warnings.append("SSH drop-in rollback failed; old config not verified")
        detail = "; ".join([detail, *warnings])
        results.append(StepResult("restore ssh.socket", Status.CHANGED, detail))
        return 0
    detail = f"{socket_unit}: {'; '.join([*warnings, *(str(exc) for exc in problems)])}"
    results.append(StepResult("restore ssh.socket", Status.FAIL, detail))
    restore_action = (
        ["enable", *_enable_flags(conversion.socket_state), "--now"]
        if conversion.socket_enabled
        else ["start"]
    )
    manual = " ".join(["systemctl", *restore_action, socket_unit])
    _recovery_hint(
        f"SSH may be DOWN: from the console verify the SSH config and check "
        f"{socket_unit}/{service} for pending jobs before running "
        f"`systemctl daemon-reload`, then `{manual}`; "
        "use `ss -tlnp` to confirm the original SSH listener"
    )
    return _RETRY if all(_retryable_recovery_error(exc) for exc in problems) else 1


def _recover_service(
    runner: Runner,
    unit: str,
    service_state: str,
    expected: set[checks.SshEndpoint],
    results: list[StepResult],
    *,
    snapshot: bytes | None,
    disk_restored: bool,
) -> int:
    def verify_unit() -> None:
        if _loaded_unit_id(runner, unit, SERVICE_UNITS, recovery=True) != unit:
            raise SshError(f"cannot identify the original loaded {unit}")
        if _unit_enablement(runner, unit) != service_state:
            raise SshError(f"{unit} enablement changed externally; left untouched")

    try:
        if not disk_restored:
            raise _RecoveryDeferred(
                "SSH drop-in rollback failed; live service left untouched; old config not verified"
            )
        verify_unit()
        _validate_restored_sshd(runner)
        active = _recovery_active(runner, unit)
        _require_recovery_idle(runner, unit)
        action = "reload" if active else "start"
        _require_original_dropin(snapshot)
        if not runner.run(["systemctl", action, "--job-mode=fail", unit], check=False).ok:
            raise _RecoveryDeferred(f"{unit} {action} not verified")
        verify_unit()
        if not _recovery_active(runner, unit) or checks.live_ssh_endpoints(runner) != expected:
            raise _RecoveryDeferred(f"{unit} previous listener not verified")
        _require_recovery_idle(runner, unit)
    except (CommandError, OSError, ValueError) as exc:
        results.append(StepResult("restore ssh listener", Status.FAIL, str(exc)))
        _recovery_hint(
            f"SSH recovery not verified; use the local console to check {unit} and `ss -tlnp`"
        )
        return _RETRY if _retryable_recovery_error(exc) else 1
    outcome = "reloaded" if active else "started"
    detail = f"{outcome} {unit}; original listener and enablement verified"
    results.append(StepResult("restore ssh listener", Status.CHANGED, detail))
    return 0


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
    detail += "; sshd not reloaded"
    return detail


def ensure_privsep_dir() -> bool:
    """Prepare the sshd privilege-separation directory, without following its leaf.

    The live CLI/worker run as root. An unsafe leaf is refused; I/O failures
    propagate so recovery can distinguish transient errors from manual conflicts.
    """
    try:
        info = PRIVSEP_DIR.lstat()
    except FileNotFoundError:
        ensure_dir(PRIVSEP_DIR, mode=0o755)
        info = PRIVSEP_DIR.lstat()
    uid = os.geteuid()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        return False
    fd = os.open(PRIVSEP_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        identity = (info.st_dev, info.st_ino)
        if (opened.st_dev, opened.st_ino) != identity:
            raise OSError(errno.ESTALE, "sshd privilege separation directory changed", PRIVSEP_DIR)
        if opened.st_uid != uid or opened.st_mode & 0o022:
            return False
        if stat.S_IMODE(opened.st_mode) != 0o755 and mutations_allowed():
            os.fchmod(fd, 0o755)
        current = PRIVSEP_DIR.lstat()
        if (current.st_dev, current.st_ino) != identity:
            raise OSError(errno.ESTALE, "sshd privilege separation directory changed", PRIVSEP_DIR)
        return current.st_uid == uid and stat.S_IMODE(current.st_mode) == 0o755
    finally:
        os.close(fd)


def _admin_key_gate(
    runner: Runner, port: int, accounts: Sequence[userkeys.Account]
) -> StepResult:
    step = "sshd -T admin keys"
    if not accounts:
        return StepResult(step, Status.FAIL, "no administrator with verified keys selected")
    ssh_connection = os.environ.get("SSH_CONNECTION")
    try:
        _, scope = ssh_auth.admin_connection_spec(accounts[0], port, ssh_connection)
    except ssh_auth.AdminSshConfigError as exc:
        return StepResult(step, Status.FAIL, str(exc))

    failures: list[str] = []
    for account in accounts:
        try:
            if userkeys.lookup_account(runner, account.name) != account:
                raise SshError("account disappeared or its identity changed after key validation")
            config, scope = ssh_auth.admin_effective_config(runner, account, port, ssh_connection)
        except (userkeys.UserKeysError, SshError, ssh_auth.AdminSshConfigError) as exc:
            failures.append(f"{account.name}: {exc}")
            continue
        problems = ssh_auth.admin_key_problems(config, account)
        # Check this account's admission in its own Match context, not that of other admins.
        problems.extend(_effective_problems(config, port, (account.name,)))
        if problems:
            failures.append(f"{account.name}: {', '.join(problems)}")

    names = ", ".join(account.name for account in accounts)
    detail = "; ".join(failures) if failures else f"managed key path and settings match for {names}"
    return StepResult(step, Status.FAIL if failures else Status.OK, f"{detail}; scope: {scope}")


def _verify_hardening(
    runner: Runner,
    port: int,
    accounts: Sequence[userkeys.Account],
    *,
    require_listener: bool = False,
    local_address: str | None = None,
) -> StepResult:
    names = [account.name for account in accounts]
    config = checks.sshd_effective_config(runner)
    problems = _effective_problems(config, port, names)
    if problems:
        return StepResult("verify", Status.FAIL, "sshd -T: " + ", ".join(problems))
    admin_gate = _admin_key_gate(runner, port, accounts)
    if admin_gate.status is Status.FAIL:
        return StepResult("verify", Status.FAIL, f"{admin_gate.name}: {admin_gate.detail}")
    if local_address is None:
        listening = checks.live_ssh_ports(runner)
    else:
        endpoints = checks.live_ssh_endpoints(runner)
        wildcard = "0.0.0.0" if ip_address(local_address).version == 4 else "::"
        listening = (
            None
            if endpoints is None
            else {port for addr, port in endpoints if addr in {local_address, "*", wildcard}}
        )
    if listening is None:
        status = Status.FAIL if require_listener else Status.SKIPPED
        return StepResult(
            "verify", status, f"ss -tlnp unavailable; listener not verified; {admin_gate.detail}"
        )
    if port not in listening:
        return StepResult(
            "verify",
            Status.FAIL,
            f"port {port} is not listening via sshd (ss -tlnp: "
            + (", ".join(str(value) for value in listening) or "no sshd listeners")
            + f"); {admin_gate.detail}",
        )
    return StepResult(
        "verify",
        Status.OK,
        f"sshd -T: port {port}, PermitRootLogin and PasswordAuthentication no; "
        f"listening on {port}/tcp; "
        f"{admin_gate.detail}",
    )


def _dropin_snapshot(path: Path | None = None, *, require_trusted: bool = False) -> bytes | None:
    """Require trusted metadata when using contents to decide what to apply."""
    path = SSHD_DROPIN if path is None else path
    if path.is_symlink():
        raise SshError(f"refusing SSH drop-in or backup symlink: {path}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SshError(f"refusing non-regular SSH drop-in or backup: {path}")
        if require_trusted and (info.st_uid != _SSHD_DROPIN_UID or info.st_mode & 0o022):
            raise SshError(
                f"refusing SSH drop-in or backup with unsafe owner or permissions: {path}"
            )
        snapshot = handle.read()
        if require_trusted:
            after = os.fstat(fd)
            if (after.st_uid, after.st_mode, after.st_ctime_ns) != (
                info.st_uid,
                info.st_mode,
                info.st_ctime_ns,
            ):
                raise SshError(f"SSH drop-in or backup changed while reading: {path}")
        return snapshot


def _hardening_preflight(
    runner: Runner,
) -> tuple[str, str, _SocketConversion | None, set[checks.SshEndpoint]]:
    socket_unit = _find_active_unit(runner, SOCKET_UNITS)
    conversion = None
    if socket_unit is not None:
        conversion = _socket_conversion(runner, socket_unit)
        socket_unit = conversion.socket
        unit = conversion.service
        service_state = conversion.service_state
    else:
        service = _find_active_unit(runner, SERVICE_UNITS)
        if service is None:
            raise SshError("refusing to change SSH: no active SSH service")
        unit = _loaded_unit_id(runner, service, SERVICE_UNITS)
        if unit is None:
            raise SshError(f"refusing to change SSH: cannot identify the loaded {service}")
        service_state = _unit_enablement(runner, unit)
    endpoints = checks.live_ssh_endpoints(runner, socket_unit=socket_unit)
    if not endpoints:
        raise SshError(
            "refusing to change SSH: current SSH listening ports and addresses not verified"
        )
    _require_idle_ssh_units(runner, unit, conversion)
    return unit, service_state, conversion, endpoints


def _manifest_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise SshError("invalid SSH watchdog byte encoding")
    try:
        raw = base64.b64decode(value, validate=True)
        raw.decode("utf-8")
    except ValueError:
        raise SshError("invalid SSH watchdog byte encoding") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise SshError("non-canonical SSH watchdog byte encoding")
    return raw


def _backup_path(name: str) -> Path:
    if not re.fullmatch(rf"{re.escape(SSHD_DROPIN.name)}\.bak(?:\.[0-9]+)?", name):
        raise SshError("invalid SSH watchdog backup name")
    return SSHD_DROPIN.with_name(name)


@dataclass(frozen=True)
class _RecoveryState:
    snapshot: bytes | None
    candidate: bytes
    backup: Path | None
    unit: str
    service_state: str
    conversion: _SocketConversion | None
    endpoints: set[checks.SshEndpoint]
    port: int
    accounts: list[userkeys.Account]
    connection: tuple[str, int, str, int] | None
    write_attempted: bool
    action: str
    fallback_attempted: bool


def _recovery_state(data: dict[str, object]) -> _RecoveryState:
    def invalid() -> SshError:
        return SshError("invalid SSH watchdog recovery manifest")

    # Session freshness is only required for confirmation, never for rollback.
    if data.keys() - {"freshness", "fallback_attempted"} != {
        "snapshot",
        "candidate",
        "backup",
        "unit",
        "service_state",
        "socket",
        "socket_state",
        "endpoints",
        "port",
        "accounts",
        "connection",
        "write_attempted",
        "action",
    }:
        raise invalid()
    snapshot = None if data["snapshot"] is None else _manifest_bytes(data["snapshot"])
    candidate = _manifest_bytes(data["candidate"])
    backup_name, write_attempted, action = data["backup"], data["write_attempted"], data["action"]
    unit, service_state = data["unit"], data["service_state"]
    socket, socket_state = data["socket"], data["socket_state"]
    port = data["port"]
    if (
        not candidate
        or candidate == snapshot
        or not isinstance(write_attempted, bool)
        or type(port) is not int
        or not 1 <= port <= 65535
        or not isinstance(unit, str)
        or unit not in SERVICE_UNITS
        or not isinstance(service_state, str)
        or service_state not in _UNIT_STATES
        or (backup_name is not None) != (write_attempted and snapshot is not None)
    ):
        raise invalid()
    backup = None
    if backup_name is not None:
        if not isinstance(backup_name, str):
            raise invalid()
        backup = _backup_path(backup_name)
    conversion = None
    actions = {"none", "reload"}
    if socket is not None:
        if (
            not isinstance(socket, str)
            or socket not in SOCKET_UNITS
            or not isinstance(socket_state, str)
            or socket_state not in _UNIT_STATES
        ):
            raise invalid()
        conversion = _SocketConversion(socket, unit, socket_state, service_state)
        if conversion.socket_enabled and service_state == "static":
            raise invalid()
        actions = {"none", "stop", "restart"}
        if conversion.socket_enabled:
            actions.add("disable")
        if conversion.service_target != service_state:
            actions.add("enable")
    elif socket_state is not None:
        raise invalid()
    fallback_attempted = data.get("fallback_attempted", False)
    if (
        not isinstance(action, str)
        or action not in actions
        or (action != "none" and not write_attempted)
        or not isinstance(fallback_attempted, bool)
        or (fallback_attempted and (conversion is None or action == "none"))
    ):
        raise invalid()
    endpoints: set[checks.SshEndpoint] = set()
    rows = data["endpoints"]
    if not isinstance(rows, list) or not rows:
        raise invalid()
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            raise invalid()
        address, endpoint_port = row
        if (
            not isinstance(address, str)
            or "%" in address
            or (address != "*" and str(ip_address(address)) != address)
            or type(endpoint_port) is not int
            or not 1 <= endpoint_port <= 65535
            or (address, endpoint_port) in endpoints
        ):
            raise invalid()
        endpoints.add((address, endpoint_port))
    accounts: list[userkeys.Account] = []
    names: set[str] = set()
    rows = data["accounts"]
    if not isinstance(rows, list) or not rows:
        raise invalid()
    for row in rows:
        if not isinstance(row, list) or len(row) != 4:
            raise invalid()
        name, uid, gid, home = row
        if (
            not isinstance(name, str)
            or not USER_RE.fullmatch(name)
            or name in names
            or type(uid) is not int
            or type(gid) is not int
            or not isinstance(home, str)
            or str(Path(home)) != home
            or ".." in Path(home).parts
        ):
            raise invalid()
        accounts.append(userkeys.Account(name, uid, gid, Path(home)))
        names.add(name)
    raw_connection = data["connection"]
    if raw_connection is not None and not isinstance(raw_connection, str):
        raise invalid()
    connection = ssh_auth.parse_ssh_connection(raw_connection)
    if raw_connection is not None and connection is None:
        raise SshError("invalid SSH_CONNECTION in watchdog recovery manifest")
    return _RecoveryState(
        snapshot,
        candidate,
        backup,
        unit,
        service_state,
        conversion,
        endpoints,
        port,
        accounts,
        connection,
        write_attempted,
        action,
        fallback_attempted,
    )


def _recover_watchdog(
    runner: Runner, pending: ssh_watchdog.Pending, results: list[StepResult]
) -> int:
    state = _recovery_state(pending.data)
    if pending.phase == "prepared":
        _require_inert_prepared(state)
        ssh_watchdog.clear(runner, pending)
        return 0
    pending = ssh_watchdog.update(pending, phase="failed")

    def record_fallback() -> None:
        nonlocal pending
        if not pending.data.get("fallback_attempted"):
            pending = ssh_watchdog.update(pending, fallback_attempted=True)

    if not state.write_attempted:
        ssh_watchdog.clear(runner, pending)
        return 0
    disk_status = 0
    try:
        results.append(_rollback_dropin(state.snapshot, state.candidate, state.backup))
    except (Exception, KeyboardInterrupt) as exc:
        detail = str(exc) or type(exc).__name__
        results.append(StepResult("restore ssh drop-in", Status.FAIL, detail))
        _recovery_hint(f"verify {SSHD_DROPIN} from the local console: {detail}")
        if isinstance(exc, KeyboardInterrupt):
            raise
        if not _retryable_recovery_error(exc):
            return 1
        disk_status = _RETRY

    disk_restored = disk_status == 0
    conversion = state.conversion
    if conversion is not None:
        runtime_status = _recover_socket(
            runner,
            conversion,
            state.endpoints,
            results,
            snapshot=state.snapshot,
            restart_attempted=state.action == "restart",
            socket_disable_attempted=state.action in {"disable", "enable", "restart"}
            and conversion.socket_enabled,
            service_enable_attempted=state.action in {"enable", "restart"}
            and conversion.service_target != conversion.service_state,
            disk_restored=disk_restored,
            preactivation=state.action == "none",
            fallback_attempted=state.fallback_attempted,
            record_fallback=record_fallback,
        )
    else:
        runtime_status = _recover_service(
            runner,
            state.unit,
            state.service_state,
            state.endpoints,
            results,
            snapshot=state.snapshot,
            disk_restored=disk_restored,
        )
    if runtime_status == 1:
        return 1
    if _RETRY in (disk_status, runtime_status):
        return _RETRY
    _require_original_dropin(state.snapshot)
    ssh_watchdog.clear(runner, pending)
    return 0


def expire_watchdog(txid: str) -> int:
    """Restore unconfirmed SSH from the independently scheduled systemd service."""
    results: list[StepResult] = []
    try:
        with locked_target(SSHD_DROPIN):
            pending = ssh_watchdog.current()
            if pending is None or pending.id != txid or pending.phase == "confirmed":
                return 0
            if pending.phase not in {"prepared", "armed", "awaiting-confirm", "failed"}:
                raise SshError("unknown SSH watchdog phase")
            if monotonic() < pending.deadline:
                return _RETRY
            status = _recover_watchdog(Runner(), pending, results)
    except BlockingIOError:
        return _RETRY
    except (CommandError, OSError, ValueError, userkeys.UserKeysError) as exc:
        _recovery_hint(f"SSH watchdog recovery failed: {exc}")
        return _RETRY if _retryable_recovery_error(exc) else 1
    for result in results:
        _recovery_hint(f"{result.name}: {result.status} {result.detail}")
    return status


def _require_watchdog_time(pending: ssh_watchdog.Pending) -> None:
    if monotonic() >= pending.deadline:
        raise SshError("SSH watchdog deadline reached; rollback is required")


def _confirmation_instructions(pending: ssh_watchdog.Pending, port: int) -> str:
    seconds = max(0, int(pending.deadline - monotonic()))
    return (
        f"{seconds}s until automatic rollback; after a successful apply, open a new, "
        f"non-multiplexed SSH key session on port {port}, then run: "
        f"sudo --preserve-env=SSH_CONNECTION lhm ssh-confirm {pending.id}"
    )


def _confirmation_cutoff(data: dict[str, object]) -> tuple[str, int]:
    cutoff = data.get("freshness")
    if isinstance(cutoff, list) and len(cutoff) == 2:
        boot_id, tick = cutoff
        if (
            isinstance(boot_id, str)
            and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot_id)
            and type(tick) is int
            and 0 < tick < (1 << 63)
        ):
            return boot_id, tick
    raise SshError("missing or invalid SSH transport freshness cutoff")


def confirm_watchdog(runner: Runner, txid: str) -> list[StepResult]:
    """After operator attestation, verify a new SSH session and commit under the lock."""
    step = "confirm SSH watchdog"
    if runner.dry_run or not mutations_allowed():
        detail = "SSH watchdog confirmation is not allowed in dry-run"
        return [StepResult(step, Status.FAIL, detail)]
    try:
        with locked_target(SSHD_DROPIN):
            pending = ssh_watchdog.current()
            if pending is None or pending.id != txid or pending.phase != "awaiting-confirm":
                raise SshError("no matching SSH watchdog transaction awaiting confirmation")
            _require_watchdog_time(pending)
            data = pending.data
            state = _recovery_state(data)
            boot_id, cutoff_tick = _confirmation_cutoff(data)
            if state.action != ("restart" if state.conversion is not None else "reload"):
                raise SshError("SSH watchdog activation was not completed")
            connection = ssh_auth.parse_ssh_connection(os.environ.get("SSH_CONNECTION"))
            if connection is None or connection == state.connection or connection[3] != state.port:
                raise SshError(
                    f"confirm from a new SSH connection on port {state.port}; "
                    "forward SSH_CONNECTION explicitly through sudo"
                )
            account = _sudo_invoker(runner, operation="SSH confirmation")
            if account is None or account not in state.accounts:
                raise SshError("confirmation requires an original authorized SSH administrator")
            ssh_session.require_fresh_ssh(boot_id, cutoff_tick, account=account)
            if _dropin_snapshot() != state.candidate:
                raise SshError("SSH drop-in changed after activation")
            _require_idle_ssh_units(runner, state.unit, state.conversion)
            for account in state.accounts:
                if not _has_login_key(runner, account):
                    raise SshError(f"{account.name}: authorized SSH key no longer verified")
            verification = _verify_hardening(
                runner,
                state.port,
                state.accounts,
                require_listener=True,
                local_address=connection[2],
            )
            if verification.status is not Status.OK:
                return [verification]
            _require_idle_ssh_units(runner, state.unit, state.conversion)
            if _dropin_snapshot() != state.candidate:
                raise SshError("SSH drop-in changed during confirmation")
            if ssh_watchdog.current() != pending:
                raise SshError("SSH watchdog transaction changed during confirmation")
            _require_watchdog_time(pending)
            ssh_watchdog.clear(runner, pending)
            return [verification, StepResult(step, Status.CHANGED, f"confirmed {txid}")]
    except (CommandError, OSError, ValueError, userkeys.UserKeysError) as exc:
        return [StepResult(step, Status.FAIL, str(exc))]


def _require_inert_prepared(state: _RecoveryState) -> None:
    if state.write_attempted:
        raise SshError("prepared SSH watchdog unexpectedly recorded an attempted write")


def _require_no_watchdog(runner: Runner, *, clear_prepared: bool = False) -> None:
    pending = ssh_watchdog.current()
    if pending is None:
        return
    if pending.phase == "prepared":
        # The lock excludes a live arming operation. A crashed arm may never
        # have scheduled a timer, and cannot have made any SSH changes yet.
        _require_inert_prepared(_recovery_state(pending.data))
        if clear_prepared:
            ssh_watchdog.clear(runner, pending)
        return
    raise SshError(f"SSH watchdog transaction {pending.id} is still pending ({pending.phase})")


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
    try:
        snapshot = _dropin_snapshot(require_trusted=True)
        retained = _managed_allow_users(snapshot) if snapshot is not None else []
    except (OSError, SshError) as exc:
        return [StepResult("ssh-hardening", Status.FAIL, str(exc))]
    requested = list(dict.fromkeys([*retained, *requested]))

    dry_run = runner.dry_run or not mutations_allowed()
    accounts: list[userkeys.Account] = []
    if dry_run:
        candidates = " ".join(requested) if requested else "discover users with valid keys"
        users_plan = f"{candidates} (key validation deferred until live apply)"
    elif requested:
        try:
            accounts = [_require_account_key(runner, name) for name in requested]
        except SshError as exc:
            return [StepResult("ssh-hardening", Status.FAIL, str(exc))]
    else:
        accounts = _accounts_with_keys(runner)
        if not accounts:
            return [
                StepResult(
                    "ssh-hardening",
                    Status.FAIL,
                    "refusing: no authorized_keys with a valid public key under /home "
                    "(run apply ssh-user first)",
                )
            ]

    names = requested if dry_run else [account.name for account in accounts]
    if not dry_run:
        users_plan = " ".join(names)
    desired = desired_conf(port, names)
    needed = snapshot != desired.encode("utf-8")
    plan = [
        "Plan (ssh-hardening):",
        f"  - allowed users: {users_plan}",
    ]
    if needed:
        plan.extend(
            [
                f"  - write {SSHD_DROPIN} "
                f"(Port {port}, PermitRootLogin no, PasswordAuthentication no)",
                "  - gate: sshd -t must accept the drop-in before any reload",
                "  - gate: sshd -T effective values must match (earlier drop-ins win)",
                "  - gate: sshd -T -C checks per-admin authorized_keys and public-key auth",
                "  - if an SSH socket is active: stop it, transfer enablement, restart its service",
                "  - else reload only the confirmed active SSH service",
                "  - verify: port must actually listen (ss -tlnp), not just sshd -T",
                "  - a systemd watchdog rolls back unless a new SSH session confirms the change",
                "  - risk: password logins stop; keep this session open and test key login first",
            ]
        )
    else:
        plan.extend(
            [
                f"  - {SSHD_DROPIN} already current (skip)",
                "  - verify: effective SSH settings, managed keys and listening port",
            ]
        )

    if dry_run:
        for line in plan:
            print(line)
        if not needed:
            runner.run(["sshd", "-T"])
            runner.run(["ss", "-tlnp"])
            return [
                StepResult(f"write {SSHD_DROPIN}", Status.SKIPPED, "already current"),
                StepResult("verify", Status.PLANNED, "effective config, managed keys and listener"),
            ]
        runner.run(["sshd", "-t"])
        # Detection is impossible in dry-run: show the worst case (socket unit).
        runner.run(["systemctl", "stop", "--job-mode=fail", SOCKET_UNITS[0]])
        runner.run(["systemctl", "disable", SOCKET_UNITS[0]])
        runner.run(["systemctl", "restart", "--job-mode=fail", SERVICE_UNITS[0]])
        runner.run(["ss", "-tlnp"])
        return [
            StepResult(f"write {SSHD_DROPIN}", Status.PLANNED),
            StepResult("sshd -t", Status.PLANNED, "gate"),
            StepResult("sshd -T effective", Status.PLANNED, "gate"),
            StepResult("sshd -T admin keys", Status.PLANNED, "scoped gate; not a login test"),
            StepResult("socket activation", Status.PLANNED, "stop if active; transfer enablement"),
            StepResult("reload sshd", Status.PLANNED),
        ]

    try:
        if needed:
            if SSHD_DROPIN.parent.exists():
                with locked_target(SSHD_DROPIN):
                    _require_no_watchdog(runner)
            if not confirm_once(plan):
                return [StepResult("ssh-hardening", Status.ABORTED, "aborted; no changes made")]
        if needed and not SSHD_DROPIN.parent.exists():
            # Never create the managed directory before obtaining its shared lock and
            # arming recovery. Keep the original preflight diagnostics on unsupported hosts.
            _hardening_preflight(runner)
            raise SshError(f"SSH drop-in directory must already exist: {SSHD_DROPIN.parent}")
        with locked_target(SSHD_DROPIN):
            locked_snapshot = _dropin_snapshot(require_trusted=True)
            if locked_snapshot != snapshot:
                return [
                    StepResult(
                        "ssh-hardening",
                        Status.FAIL,
                        "SSH drop-in changed during confirmation; rerun to review the new plan",
                    )
                ]
            if not needed:
                _require_no_watchdog(runner, clear_prepared=True)
                return [
                    StepResult(f"write {SSHD_DROPIN}", Status.SKIPPED, "already current"),
                    _verify_hardening(runner, port, accounts),
                ]
            for account in accounts:
                _require_account_key(runner, account.name, expected=account)
            _require_no_watchdog(runner, clear_prepared=True)
            return _apply_confirmed_hardening(runner, desired, port, accounts, locked_snapshot)
    except (CommandError, OSError, ValueError) as exc:
        return [StepResult("ssh-hardening", Status.FAIL, str(exc))]


def _apply_confirmed_hardening(
    runner: Runner,
    desired: str,
    port: int,
    accounts: Sequence[userkeys.Account],
    snapshot: bytes | None,
) -> list[StepResult]:
    results: list[StepResult] = []
    candidate = desired.encode("utf-8")
    pending: ssh_watchdog.Pending | None = None
    recover_here = True

    def record(*, phase: str | None = None, **fields: object) -> ssh_watchdog.Pending:
        nonlocal pending
        if pending is None:
            raise SshError("SSH watchdog not armed")
        _require_watchdog_time(pending)
        pending = ssh_watchdog.update(pending, phase=phase, **fields)
        return pending

    def record_backup(path: Path) -> None:
        if snapshot is None:
            # An outside writer created the target after our absent-file check.
            record(write_attempted=False)
        if (
            snapshot is None
            or _dropin_snapshot(path) != snapshot
            or _dropin_snapshot(require_trusted=True) != snapshot
        ):
            raise SshError("SSH drop-in changed before write; rerun to review the new plan")
        if _backup_path(path.name) != path:
            raise SshError("SSH backup is not beside the drop-in")
        record(write_attempted=True, backup=path.name)

    try:
        unit, service_state, conversion, previous_endpoints = _hardening_preflight(runner)
        data: dict[str, object] = {
            "snapshot": None if snapshot is None else base64.b64encode(snapshot).decode("ascii"),
            "candidate": base64.b64encode(candidate).decode("ascii"),
            "backup": None,
            "unit": unit,
            "service_state": service_state,
            "socket": conversion.socket if conversion else None,
            "socket_state": conversion.socket_state if conversion else None,
            "endpoints": [list(endpoint) for endpoint in sorted(previous_endpoints)],
            "port": port,
            "accounts": [[a.name, a.uid, a.gid, str(a.home)] for a in accounts],
            "connection": os.environ.get("SSH_CONNECTION"),
            "write_attempted": False,
            "action": "none",
        }
        _recovery_state(data)
        if _dropin_snapshot(require_trusted=True) != snapshot:
            raise SshError("SSH drop-in changed before write; rerun to review the new plan")
        pending = ssh_watchdog.arm(runner, data)
        _require_watchdog_time(pending)
        _recovery_hint(f"SSH watchdog armed: {_confirmation_instructions(pending, port)}")
        if not ensure_privsep_dir():
            raise SshError("could not prepare /run/sshd")
        if _dropin_snapshot(require_trusted=True) != snapshot:
            raise SshError("SSH drop-in changed before write; rerun to review the new plan")
        if snapshot is None:
            record(write_attempted=True)
        outcome = write_dropin(
            SSHD_DROPIN, desired, on_backup=record_backup, require_backup=snapshot is not None
        )
        results.append(
            StepResult(
                f"write {SSHD_DROPIN}",
                Status.CHANGED if outcome == "written" else Status.SKIPPED,
            )
        )
        if outcome != "written":
            record(write_attempted=False, backup=None)
            results.append(_verify_hardening(runner, port, accounts))
            return results
        gate = runner.run(["sshd", "-t"], check=False)
        if not gate.ok:
            detail = f"rejected the drop-in (rc={gate.returncode}); sshd not reloaded"
            if gate.stderr.strip():
                detail += f"\n{gate.stderr.strip()}"
            results.append(StepResult("sshd -t", Status.FAIL, detail))
            return results
        results.append(StepResult("sshd -t", Status.OK, "config accepted"))

        # first-obtained-value-wins: an earlier 50-cloud-init.conf can silently
        # override the 99- drop-in, so gate on the effective config BEFORE reload.
        effective = checks.sshd_effective_config(runner)
        names = [account.name for account in accounts]
        conflicts = _effective_problems(effective, port, names)
        if conflicts:
            results.append(
                StepResult("sshd -T effective", Status.FAIL, _conflict_detail(conflicts))
            )
            return results
        results.append(StepResult("sshd -T effective", Status.OK, "port/root/password match"))
        admin_gate = _admin_key_gate(runner, port, accounts)
        results.append(admin_gate)
        if admin_gate.status is Status.FAIL:
            return results

        # Debian 12 socket activation: ssh.socket owns the listener (Port 22), so
        # the Port drop-in only takes effect once the socket unit is stopped.
        _require_idle_ssh_units(runner, unit, conversion)
        operation = "reload"
        if conversion is not None:
            socket_unit = conversion.socket
            # Some systemctl versions ignore the stop's exit status with disable --now.
            record(action="stop")
            runner.run(["systemctl", "stop", "--job-mode=fail", socket_unit])
            if _unit_active(runner, socket_unit) is not False:
                raise SshError(f"{socket_unit} not confirmed inactive after stop")
            results.append(StepResult("stop ssh.socket", Status.CHANGED, f"stopped {socket_unit}"))
            if conversion.socket_enabled:
                # Disable may have removed links even if it fails or gets interrupted.
                record(action="disable")
                flags = _enable_flags(conversion.socket_state)
                runner.run(["systemctl", "disable", *flags, socket_unit])
                results.append(
                    StepResult("disable ssh.socket", Status.CHANGED, f"disabled {socket_unit}")
                )
            target = conversion.service_target
            if target != conversion.service_state:
                # An unsuccessful command can still have created the enablement links.
                record(action="enable")
                runner.run(["systemctl", "enable", *_enable_flags(target), unit])
                results.append(StepResult(f"enable {unit}", Status.CHANGED, target))
            if (
                target in {"enabled", "enabled-runtime"}
                and _unit_enablement(runner, unit) != target
            ):
                raise SshError(f"{unit} enablement did not reach {target!r}")
            if _unit_active(runner, socket_unit) is not False:
                raise SshError(f"{socket_unit} not confirmed inactive before restarting {unit}")
            _require_idle_ssh_units(runner, unit, conversion)
            operation = "restart"
        # Persist the exact attempt before submitting a job, even if systemctl times out.
        record(action=operation)
        activated = runner.run(["systemctl", operation, "--job-mode=fail", unit], check=False)
        if not activated.ok:
            results.append(StepResult("reload sshd", Status.FAIL, str(CommandError(activated))))
            return results
        action = "restarted" if conversion is not None else "reloaded"
        results.append(StepResult("reload sshd", Status.CHANGED, f"{action} {unit}"))

        verification = _verify_hardening(runner, port, accounts, require_listener=True)
        if verification.status is Status.OK:
            # BOOTTIME ticks identify a newer SSH transport, not the watchdog
            # deadline; expiry and confirmation still use CLOCK_MONOTONIC.
            boot_id, cutoff_tick = ssh_session.freshness_cutoff()
            awaiting = record(phase="awaiting-confirm", freshness=[boot_id, cutoff_tick])
            recover_here = False
            results.append(
                StepResult(
                    "SSH watchdog", Status.CHANGED, _confirmation_instructions(awaiting, port)
                )
            )
        results.append(verification)
    except Exception as exc:
        results.append(StepResult("ssh-hardening", Status.FAIL, str(exc)))
    except KeyboardInterrupt:
        raise
    except BaseException:
        recover_here = False
        raise
    finally:
        if recover_here and pending is not None:
            try:
                # A failed update may have reached disk; recover from the resulting manifest.
                current = ssh_watchdog.current()
                if current is None or current.id != pending.id:
                    raise SshError("SSH watchdog manifest disappeared during apply")
                _recover_watchdog(runner, current, results)
            except Exception as exc:
                results.append(StepResult("SSH watchdog", Status.FAIL, str(exc)))
                _recovery_hint("SSH recovery not verified; inspect the watchdog from the console")

    return results


def inspect(runner: Runner, *, port: int = DEFAULT_PORT) -> dict[str, object]:
    """Read-only state used by ``check``."""
    snapshot = None
    present: bool | None
    names: list[str] | None
    try:
        snapshot = _dropin_snapshot(require_trusted=True)
        present = snapshot is not None
        names = [] if snapshot is None else list(dict.fromkeys(_managed_allow_users(snapshot)))
    except SshError:
        present, names = True, None
    except OSError:
        present, names = None, None  # An I/O error can hide the file itself.
    unlisted = unverified = None
    # Unprivileged query reports the managed list without attempting a UID/GID switch.
    if names is not None and geteuid() == 0 and not runner.dry_run and mutations_allowed():
        key_holders = users_with_keys(runner)
        unlisted = [name for name in key_holders if name not in names]
        unverified = []
        for name in names:
            if name not in key_holders:
                try:
                    _require_account_key(runner, name)
                except SshError:
                    unverified.append(name)
    effective = checks.sshd_effective_config(runner)
    return {
        "dropin": str(SSHD_DROPIN),
        "dropin_present": present,
        "dropin_current": bool(names) and snapshot == desired_conf(port, names).encode("utf-8"),
        "authorized_users": names,
        "unlisted_key_holders": unlisted,
        "unverified_managed_keys": unverified,
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
