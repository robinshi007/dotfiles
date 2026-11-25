"""fail2ban module: install, jail.d drop-in for sshd/caddy, enable and verify.

lhm writes a ``jail.d/99-lhm.local`` drop-in, never ``/etc/fail2ban/jail.local``.
"""

import base64
import hashlib
import json
import os
import pwd
import re
import secrets
import shlex
import socket
import stat
from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from lhm.core import caddy_guard
from lhm.core.backup import rollback_file
from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend, DistroError
from lhm.core.files import locked_target, remove_file, render_template, write_dropin
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGES = ("fail2ban", "nftables")  # nftables is only a Recommends of fail2ban
TEMPLATE = "99-lhm.local.tmpl"
CADDY_TEMPLATE = "caddy-filter.conf.tmpl"

JAIL_DROPIN = Path("/etc/fail2ban/jail.d/99-lhm.local")
CADDY_FILTER = Path("/etc/fail2ban/filter.d/caddy-lhm.conf")
CADDY_ACCESS_FILTER = Path("/etc/fail2ban/filter.d/caddy-lhm-access.conf")
CADDY_ACCESS_LOG = Path("/var/log/caddy/access.log")
_ATTESTATION = "# lhm caddy-direct: "
_PENDING_REVOKE = "# lhm caddy-cleanup-pending: "
DBFILE = Path("/var/lib/fail2ban/fail2ban.sqlite3")
CADDY_UNIT = "caddy.service"
ACCESS_JAIL = "caddy-lhm-access"
ACCESS_JAIL_RE = rf"{ACCESS_JAIL}(?:-[0-9a-f]{{24}})?"
ACCESS_ACTIONS = ("nftables-multiport", "nftables-caddy-quic")
JAIL_HEADER = "# ===== lhm fail2ban jail.d drop-in =====\n"
LEGACY_FILTER_HEADER = "# ===== lhm-managed fail2ban filter for Caddy =====\n"
ACCESS_FILTER_HEADER = "# ===== lhm-managed fail2ban file filter for Caddy =====\n"
CaddyMode = Literal["off", "journald", "file", "unmanaged"]

# Never written by lhm: it holds the host's own custom jails. Guards any future
# code path that might target it (the drop-in overrides it by load order).
LEGACY_JAIL_LOCAL = Path("/etc/fail2ban/jail.local")

SSH_PORT = 22345
CADDY_PORTS = "80,443"
SSHD_BANTIME = "8h"
SSHD_FINDTIME = "30m"
SSHD_MAXRETRY = "3"
CADDY_MAXRETRY = "5"
TIME_RE = re.compile(r"\d+[smhdw]?")
RETRY_RE = re.compile(r"\d+")
AUTH_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*")


class JailError(ValueError):
    """Raised when a jail duration or retry value is malformed."""


@dataclass(frozen=True)
class DirectAccess:
    digest: str
    protected_paths: tuple[str, ...]
    generation: str

    @property
    def jail(self) -> str:
        policy = " ".join((self.digest, self.generation, *self.protected_paths))
        fingerprint = hashlib.sha256(policy.encode("ascii")).hexdigest()[:24]
        return f"{ACCESS_JAIL}-{fingerprint}"


def _protected_paths(paths: tuple[str, ...]) -> str:
    if not 1 <= len(paths) <= 32 or any(
        len(path) > 256 or not AUTH_PATH_RE.fullmatch(path) or {".", ".."} & set(path.split("/"))
        for path in paths
    ):
        raise JailError("expected 1–32 literal protected paths (no query, wildcard or dot segment)")
    return "|".join(re.escape(path) for path in dict.fromkeys(paths))


def _time_value(name: str, value: str) -> str:
    if not TIME_RE.fullmatch(value):
        raise JailError(f"invalid {name} {value!r}: use e.g. 1h, 10m, 3600")
    if _seconds(value) == 0:
        raise JailError(
            f"invalid {name} {value!r}: must be strictly positive "
            "(a zero duration disables the jail, e.g. use 1h, 10m, 3600)"
        )
    return value


def _retry_value(name: str, value: str) -> str:
    if not RETRY_RE.fullmatch(value):
        raise JailError(
            f"invalid {name} {value!r}: use a positive integer without a unit "
            "suffix (e.g. 3)"
        )
    if int(value) == 0:
        raise JailError(
            f"invalid {name} {value!r}: must be strictly positive "
            "(0 would disable banning, e.g. use 3)"
        )
    return str(int(value))


def _seconds(value: str) -> int | None:
    """Seconds for a fail2ban duration (``1h``, ``30m``, ``4w``, ``3600``)."""
    match = re.fullmatch(r"(\d+)([smhdw]?)", value)
    if match is None:
        return None
    scale = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return int(match.group(1)) * scale[match.group(2)]


def _write_managed(
    path: Path, content: str, *, backups: dict[Path, Path | None] | None = None
) -> str:
    """Write a managed config, refusing the host's hand-maintained jail.local."""
    if Path(path) == LEGACY_JAIL_LOCAL:
        raise JailError(
            "refusing to write /etc/fail2ban/jail.local: lhm only writes the "
            "jail.d/99-lhm.local drop-in and never touches the host's jail.local"
        )
    previous = _managed_text(path, content.splitlines(keepends=True)[0])
    if backups is None:
        return write_dropin(path, content)
    if previous is None:
        backups[path] = None

    def remember(source: Path) -> None:
        backups[path] = source

    return write_dropin(path, content, on_backup=remember)


def desired_conf(
    *,
    bantime: str = SSHD_BANTIME,
    findtime: str = SSHD_FINDTIME,
    maxretry: str = SSHD_MAXRETRY,
    caddy: bool = False,
    caddy_maxretry: str = CADDY_MAXRETRY,
    hostname: str = "",
    caddy_mode: CaddyMode | None = None,
    direct: DirectAccess | None = None,
) -> str:
    mode = caddy_mode or ("journald" if caddy else "off")
    retry = _retry_value("caddy_maxretry", caddy_maxretry)
    if mode == "file" and int(retry) < 2:
        raise JailError("invalid caddy_maxretry: file jail requires repeated failures (at least 2)")
    base = render_template(
        TEMPLATE,
        bantime=_time_value("bantime", bantime),
        findtime=_time_value("findtime", findtime),
        maxretry=_retry_value("maxretry", maxretry),
        ssh_port=str(SSH_PORT),
        hostname=hostname or socket.gethostname(),
    )
    if mode == "unmanaged":
        return base
    file_mode = mode == "file"
    if file_mode:
        if direct is None or not (
            re.fullmatch(r"[0-9a-f]{64}", direct.digest)
            and re.fullmatch(r"[0-9a-f]{32}", direct.generation)
        ):
            raise JailError("file jail requires a direct-client attestation")
        _protected_paths(direct.protected_paths)
    jail = render_template(
        "caddy-jail.local.tmpl",
        jail=direct.jail if file_mode and direct else "caddy",
        enabled="false" if mode == "off" else "true",
        backend="polling" if file_mode else "systemd",
        source=(
            f"logpath = {CADDY_ACCESS_LOG} tail"
            if file_mode
            else f"journalmatch = _SYSTEMD_UNIT={CADDY_UNIT}"
        ),
        filter=ACCESS_JAIL if file_mode else "caddy-lhm",
        maxretry=retry,
    )
    if file_mode and direct:
        policy = " ".join((direct.digest, direct.generation, *direct.protected_paths))
        jail += (
            f"{_ATTESTATION}{policy}\n"
            "usedns = no\n"
            "logencoding = utf-8\n"
            "ignorecache =\n"
            f"ignorecommand = {_access_guard(direct)}\n"
            f'action = nftables-multiport[name={direct.jail}, port="80,443", '
            "protocol=tcp, actionstart_on_demand=false]\n"
            f"         nftables-multiport[actname=nftables-caddy-quic, name={direct.jail}-quic, "
            "port=443, protocol=udp, actionstart_on_demand=false]\n"
        )
    return f"{base}\n{jail}"


def desired_caddy_filter(*, protected_paths: tuple[str, ...] = ()) -> str:
    if not protected_paths:
        return render_template(CADDY_TEMPLATE)
    return render_template(
        "caddy-access-filter.conf.tmpl", protected_paths=_protected_paths(protected_paths)
    )


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _managed_text(path: Path, header: str) -> str | None:
    """A managed destination must be absent or a regular file with our header."""
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise JailError(f"refusing to overwrite unmanaged {path}")
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    if not text.startswith(header):
        raise JailError(f"refusing to overwrite unmanaged {path}")
    return text


def _external_caddy_jail(jail: str | None = None) -> Path | None:
    fragments = JAIL_DROPIN.parent
    sources = [
        fragments.parent / "jail.conf",
        *fragments.glob("*.conf"),
        LEGACY_JAIL_LOCAL,
        *fragments.glob("*.local"),
    ]
    names = re.escape(jail) if jail else f"caddy|{ACCESS_JAIL_RE}"
    for path in sources:
        if path == JAIL_DROPIN:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        if re.search(rf"(?m)^[ \t]*\[(?:{names})\]", text):
            return path
    return None


def _read_direct_access(text: str) -> DirectAccess | None:
    for line in text.splitlines():
        if line.startswith(_ATTESTATION):
            try:
                digest, generation, *paths = line.removeprefix(_ATTESTATION).split()
                _protected_paths(tuple(paths))
            except ValueError:
                return None
            if re.fullmatch(r"[0-9a-f]{64}", digest) and re.fullmatch(r"[0-9a-f]{32}", generation):
                return DirectAccess(digest, tuple(paths), generation)
    return None


def _caddy_runtime_digest(runner: Runner) -> str | None:
    """Fingerprint only a live JSON config equal to the managed Caddyfile."""
    from lhm.modules import caddy

    try:
        if not caddy_guard.trusted_log(CADDY_ACCESS_LOG, pwd.getpwnam("caddy").pw_uid):
            return None
    except OSError, KeyError:
        return None
    active = caddy.running_config_fingerprint(runner)
    return active.wire_fingerprint if active and active.access_log == CADDY_ACCESS_LOG else None


def _access_guard(direct: DirectAccess) -> str:
    """Fail2ban ignores new and restored tickets if the attestation is stale."""
    from lhm.modules import caddy

    source = base64.b64encode(Path(caddy_guard.__file__).read_bytes()).decode("ascii")
    command = shlex.join(
        (
            "/usr/bin/python3",
            "-I",
            "-c",
            f"import base64;exec(base64.b64decode('{source}'))",
            direct.digest,
            str(caddy.ADMIN_SOCKET),
            str(CADDY_ACCESS_LOG),
        )
    )
    # Only explicit success from the guard may permit a failure ticket.
    return shlex.join(("/bin/sh", "-c", f'{command}; [ "$?" -ne 42 ]')).replace("%", "%%")


def dbfile_path(runner: Runner) -> tuple[Path, bool]:
    """Effective dbfile and whether it exists (packaging default as fallback).

    ``bantime.increment`` is silently inert without a dbfile, so the path the
    daemon actually uses matters, not just the hardcoded Debian default.
    """
    result = runner.run(["fail2ban-client", "-d"], check=False)
    if result.ok:
        match = re.search(r"\['set', 'dbfile', '([^']+)'\]", result.stdout)
        if match:
            path = Path(match.group(1))
            return path, path.exists()
    return DBFILE, DBFILE.exists()


def caddy_unit_present(runner: Runner) -> bool | None:
    """Whether ``caddy.service`` exists; None when it cannot be probed."""
    result = runner.run(["systemctl", "list-unit-files", CADDY_UNIT], check=False)
    if not result.ok:
        return None
    return any(
        line.split() and line.split()[0] == CADDY_UNIT
        for line in result.stdout.splitlines()
    )


def jail_setting(runner: Runner, jail: str, key: str) -> str | None:
    """Effective value from the running daemon, or None when unprobeable."""
    result = runner.run(["fail2ban-client", "get", jail, key], check=False)
    if not result.ok:
        return None
    return result.stdout.strip()


def jail_increment_active(runner: Runner, jail: str) -> bool | None:
    """Whether ``bantime.increment`` is effective, read from ``fail2ban-client -d``."""
    result = runner.run(["fail2ban-client", "-d"], check=False)
    if not result.ok:
        return None
    pattern = re.compile(rf"\['set', '{re.escape(jail)}', 'bantime\.increment', True\]")
    return pattern.search(result.stdout) is not None


def _client_missing(result: object) -> bool:
    """True when the probe failed because fail2ban-client itself is unavailable."""
    return getattr(result, "returncode", 0) in {126, 127, 124}


def _verify_access_action(runner: Runner, jail: str) -> StepResult:
    name = "verify caddy nftables action"
    actions = jail_setting(runner, jail, "actions")
    if not actions or set(actions.splitlines()[-1].split(", ")) != set(ACCESS_ACTIONS):
        return StepResult(name, Status.FAIL, "expected live Caddy TCP and QUIC nftables actions")
    chain = runner.run(
        ["nft", "--numeric", "list", "chain", "inet", "f2b-table", "f2b-chain"], check=False
    )
    if not chain.ok or "type filter hook input" not in chain.stdout:
        return StepResult(name, Status.FAIL, "fail2ban nftables input chain unavailable")
    for family, prefix in (("ip", "addr-set"), ("ip6", "addr6-set")):
        for match, suffix in (
            (r"tcp dport \{ 80, 443 \}", ""),
            (r"udp dport (?:443|\{ 443 \})", "-quic"),
        ):
            rule = rf"{match} {family} saddr @{prefix}-{jail}{suffix} (?:reject|drop)\b"
            if not re.search(rf"(?m)^\s*{rule}", chain.stdout):
                return StepResult(name, Status.FAIL, f"Caddy {family}/{suffix} rule missing")
    return StepResult(name, Status.OK, "Caddy IPv4/IPv6 TCP and QUIC input rules active")


def _verify_access_policy(runner: Runner, direct: DirectAccess) -> None:
    parser = ConfigParser()
    parser.read_string(desired_caddy_filter(protected_paths=direct.protected_paths))
    expected = runner.run(
        [
            "/usr/bin/python3",
            "-I",
            "-c",
            "import sys; from fail2ban.server.failregex import FailRegex; "
            "print(FailRegex(sys.argv[1], useDns='no').getRegex())",
            parser["Definition"]["failregex"],
        ],
        check=False,
    )
    current = jail_setting(runner, direct.jail, "failregex")
    lines = current.splitlines() if current else []
    expected_lines = [
        "The following regular expression are defined:",
        f"`- [0]: {expected.stdout.strip()}",
    ]
    if not expected.ok or not expected.stdout.strip() or lines != expected_lines:
        raise JailError("live Caddy failregex does not match the attested policy")
    guard = jail_setting(runner, direct.jail, "ignorecommand")
    if guard != _access_guard(direct).replace("%%", "%"):
        raise JailError("live Caddy guard does not match the attested policy")


def _verify(
    runner: Runner,
    *,
    caddy_mode: CaddyMode,
    caddy_notice: str,
    caddy_jail: str | None,
    bantime: str = SSHD_BANTIME,
) -> list[StepResult]:
    results: list[StepResult] = []
    status = runner.run(["fail2ban-client", "status", "sshd"], check=False)
    if _client_missing(status):
        return [
            StepResult(
                "verify sshd jail",
                Status.SKIPPED,
                f"fail2ban-client unavailable (rc={status.returncode})",
            )
        ]
    if not status.ok or "sshd" not in status.stdout:
        detail = f"fail2ban-client status sshd rc={status.returncode}"
        if status.stderr.strip():
            detail += f": {status.stderr.strip()}"
        results.append(StepResult("verify sshd jail", Status.FAIL, detail))
        return results
    match = re.search(r"Currently banned:\s*(\d+)", status.stdout)
    banned = match.group(1) if match else "?"
    results.append(
        StepResult("verify sshd jail", Status.OK, f"active, currently banned: {banned}")
    )

    effective = jail_setting(runner, "sshd", "bantime")
    want = _seconds(bantime)
    if effective is None:
        results.append(
            StepResult(
                "verify bantime", Status.SKIPPED, "fail2ban-client get unavailable (needs root?)"
            )
        )
    elif effective.isdigit() and _seconds(effective) == want:
        results.append(StepResult("verify bantime", Status.OK, f"{bantime} effective"))
    else:
        results.append(
            StepResult("verify bantime", Status.FAIL, f"effective {effective}s, want {want}s")
        )

    increment = jail_increment_active(runner, "sshd")
    if increment is None:
        results.append(
            StepResult("verify bantime.increment", Status.SKIPPED, "fail2ban-client -d unavailable")
        )
    elif increment:
        results.append(
            StepResult("verify bantime.increment", Status.OK, "incrementing bans active")
        )
    else:
        results.append(
            StepResult(
                "verify bantime.increment", Status.FAIL, "bantime.increment not set for sshd"
            )
        )

    if caddy_jail is None:
        results.append(StepResult("verify caddy jail", Status.SKIPPED, caddy_notice))
        return results
    file_mode = caddy_mode == "file"
    jail = caddy_jail
    caddy_status = runner.run(["fail2ban-client", "status", jail], check=False)
    if caddy_status.ok and f"Status for the jail: {jail}" in caddy_status.stdout.splitlines():
        results.append(StepResult("verify caddy jail", Status.OK, "caddy jail active"))
        if file_mode:
            logpath = jail_setting(runner, jail, "logpath") or ""
            expected = f"`- {CADDY_ACCESS_LOG}"
            results.append(
                StepResult(
                    "verify caddy log path",
                    Status.OK if logpath.splitlines()[1:] == [expected] else Status.FAIL,
                    f"expected only {CADDY_ACCESS_LOG}",
                )
            )
            results.append(_verify_access_action(runner, jail))
    else:
        detail = f"fail2ban-client status {jail} rc={caddy_status.returncode}"
        if caddy_status.stderr.strip():
            detail += f": {caddy_status.stderr.strip().splitlines()[-1]}"
        results.append(StepResult("verify caddy jail", Status.FAIL, detail))
    return results


def _service_active(runner: Runner) -> bool:
    result = runner.run(["systemctl", "is-active", "fail2ban"], check=False)
    state = result.stdout.strip()
    if result.ok and state == "active":
        return True
    if result.returncode == 3 and state in {"inactive", "failed"}:
        return False
    if result.returncode == 4:
        load = runner.run(
            ["systemctl", "show", "--property=LoadState", "--value", "fail2ban"], check=False
        )
        if load.ok and load.stdout.strip() == "not-found":
            return False
    raise JailError("cannot determine stable fail2ban service state")


def _jail_live(runner: Runner, jail: str) -> bool:
    status = runner.run(["fail2ban-client", "status", jail], check=False)
    if status.ok and f"Status for the jail: {jail}" in status.stdout.splitlines():
        return True
    if status.returncode == 1 and f"jail '{jail}' does not exist" in status.stderr + status.stdout:
        return False
    raise JailError(f"cannot determine live state of fail2ban jail {jail}")


def _service_enable_state(runner: Runner) -> str:
    result = runner.run(["systemctl", "is-enabled", "fail2ban"], check=False)
    state = result.stdout.strip()
    if result.ok and state in {"enabled", "enabled-runtime"}:
        return state
    if result.returncode == 1 and state == "disabled":
        return state
    if not result.ok:
        load = runner.run(
            ["systemctl", "show", "--property=LoadState", "--value", "fail2ban"], check=False
        )
        if load.ok and load.stdout.strip() == "not-found":
            return "not-found"
    raise JailError("cannot determine fail2ban boot enable state")


def _restore_service_enable(runner: Runner, expected: str) -> None:
    current = _service_enable_state(runner)
    if expected == "not-found" and current != "not-found":
        # The failed install may have left a usable package; do not uninstall it.
        expected = "disabled"
    if current == expected:
        return
    if current != "disabled":
        runtime = ["--runtime"] if current == "enabled-runtime" else []
        runner.run(["systemctl", "disable", *runtime, "fail2ban"])
    if expected != "disabled":
        runtime = ["--runtime"] if expected == "enabled-runtime" else []
        runner.run(["systemctl", "enable", *runtime, "fail2ban"])
    if _service_enable_state(runner) != expected:
        raise JailError("could not restore fail2ban boot enable state")


def _restore_service_activity(runner: Runner, expected: bool) -> None:
    if _service_active(runner) != expected:
        runner.run(["systemctl", "start" if expected else "stop", "fail2ban"])
        if _service_active(runner) != expected:
            raise JailError("could not restore fail2ban running state")


def _activate(runner: Runner, *, was_active: bool) -> tuple[str, Status]:
    """Restart the jails when the daemon runs, enable --now when it does not.

    A plain ``systemctl reload`` (SIGHUP -> ``fail2ban-client reload``) breaks
    the banaction: fail2ban 1.0.2's reload never runs the action's
    ``actionstart``, and when ``banaction`` resolves to a new action name the
    reload deletes both the old and the freshly added action, leaving the jail
    with none (``fail2ban-client get sshd actions`` -> "No actions for jail
    sshd"). Bans then only reach the DB: ``set <jail> banip`` reports OK while
    the nftables table is never created and nothing is blocked.
    ``reload --restart`` stops and restarts the affected jails, so
    ``actionstart`` runs and recreates the table, while the server (and its
    socket) stays up; existing bans are kept (no ``--unban``).
    """
    if was_active:
        runner.run(["fail2ban-client", "reload", "--restart"])
        return "reload --restart fail2ban", Status.CHANGED
    runner.run(["systemctl", "enable", "--now", "fail2ban"])
    return "enable --now fail2ban", Status.CHANGED


def _configured_caddy(text: str) -> tuple[CaddyMode, str | None]:
    for match in re.finditer(rf"(?m)^\[(caddy|{ACCESS_JAIL_RE})\]\n", text):
        jail = match[1]
        body = text[match.end() :].split("\n[", 1)[0]
        if re.search(r"(?mi)^[ \t]*enabled[ \t]*=[ \t]*true[ \t]*$", body):
            return ("journald" if jail == "caddy" else "file"), jail
    return "off", None


def _verify_access_removed(runner: Runner, jail: str) -> None:
    names = {
        f"{prefix}-{stem}{suffix}"
        for stem in ({jail, "caddy-lhm"} if jail == ACCESS_JAIL else {jail})
        for prefix in ("addr-set", "addr6-set")
        for suffix in ("", "-quic")
    }
    result = runner.run(["nft", "--json", "list", "ruleset"], check=False)
    try:
        ruleset = json.loads(result.stdout)
        entries = ruleset.get("nftables") if isinstance(ruleset, dict) else None
        if (
            not result.ok
            or not isinstance(entries, list)
            or not all(isinstance(entry, dict) for entry in entries)
        ):
            raise ValueError("invalid nftables listing")
    except ValueError:
        raise JailError(f"cannot verify nftables cleanup for {jail}") from None

    def contains_name(node: object) -> bool:
        if isinstance(node, str):
            return node.removeprefix("@") in names
        if isinstance(node, dict):
            return any(contains_name(value) for value in node.values())
        if isinstance(node, list):
            return any(contains_name(value) for value in node)
        return False

    if any(
        contains_name(entry.get("set")) or contains_name(entry.get("rule")) for entry in entries
    ):
        raise JailError(
            f"old nftables sets or rules remain for {jail}; "
            "resolve cleanup and rerun lhm apply fail2ban --caddy-revoke-direct"
        )


def _stop_access_jail(runner: Runner, jail: str) -> bool:
    if external := _external_caddy_jail(jail):
        raise JailError(f"refusing to stop {jail}: also configured by {external}")
    stopped = _service_active(runner) and _jail_live(runner, jail)
    if stopped:
        runner.run(["fail2ban-client", "stop", jail])
        if _jail_live(runner, jail):
            raise JailError(f"outdated fail2ban jail {jail} is still active")
    _verify_access_removed(runner, jail)
    return stopped


def _without_access_jail(text: str, jail: str) -> str:
    section = f"[{jail}]\n"
    start = text.index(f"\n{section}") + 1
    body = start + len(section)
    rest = re.search(r"(?m)^\[", text[body:])
    before = start - 1 if text[start - 2 : start] == "\n\n" else start
    return text[:before] + ("" if rest is None else text[body + rest.start() :])


def _pending_access_cleanup(text: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(_PENDING_REVOKE)}({ACCESS_JAIL_RE})$", text)
    return match[1] if match else None


def _sync_jail_directory() -> None:
    fd = os.open(JAIL_DROPIN.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _record_access_revocation(current: str, jail: str) -> str:
    # Revocation is irreversible: next boot must not reload this policy even
    # if stop, cleanup verification, or a later configuration test fails.
    if external := _external_caddy_jail(jail):
        raise JailError(f"refusing to revoke {jail}: also configured by {external}")
    if _managed_text(JAIL_DROPIN, JAIL_HEADER) != current:
        raise JailError("fail2ban drop-in changed before Caddy revocation")
    safe = _without_access_jail(current, jail)
    pending = f"{JAIL_HEADER}{_PENDING_REVOKE}{jail}\n{safe.removeprefix(JAIL_HEADER)}"
    _write_managed(JAIL_DROPIN, pending)
    _sync_jail_directory()
    return pending


def _revoke_access_jail(runner: Runner, current: str, jail: str) -> None:
    if _pending_access_cleanup(current) == jail:
        pending = current
        _sync_jail_directory()
    else:
        pending = _record_access_revocation(current, jail)
    _stop_access_jail(runner, jail)
    if _managed_text(JAIL_DROPIN, JAIL_HEADER) != pending:
        raise JailError("fail2ban drop-in changed during Caddy revocation")
    safe = pending.removeprefix(f"{JAIL_HEADER}{_PENDING_REVOKE}{jail}\n")
    _write_managed(JAIL_DROPIN, JAIL_HEADER + safe)
    _sync_jail_directory()


def stop_managed_caddy_access(runner: Runner, *, revoke: bool = False) -> bool:
    """Stop the file jail while the Caddy caller holds its outer transaction lock."""
    current = _managed_text(JAIL_DROPIN, JAIL_HEADER)
    if _configured_caddy(current or "")[0] != "file" and not _pending_access_cleanup(current or ""):
        return False
    with locked_target(JAIL_DROPIN.parents[1]):
        current = _managed_text(JAIL_DROPIN, JAIL_HEADER) or ""
        mode, jail = _configured_caddy(current)
        if pending := _pending_access_cleanup(current):
            _revoke_access_jail(runner, current, pending)
            return True
        if mode != "file" or jail is None:
            return False
        if not revoke:
            return _stop_access_jail(runner, jail)
        _revoke_access_jail(runner, current, jail)
        return True


def _apply_revoke(runner: Runner, current: str, jail: str | None) -> list[StepResult]:
    name = "revoke direct Caddy policy"
    if jail is None:
        return [StepResult(name, Status.SKIPPED, "no managed Caddy file jail")]
    plan = [f"Plan: remove {jail} from {JAIL_DROPIN} and verify firewall cleanup; SSH unchanged"]
    if runner.dry_run:
        print(plan[0])
        return [StepResult(name, Status.PLANNED)]
    if not confirm_once(plan):
        return [StepResult(name, Status.ABORTED, "aborted; no changes made")]
    _revoke_access_jail(runner, current, jail)
    return [StepResult(name, Status.CHANGED)]


def _check_caddy_precedence(mode: CaddyMode, filter_path: Path, content: str) -> None:
    if mode not in {"file", "journald"}:
        return
    if external := _external_caddy_jail():
        raise JailError(f"Caddy jail precedence changed: {external}")
    override = filter_path.with_suffix(".local")
    if override.exists() or override.is_symlink():
        raise JailError(f"Caddy filter override appeared: {override}")
    header = ACCESS_FILTER_HEADER if mode == "file" else LEGACY_FILTER_HEADER
    if _managed_text(filter_path, header) != content:
        raise JailError(f"Caddy filter changed: {filter_path}")


def _restore_access_transaction(
    runner: Runner,
    backups: dict[Path, Path | None],
    *,
    attempted: bool,
    was_active: bool,
    prior_jail: str | None,
    new_jail: str | None,
    revoked_prior: str | None,
    prior_text: str | None,
) -> None:
    # Disarm the failed policy persistently before restoring unrelated settings.
    cleanup_jail = revoked_prior
    if attempted and new_jail is not None and new_jail != prior_jail:
        cleanup_jail = cleanup_jail or new_jail
    cleanup_error: Exception | None = None
    if cleanup_jail is not None:
        try:
            current = _managed_text(JAIL_DROPIN, JAIL_HEADER) or ""
            _revoke_access_jail(runner, current, cleanup_jail)
        except (OSError, ValueError, CommandError) as exc:
            cleanup_error = exc
    pending_jail = cleanup_jail if cleanup_error is not None else None
    for path, backup in reversed(backups.items()):
        if path == JAIL_DROPIN and (pending_jail is not None or revoked_prior is not None):
            safe = prior_text or JAIL_HEADER
            if revoked_prior is not None:
                safe = _without_access_jail(safe, revoked_prior)
            if pending_jail is not None:
                body = safe.removeprefix(JAIL_HEADER)
                safe = f"{JAIL_HEADER}{_PENDING_REVOKE}{pending_jail}\n{body}"
            _write_managed(JAIL_DROPIN, safe)
            _sync_jail_directory()
        elif backup is None:
            remove_file(path, missing_ok=True)
        else:
            rollback_file(path, backup=backup)
    if pending_jail is not None:
        # Keep the cleanup identity across retries without enabling the jail.
        current = _managed_text(JAIL_DROPIN, JAIL_HEADER) or JAIL_HEADER
        if _pending_access_cleanup(current) != pending_jail:
            pending = (
                f"{JAIL_HEADER}{_PENDING_REVOKE}{pending_jail}\n{current.removeprefix(JAIL_HEADER)}"
            )
            _write_managed(JAIL_DROPIN, pending)
            _sync_jail_directory()
    if attempted:
        active = _service_active(runner)
        if was_active:
            runner.run(["fail2ban-client", "-t"])
            if active:
                runner.run(["fail2ban-client", "reload", "--restart"])
            else:
                runner.run(["systemctl", "start", "fail2ban"])
            if not _jail_live(runner, "sshd") or (
                prior_jail is not None and not _jail_live(runner, prior_jail)
            ):
                raise JailError("previous fail2ban jails did not recover")
            if prior_jail and re.fullmatch(ACCESS_JAIL_RE, prior_jail):
                policy = _read_direct_access(prior_text or "")
                if policy is None or policy.jail != prior_jail:
                    raise JailError("cannot verify prior Caddy policy")
                try:
                    _verify_access_policy(runner, policy)
                except JailError:
                    restored = _managed_text(JAIL_DROPIN, JAIL_HEADER)
                    if restored is not None:
                        _revoke_access_jail(runner, restored, prior_jail)
                    raise
                result = _verify_access_action(runner, prior_jail)
                if result.status is Status.FAIL:
                    raise JailError(result.detail)
        elif active:
            _restore_service_activity(runner, False)
    if cleanup_error:
        raise cleanup_error


def _select_caddy(
    *, legacy: bool, current: CaddyMode, direct: DirectAccess | None
) -> tuple[CaddyMode, str]:
    external = _external_caddy_jail()
    if external is not None:
        return "unmanaged", f"preserving unmanaged Caddy jail in {external}"
    if direct is not None:
        mode: CaddyMode = "file"
    elif legacy or current == "journald":
        mode = "journald"
    else:
        return "off", "no validated direct-client Caddy access log; no automatic bans"
    path, header = (
        (CADDY_FILTER, LEGACY_FILTER_HEADER)
        if mode == "journald"
        else (CADDY_ACCESS_FILTER, ACCESS_FILTER_HEADER)
    )
    override = path.with_suffix(".local")
    if override.exists() or override.is_symlink():
        return "unmanaged", f"preserving unmanaged Caddy filter override {override}"
    try:
        _managed_text(path, header)
    except JailError as exc:
        return "unmanaged", str(exc)
    return mode, ""


def apply_fail2ban(
    runner: Runner,
    *,
    bantime: str = SSHD_BANTIME,
    findtime: str = SSHD_FINDTIME,
    maxretry: str = SSHD_MAXRETRY,
    caddy: bool = False,
    caddy_maxretry: str = CADDY_MAXRETRY,
    caddy_direct: bool = False,
    caddy_protected_paths: tuple[str, ...] = (),
    caddy_revoke_direct: bool = False,
) -> list[StepResult]:
    from lhm.modules import caddy as caddy_module

    def apply() -> list[StepResult]:
        return _apply_fail2ban_locked(
            runner,
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            caddy=caddy,
            caddy_maxretry=caddy_maxretry,
            caddy_direct=caddy_direct,
            caddy_protected_paths=caddy_protected_paths,
            caddy_revoke_direct=caddy_revoke_direct,
        )

    if runner.dry_run:
        return apply()
    try:
        with locked_target(caddy_module.CADDYFILE.parent), locked_target(JAIL_DROPIN.parents[1]):
            return apply()
    except (CommandError, OSError, ValueError, KeyboardInterrupt) as exc:
        return [StepResult("fail2ban", Status.FAIL, str(exc))]


def _apply_fail2ban_locked(
    runner: Runner,
    *,
    bantime: str,
    findtime: str,
    maxretry: str,
    caddy: bool,
    caddy_maxretry: str,
    caddy_direct: bool,
    caddy_protected_paths: tuple[str, ...],
    caddy_revoke_direct: bool,
) -> list[StepResult]:
    try:
        # Validate inputs before the Caddy readiness probe.
        _time_value("bantime", bantime)
        _time_value("findtime", findtime)
        _retry_value("maxretry", maxretry)
        _retry_value("caddy_maxretry", caddy_maxretry)
        if caddy_direct != bool(caddy_protected_paths) or (caddy and caddy_direct):
            raise JailError(
                "--caddy-direct requires --caddy-protected-path and cannot be used with --caddy"
            )
        if caddy_revoke_direct and (caddy or caddy_direct):
            raise JailError("--caddy-revoke-direct cannot be used with either Caddy mode")
        if caddy_direct:
            _protected_paths(caddy_protected_paths)
        current = _managed_text(JAIL_DROPIN, JAIL_HEADER)
        current_mode, previous_jail = _configured_caddy(current or "")
        pending = _pending_access_cleanup(current or "")
        if caddy_revoke_direct or pending is not None:
            # A pending cleanup must finish before another policy may be installed.
            revoke_jail = pending or (previous_jail if current_mode == "file" else None)
            cleaned = _apply_revoke(runner, current or "", revoke_jail)
            if not caddy_revoke_direct and cleaned[-1].status is not Status.ABORTED:
                cleaned.append(
                    StepResult(
                        "apply fail2ban settings",
                        Status.FAIL,
                        "settings not applied; rerun the original request after cleanup",
                    )
                )
            return cleaned
        previous_direct = _read_direct_access(current or "") if current_mode == "file" else None
        if previous_direct is not None and previous_direct.jail != previous_jail:
            previous_direct = None
        direct = None
        if not caddy and (caddy_direct or previous_direct is not None):
            if runner.dry_run:
                digest = previous_direct.digest if previous_direct else "0" * 64
            else:
                digest = _caddy_runtime_digest(runner)
            if digest is not None:
                if caddy_direct:
                    generation = "0" * 32 if runner.dry_run else secrets.token_hex(16)
                    direct = DirectAccess(digest, caddy_protected_paths, generation)
                elif previous_direct is not None and previous_direct.digest == digest:
                    direct = previous_direct
        caddy_mode, caddy_notice = _select_caddy(legacy=caddy, current=current_mode, direct=direct)
        direct_refused = caddy_direct and caddy_mode != "file"
        if direct_refused and caddy_mode in {"off", "journald"}:
            caddy_notice = f"could not verify active managed Caddy and {CADDY_ACCESS_LOG}"
        if direct_refused and current_mode != "file":
            return [StepResult("caddy direct attestation", Status.FAIL, caddy_notice)]
        stale_direct = current_mode == "file" and (
            caddy_mode != "file" or previous_direct != direct
        )
        if stale_direct and caddy_mode == "off":
            caddy_notice = "Caddy direct attestation expired or configuration changed; disabling"
        desired = desired_conf(
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            caddy_maxretry=caddy_maxretry,
            caddy_mode=caddy_mode,
            direct=direct,
        )
        file_mode = caddy_mode == "file"
        use_caddy = caddy_mode in {"journald", "file"}
        caddy_jail = direct.jail if file_mode and direct else ("caddy" if use_caddy else None)
        filter_path = CADDY_ACCESS_FILTER if file_mode else CADDY_FILTER
        protected_paths = direct.protected_paths if file_mode and direct else ()
        caddy_filter = desired_caddy_filter(protected_paths=protected_paths) if use_caddy else ""
    except (OSError, ValueError) as exc:
        return [StepResult("fail2ban", Status.FAIL, str(exc))]

    backend = AptBackend(runner)
    installed = [p for p in PACKAGES if not runner.dry_run and backend.pkg_installed(p)]
    missing = [p for p in PACKAGES if p not in installed]
    first_install = "fail2ban" in missing
    jail_needed = current != desired
    previous_filter = _read(filter_path) if use_caddy else None
    filter_needed = use_caddy and previous_filter != caddy_filter
    # Dry-run executes nothing (not even read-only probes), so the activation
    # branch and the caddy unit check are only known at apply time.
    was_active: bool | None = None if runner.dry_run else _service_active(runner)
    original_active = bool(was_active)
    access_missing = bool(
        was_active
        and file_mode
        and caddy_jail
        and not jail_needed
        and not _jail_live(runner, caddy_jail)
    )
    unit_present = (
        caddy_unit_present(runner) if caddy_mode == "journald" and not runner.dry_run else None
    )

    plan = ["Plan (fail2ban):"]
    if missing:
        plan.append(f"  - install {' '.join(missing)}")
        if first_install:
            plan.append("  - on failure restore service state; installed packages may remain")
    else:
        plan.append(f"  - {' '.join(PACKAGES)} already installed")
    plan.append(
        f"  - write {JAIL_DROPIN} (sshd jail: port {SSH_PORT}, mode aggressive, "
        f"maxretry {maxretry}, findtime {findtime}, bantime {bantime}, "
        f"bantime.increment 2^n factor 3 maxtime 4w)"
        if jail_needed
        else f"  - {JAIL_DROPIN} already current (skip)"
    )
    if use_caddy:
        plan.append(
            f"  - write {filter_path} (caddy jail: port {CADDY_PORTS}, "
            f"maxretry {caddy_maxretry}, findtime 10m, bantime 1h)"
            if filter_needed
            else f"  - {filter_path} already current (skip)"
        )
        if file_mode:
            plan.append(f"  - caddy jail enabled in the drop-in (JSON file {CADDY_ACCESS_LOG})")
            plan.append(f"  - only 401 responses on attested paths: {', '.join(protected_paths)}")
        else:
            plan.append(f"  - caddy jail enabled in the drop-in (journald unit {CADDY_UNIT})")
            plan.append("  - WARNING: legacy journald jail retains its broader status-code policy")
        if caddy_mode == "journald" and unit_present is False:
            plan.append(
                f"  - WARNING: {CADDY_UNIT} does not exist; fail2ban will fail to start "
                "until Caddy is installed (install caddy, then re-run)"
            )
        elif caddy_mode == "journald" and unit_present is None:
            plan.append(f"  - WARNING: cannot confirm {CADDY_UNIT} in dry-run")
    else:
        plan.append(f"  - {caddy_notice}")
    if runner.dry_run:
        plan.append("  - Caddy runtime and direct eligibility are checked only on apply")
    if was_active is None:
        plan.append(
            "  - reload --restart fail2ban if active (a plain reload leaves the jail "
            "with no action, see _activate), else enable --now"
        )
    elif was_active:
        plan.append(
            "  - fail2ban-client reload --restart (restarts the jails so actionstart "
            "runs; the server and its bans stay up)"
        )
    else:
        plan.append("  - systemctl enable --now fail2ban")
    plan.append(
        f"  - note: a legacy {LEGACY_JAIL_LOCAL} is preserved untouched; "
        "jail.d/*.local wins over it"
    )
    plan.append("  - risk: check your own IP is not banned before closing the session")

    if runner.dry_run:
        for line in plan:
            print(line)
        results: list[StepResult] = []
        if missing:
            backend.install(missing)
            results.append(StepResult(f"install {' '.join(missing)}", Status.PLANNED))
        else:
            results.append(StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"))
        results.append(
            StepResult(
                f"write {JAIL_DROPIN}",
                Status.PLANNED if jail_needed else Status.SKIPPED,
                "" if jail_needed else "already current",
            )
        )
        if use_caddy:
            results.append(
                StepResult(
                    f"write {filter_path}",
                    Status.PLANNED if filter_needed else Status.SKIPPED,
                    "" if filter_needed else "already current",
                )
            )
        runner.run(["systemctl", "enable", "--now", "fail2ban"])
        results.append(StepResult("enable --now fail2ban", Status.PLANNED))
        return results

    if not jail_needed and not filter_needed and not missing and was_active and not access_missing:
        if file_mode and direct and current is not None:
            try:
                _verify_access_policy(runner, direct)
            except JailError as exc:
                _revoke_access_jail(runner, current, direct.jail)
                return [StepResult("revoke mismatched Caddy policy", Status.FAIL, str(exc))]
        results = [
            StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"),
            StepResult(f"write {JAIL_DROPIN}", Status.SKIPPED, "already current"),
        ]
        if use_caddy:
            results.append(StepResult(f"write {filter_path}", Status.SKIPPED, "already current"))
        results.append(StepResult("reload --restart fail2ban", Status.SKIPPED, "already active"))
        results.extend(
            _verify(
                runner,
                caddy_mode=caddy_mode,
                caddy_notice=caddy_notice,
                caddy_jail=caddy_jail,
                bantime=bantime,
            )
        )
        return results

    if not confirm_once(plan):
        return [StepResult("fail2ban", Status.ABORTED, "aborted; no changes made")]

    results = []
    backups: dict[Path, Path | None] = {}
    transactional = first_install or file_mode or current_mode == "file"
    attempted = False
    install_attempted = False
    before_enable = None
    prior_jail = previous_jail
    revoked_prior = None
    try:
        if (
            _managed_text(JAIL_DROPIN, JAIL_HEADER) != current
            or (use_caddy and _read(filter_path) != previous_filter)
            or (use_caddy and _external_caddy_jail() is not None)
            or _service_active(runner) != was_active
        ):
            raise JailError("fail2ban inputs changed during confirmation; re-run to recompute")
        if transactional:
            before_enable = _service_enable_state(runner)
        if stale_direct and current is not None and previous_jail is not None:
            _revoke_access_jail(runner, current, previous_jail)
            current = _without_access_jail(current, previous_jail)
            prior_jail = None
            jail_needed = current != desired
            results.append(StepResult("revoke outdated Caddy jail", Status.CHANGED))
        if missing:
            install_attempted = first_install
            backend.install(missing)
            results.append(StepResult(f"install {' '.join(missing)}", Status.CHANGED))
            was_active = _service_active(runner)
        else:
            results.append(StepResult(f"install {' '.join(PACKAGES)}", Status.SKIPPED, "installed"))
        if file_mode and direct and _caddy_runtime_digest(runner) != direct.digest:
            if current is not None and prior_jail is not None and current_mode == "file":
                _revoke_access_jail(runner, current, prior_jail)
            raise JailError("Caddy direct-client eligibility changed; re-run to recompute the plan")
        if use_caddy:
            outcome = _write_managed(
                filter_path, caddy_filter, backups=backups if transactional else None
            )
            results.append(
                StepResult(
                    f"write {filter_path}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        if jail_needed:
            outcome = _write_managed(
                JAIL_DROPIN, desired, backups=backups if transactional else None
            )
            results.append(
                StepResult(
                    f"write {JAIL_DROPIN}",
                    Status.CHANGED if outcome == "written" else Status.SKIPPED,
                )
            )
        else:
            results.append(StepResult(f"write {JAIL_DROPIN}", Status.SKIPPED, "already current"))
        if transactional:
            _check_caddy_precedence(caddy_mode, filter_path, caddy_filter)
            runner.run(["fail2ban-client", "-t"])
        _check_caddy_precedence(caddy_mode, filter_path, caddy_filter)
        attempted = True
        name, status = _activate(runner, was_active=bool(was_active))
        results.append(StepResult(name, status))
        if file_mode and direct:
            try:
                _verify_access_policy(runner, direct)
            except JailError:
                if prior_jail == direct.jail:
                    revoked_prior = prior_jail
                    prior_jail = None
                raise
        verification = _verify(
            runner,
            caddy_mode=caddy_mode,
            caddy_notice=caddy_notice,
            caddy_jail=caddy_jail,
            bantime=bantime,
        )
        results.extend(verification)
        if transactional and (
            any(result.status is Status.FAIL for result in verification)
            or not verification
            or verification[0].status is not Status.OK
        ):
            raise JailError("running fail2ban configuration failed verification")
        if file_mode and direct and _caddy_runtime_digest(runner) != direct.digest:
            if prior_jail is not None and prior_jail == caddy_jail:
                # This policy is no longer attested even if it was active before.
                revoked_prior = prior_jail
                prior_jail = None
            raise JailError("Caddy direct-client eligibility changed during activation")
        if direct_refused and first_install:
            raise JailError(caddy_notice)
        backups.clear()
    except (CommandError, OSError, ValueError, KeyboardInterrupt) as exc:
        if transactional and (backups or attempted):
            try:
                _restore_access_transaction(
                    runner,
                    backups,
                    attempted=attempted,
                    was_active=original_active,
                    prior_jail=prior_jail,
                    new_jail=caddy_jail if file_mode else None,
                    revoked_prior=revoked_prior,
                    prior_text=current,
                )
            except (CommandError, OSError, ValueError) as error:
                results.append(
                    StepResult("reconcile previous fail2ban state", Status.FAIL, str(error))
                )
        if install_attempted:
            try:
                _restore_service_activity(runner, original_active)
            except (CommandError, OSError, ValueError) as error:
                results.append(
                    StepResult("restore fail2ban running state", Status.FAIL, str(error))
                )
        if (attempted or install_attempted) and before_enable is not None:
            try:
                _restore_service_enable(runner, before_enable)
            except (CommandError, OSError, ValueError) as error:
                results.append(
                    StepResult("restore fail2ban boot enable state", Status.FAIL, str(error))
                )
        detail = str(exc) or "interrupted"
        if install_attempted:
            detail += "; installed packages may remain"
        results.append(StepResult("fail2ban", Status.FAIL, detail))
        return results

    if direct_refused:
        results.append(StepResult("caddy direct attestation", Status.FAIL, caddy_notice))
    return results


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    try:
        installed = AptBackend(runner).pkg_installed("fail2ban") if probe_package else None
    except DistroError:
        installed = None
    try:
        active = _service_active(runner)
    except JailError:
        active = None
    current = _read(JAIL_DROPIN)
    caddy_mode, caddy_jail = _configured_caddy(current or "")
    try:
        caddy_live = _jail_live(runner, caddy_jail) if caddy_jail is not None else None
    except JailError:
        caddy_live = None
    direct = _read_direct_access(current or "") if caddy_mode == "file" else None
    caddy_enabled = (
        caddy_mode != "off"
        if current and ("\n[caddy]\n" in current or caddy_mode == "file")
        else None
    )
    filter_path = CADDY_ACCESS_FILTER if caddy_mode == "file" else CADDY_FILTER
    expected_mode: CaddyMode = caddy_mode if caddy_enabled is not None else "unmanaged"
    reported_mode = caddy_mode
    if current is not None and caddy_enabled is None:
        try:
            if _external_caddy_jail() is not None:
                reported_mode = "unmanaged"
        except OSError:
            pass
    dbfile, dbfile_present = dbfile_path(runner)
    return {
        "package": "fail2ban",
        "nftables_dependency": "explicitly installed by lhm",
        "installed": installed,
        "active": active,
        "jail_dropin": str(JAIL_DROPIN),
        "jail_current": (
            current == desired_conf(caddy_mode=expected_mode, direct=direct)
            if expected_mode != "file" or direct is not None
            else False
        ),
        "caddy_filter": str(filter_path),
        "caddy_filter_present": filter_path.is_file(),
        "caddy_enabled": caddy_enabled,
        "caddy_mode": reported_mode,
        "caddy_jail": caddy_jail,
        "caddy_jail_live": caddy_live,
        "legacy_jail_local": str(LEGACY_JAIL_LOCAL),
        "legacy_jail_local_present": LEGACY_JAIL_LOCAL.is_file(),
        "dbfile": str(dbfile),
        "dbfile_present": dbfile_present,
    }


class Fail2banModule:
    name = "fail2ban"
    description = "Install fail2ban and write the jail.d drop-in for sshd (+caddy)"
    implemented = True

    def apply(
        self,
        runner: Runner,
        *,
        bantime: str = SSHD_BANTIME,
        findtime: str = SSHD_FINDTIME,
        maxretry: str = SSHD_MAXRETRY,
        caddy: bool = False,
        caddy_maxretry: str = CADDY_MAXRETRY,
        caddy_direct: bool = False,
        caddy_protected_paths: tuple[str, ...] = (),
        caddy_revoke_direct: bool = False,
    ) -> list[StepResult]:
        return apply_fail2ban(
            runner,
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            caddy=caddy,
            caddy_maxretry=caddy_maxretry,
            caddy_direct=caddy_direct,
            caddy_protected_paths=caddy_protected_paths,
            caddy_revoke_direct=caddy_revoke_direct,
        )
