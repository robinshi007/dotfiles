"""Install and manage a single Caddy HTTPS reverse proxy."""

import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import struct
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from lhm.core import network
from lhm.core.backup import backup_file, rollback_file
from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend, DistroError
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

PACKAGE = "caddy"
UNIT = "caddy.service"
CADDY_BINARY = Path("/usr/bin/caddy")
VENDOR_UNIT_DIRS = (Path("/usr/lib/systemd/system"), Path("/lib/systemd/system"))
CADDYFILE = Path("/etc/caddy/Caddyfile")
INSTALL_HOLD = Path("/etc/systemd/system/caddy.service.d/zz-lhm-install-hold.conf")
ADMIN_SOCKET = Path("/var/lib/caddy/lhm-admin.sock")
ACCESS_LOG = Path("/var/log/caddy/access.log")
ROLL_SIZE = "100MiB"
ROLL_KEEP = 10
MARKER = "# lhm-managed Caddyfile"
ROOT_UID = 0
_SERVICE_FIELDS = "ActiveState,UnitFileState,LoadState,InvocationID,MainPID"
_NO_UNIT_OVERRIDES = (
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
    "RootDirectory",
    "RootImage",
    "RootImageOptions",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
    "MountImages",
    "ExtensionImages",
    "ExtensionDirectories",
    "InaccessiblePaths",
    "ReadOnlyPaths",
    "ReadWritePaths",
    "ExecPaths",
    "NoExecPaths",
    "ConfigurationDirectory",
    "StateDirectory",
    "RuntimeDirectory",
    "CacheDirectory",
    "LogsDirectory",
    "Environment",
    "EnvironmentFiles",
    "PassEnvironment",
    "PAMName",
)
_EXEC_FIELDS = ",".join(
    (
        "ExecStart",
        "ExecReload",
        "User",
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        *_NO_UNIT_OVERRIDES,
    )
)
_CURL = ("curl", "--disable", "--noproxy", "*", "--connect-timeout", "1", "--max-time", "3", "-sS")
_ROUTE_PROBE = "/_lhm-caddy-check/segment%2Fleaf?next=https%3A%2F%2Fexample.invalid%2F&n=2"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_SITE = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}", re.ASCII | re.IGNORECASE)
_UPSTREAM = re.compile(r"(?:http://)?(localhost|[0-9.]+|\[[0-9a-f:]+\]):([0-9]{1,5})", re.I)


class CaddyError(ValueError):
    """An unsafe configuration or service state."""


@dataclass(frozen=True)
class RunningConfig:
    invocation_id: str
    fingerprint: str
    site: str
    access_log: Path
    wire_fingerprint: str


@dataclass(frozen=True)
class _Service:
    active: bool
    enable: str
    load: str
    invocation_id: str
    pid: int


def _site(value: str) -> str:
    if len(value) > 253 or not _SITE.fullmatch(value) or value.rsplit(".", 1)[-1].isdigit():
        raise CaddyError("site must be a DNS hostname (no scheme, port, wildcard or path)")
    return value.lower()


def _upstream(value: str) -> str:
    match = _UPSTREAM.fullmatch(value)
    if match is not None:
        host, raw_port = match.groups()
        port = int(raw_port)
        try:
            address = ipaddress.ip_address(
                "127.0.0.1" if host.lower() == "localhost" else host.strip("[]")
            )
        except ValueError:
            pass
        else:
            if address.is_loopback and 1 <= port <= 65535:
                return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    raise CaddyError("upstream must be a loopback host:port (e.g. 127.0.0.1:8080 or [::1]:8080)")


def desired_conf(*, site: str, upstream: str) -> str:
    return render_template(
        "Caddyfile.tmpl",
        site=_site(site),
        upstream=_upstream(upstream),
        admin_socket=str(ADMIN_SOCKET),
        access_log=str(ACCESS_LOG),
        roll_size=ROLL_SIZE,
        roll_keep=str(ROLL_KEEP),
    )


@contextmanager
def _trusted_dir(path: Path) -> Iterator[int]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != ROOT_UID or metadata.st_mode & 0o022:
            raise CaddyError(f"unsafe directory: {path}")
        yield fd
    finally:
        os.close(fd)


def _read(path: Path) -> str | None:
    try:
        with _trusted_dir(path.parent) as parent:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=parent,
            )
            with os.fdopen(fd, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != ROOT_UID
                    or metadata.st_mode & 0o022
                    or metadata.st_nlink != 1
                ):
                    raise CaddyError(f"unsafe managed file: {path}")
                return handle.read().decode("utf-8")
    except FileNotFoundError:
        return None


def _sync_dir(directory: Path) -> None:
    with _trusted_dir(directory) as fd:
        os.fsync(fd)


def _managed_settings(text: str | None) -> tuple[str, str] | None:
    if text is not None:
        lines = text.splitlines()
        if len(lines) >= 3 and lines[0] == MARKER:
            site = lines[1].removeprefix("# site: ")
            upstream = lines[2].removeprefix("# upstream: ")
            try:
                if text == desired_conf(site=site, upstream=upstream):
                    return site, upstream
            except CaddyError:
                pass
    return None


def _read_managed() -> tuple[str, str] | None:
    try:
        return _managed_settings(_read(CADDYFILE))
    except OSError, ValueError:
        return None


def managed_access_log() -> Path | None:
    """Detect LHM's log configuration; this does not attest direct ingress."""
    return ACCESS_LOG if _read_managed() is not None else None


def _hold_content() -> str:
    return render_template("caddy-install-hold.conf.tmpl", hold=str(INSTALL_HOLD))


def _installation_held() -> bool:
    content = _read(INSTALL_HOLD)
    if content is not None and content != _hold_content():
        raise CaddyError(f"refusing to change unmanaged installation hold: {INSTALL_HOLD}")
    return content is not None


def _check_unit_dropins(runner: Runner) -> None:
    paths = runner.capture(["systemctl", "show", "--property=UnitPath", "--value"]).split()
    if str(INSTALL_HOLD.parent.parent) not in paths or not all(
        Path(p).is_absolute() for p in paths
    ):
        raise CaddyError("cannot verify systemd unit drop-in search paths")
    for root in map(Path, paths):
        for directory in (root / "service.d", root / f"{UNIT}.d"):
            try:
                overrides = [
                    p for p in directory.iterdir() if p.suffix == ".conf" and p != INSTALL_HOLD
                ]
            except FileNotFoundError:
                continue
            if overrides:
                raise CaddyError(f"unexpected on-disk Caddy systemd drop-in: {overrides[0]}")


def _mask_on_disk() -> bool:
    with _trusted_dir(INSTALL_HOLD.parent.parent) as parent:
        try:
            return os.readlink(UNIT, dir_fd=parent) == "/dev/null"
        except FileNotFoundError:
            return False


def _verify_exec(runner: Runner) -> Path:
    _check_unit_dropins(runner)
    with _trusted_dir(CADDY_BINARY.parent) as parent:
        binary = os.stat(CADDY_BINARY.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(binary.st_mode)
            or binary.st_uid != ROOT_UID
            or binary.st_mode & 0o022
            or not binary.st_mode & stat.S_IXUSR
        ):
            raise CaddyError(f"unsafe Caddy service executable: {CADDY_BINARY}")
    output = runner.capture(["systemctl", "show", "--all", f"--property={_EXEC_FIELDS}", UNIT])
    fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if fields.get("NeedDaemonReload") != "no":
        raise CaddyError("Caddy effective unit has pending or unverified systemd changes")
    fragment = Path(fields.get("FragmentPath", ""))
    if (
        fragment not in {directory / UNIT for directory in VENDOR_UNIT_DIRS}
        or _read(fragment) is None
    ):
        raise CaddyError("Caddy service is not using a trusted distro unit fragment")
    dropins = fields.get("DropInPaths", "").split()
    if dropins and (dropins != [str(INSTALL_HOLD)] or not _installation_held()):
        raise CaddyError("unexpected Caddy systemd drop-ins")
    if fields.get("User") != "caddy" or any(fields.get(key) for key in _NO_UNIT_OVERRIDES):
        raise CaddyError("unexpected Caddy systemd account, mount, environment or lifecycle hook")
    for key, arguments in (
        ("ExecStart", f"run --environ --config {CADDYFILE}"),
        ("ExecReload", f"reload --config {CADDYFILE} --force"),
    ):
        prefix = f"{{ path={CADDY_BINARY} ; argv[]={CADDY_BINARY} {arguments} ; ignore_errors=no ;"
        text = fields.get(key, "")
        if not text.startswith(prefix) or text.count("{") != 1 or text.count("}") != 1:
            raise CaddyError(f"unexpected effective {key} for {UNIT}")
    return fragment


def _set_hold(runner: Runner, *, held: bool, require_inactive: bool = True) -> None:
    was_held = _installation_held()
    if held:
        ensure_dir(INSTALL_HOLD.parent, mode=0o755)
        with _trusted_dir(INSTALL_HOLD.parent) as fd:
            write_dropin(INSTALL_HOLD, _hold_content(), mode=0o644)
            os.fsync(fd)
        # Check the filesystem, not only the manager's cached unit state.
        _sync_dir(INSTALL_HOLD.parent.parent)
        runner.run(["systemctl", "mask", UNIT])
        runner.run(["systemctl", "daemon-reload"])
        _verify_held(runner, require_inactive=require_inactive)
        _sync_dir(INSTALL_HOLD.parent.parent)
    elif was_held:
        # Never release the hard mask before the validated config is durable.
        _sync_dir(CADDYFILE.parent)
        _check_unit_dropins(runner)
        runner.run(["systemctl", "unmask", UNIT])
        if _mask_on_disk():
            raise CaddyError(f"persistent mask remains in place for {UNIT}")
        _sync_dir(INSTALL_HOLD.parent.parent)
        runner.run(["systemctl", "daemon-reload"])
        # The condition remains in effect while inspecting the unmasked unit.
        _verify_exec(runner)
        with _trusted_dir(INSTALL_HOLD.parent) as fd:
            remove_file(INSTALL_HOLD)
            os.fsync(fd)
        runner.run(["systemctl", "daemon-reload"])


def _packaged_default(runner: Runner, text: str) -> bool:
    # dpkg records a checksum of the vendor conffile, not of the host's edits.
    conffiles = runner.capture(["dpkg-query", "-W", "-f=${Conffiles}", PACKAGE])
    digest = hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()
    return any(line.split() == [str(CADDYFILE), digest] for line in conffiles.splitlines())


def _service(runner: Runner) -> _Service:
    result = runner.run(["systemctl", "show", f"--property={_SERVICE_FIELDS}", UNIT], check=False)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    load = fields.get("LoadState", "")
    active = fields.get("ActiveState", "")
    if (not result.ok and load != "not-found") or active not in {"active", "inactive", "failed"}:
        raise CaddyError(f"cannot determine stable status of {UNIT}")
    raw_pid = fields.get("MainPID", "")
    return _Service(
        active == "active",
        fields.get("UnitFileState", ""),
        load,
        fields.get("InvocationID", ""),
        int(raw_pid) if raw_pid.isascii() and raw_pid.isdigit() else 0,
    )


def _verify_held(runner: Runner, *, require_inactive: bool = True) -> None:
    service = _service(runner)
    if (
        not _mask_on_disk()
        or (require_inactive and service.active)
        or service.load != "masked"
        or service.enable != "masked"
    ):
        raise CaddyError(f"installation hold is not effective for {UNIT}")


def _set_enable(runner: Runner, expected: str) -> bool:
    current = _service(runner).enable
    if current == expected:
        return False
    if current not in {"enabled", "enabled-runtime", "disabled"}:
        raise CaddyError(f"cannot restore unexpected enable state of {UNIT}: {current!r}")
    if expected != "enabled":
        runtime = ["--runtime"] if current == "enabled-runtime" else []
        runner.run(["systemctl", "disable", *runtime, UNIT])
    if expected != "disabled":
        runtime = ["--runtime"] if expected == "enabled-runtime" else []
        runner.run(["systemctl", "enable", *runtime, UNIT])
    if _service(runner).enable != expected:
        raise CaddyError(f"could not verify {expected} boot state of {UNIT}")
    return True


@dataclass(frozen=True)
class _BootLink:
    target: str
    device: int
    inode: int
    changed_ns: int


def _read_boot_link(parent: int) -> _BootLink | None:
    try:
        metadata = os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != ROOT_UID or metadata.st_nlink != 1:
        raise CaddyError(f"untrusted startup link for {UNIT}")
    target = os.readlink(UNIT, dir_fd=parent)
    after = os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
    if not os.path.samestat(after, metadata) or after.st_ctime_ns != metadata.st_ctime_ns:
        raise CaddyError(f"startup link for {UNIT} changed while reading")
    return _BootLink(target, metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns)


@dataclass
class _BootEnable:
    before: str
    fragment: Path
    directory: Path
    created: _BootLink | None = None
    created_parent: tuple[int, int] | None = None

    @classmethod
    def snapshot(cls, before: str, fragment: Path) -> "_BootEnable":
        if before not in {"disabled", "enabled-runtime"}:
            raise CaddyError(f"cannot safely enable {UNIT} from boot state {before!r}")
        # Only the distro's single, known install link can be safely unwound.
        text = _read(fragment) or ""
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", ";"))
        ]
        if lines.count("[Install]") != 1:
            raise CaddyError("Caddy unit lacks the expected [Install] section")
        install = lines[lines.index("[Install]") + 1 :]
        install = install[
            : next((i for i, line in enumerate(install) if line.startswith("[")), len(install))
        ]
        if install != ["WantedBy=multi-user.target"]:
            raise CaddyError("Caddy unit has unexpected startup link targets")
        system = INSTALL_HOLD.parent.parent
        with _trusted_dir(system):
            directory = system / "multi-user.target.wants"
            try:
                with _trusted_dir(directory) as fd:
                    if _read_boot_link(fd) is not None:
                        raise CaddyError(f"unexpected existing startup link: {directory / UNIT}")
            except FileNotFoundError:
                pass
        return cls(before, fragment, directory)

    def mark_created(self) -> None:
        with _trusted_dir(self.directory) as parent:
            link = _read_boot_link(parent)
            if link is None or link.target not in {
                str(self.fragment),
                str(self.fragment.resolve()),
            }:
                raise CaddyError("could not identify the startup link created by enable")
            metadata = os.fstat(parent)
            self.created_parent = (metadata.st_dev, metadata.st_ino)
            self.created = link

    def restore_without_unit(self, runner: Runner) -> None:
        """Undo only the operation's own link, without loading the changed unit."""
        try:
            try:
                with _trusted_dir(self.directory) as parent:
                    current = _read_boot_link(parent)
                    if current is not None:
                        metadata = os.fstat(parent)
                        parent_key = (metadata.st_dev, metadata.st_ino)
                        if parent_key != self.created_parent or current != self.created:
                            raise CaddyError(
                                "startup link was replaced or has an unexpected target"
                            )
                        os.unlink(UNIT, dir_fd=parent)
                        os.fsync(parent)
                        if _read_boot_link(parent) is not None:
                            raise CaddyError("startup link reappeared")
            except FileNotFoundError:
                if self.created is not None:
                    raise
            observed = runner.run(["systemctl", "is-enabled", UNIT], check=False)
            if observed.stdout.strip() != self.before or observed.returncode not in {0, 1}:
                raise CaddyError(f"could not verify previous boot state {self.before}")
        except (CommandError, OSError, ValueError) as exc:
            raise CaddyError(
                f"manual boot-state cleanup required: {self.directory / UNIT}: {exc}"
            ) from exc


def _fingerprint(text: str) -> str:
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise CaddyError("Caddy did not return valid configuration JSON") from exc
    if not isinstance(value, dict) or "apps" not in value:
        raise CaddyError("Caddy did not return a complete configuration")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _expected(runner: Runner, config: Path) -> str:
    return _fingerprint(
        runner.capture(["caddy", "adapt", "--config", str(config), "--adapter", "caddyfile"])
    )


def _runtime_json(pid: int) -> str:
    """Fetch one bounded HTTP response from the actual systemd MainPID."""
    limit = 1 << 20
    deadline = monotonic() + 3.0
    data = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3.0)
        conn.connect(str(ADMIN_SOCKET))
        raw_peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        peer, _, _ = struct.unpack("3i", raw_peer)
        if peer != pid:
            raise CaddyError("the admin socket is not owned by the running Caddy process")
        conn.settimeout(max(0.0, deadline - monotonic()))
        conn.sendall(b"GET /config/ HTTP/1.0\r\nHost:\r\nConnection: close\r\n\r\n")
        while len(data) < limit:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise CaddyError("timed out reading the Caddy admin socket")
            conn.settimeout(remaining)
            part = conn.recv(min(65536, limit - len(data)))
            if not part:
                header, sep, body = data.partition(b"\r\n\r\n")
                if not sep or not header.startswith(b"HTTP/1.0 200 "):
                    raise CaddyError("Caddy admin socket did not return HTTP 200")
                return body.decode("utf-8")
            data.extend(part)
    raise CaddyError("Caddy admin response exceeded the size limit")


def _verify_runtime(runner: Runner, expected: str) -> tuple[str, str]:
    before = _service(runner)
    if (
        not before.active
        or before.load != "loaded"
        or before.pid <= 1
        or not re.fullmatch(r"[a-f0-9]{32}", before.invocation_id)
    ):
        raise CaddyError(f"{UNIT} is not running with a known invocation")
    if before.invocation_id == "0" * 32:
        raise CaddyError(f"{UNIT} has no invocation ID")
    try:
        runtime = _runtime_json(before.pid)
    except OSError as exc:
        raise CaddyError(
            "could not read the running Caddy config from its local admin socket"
        ) from exc
    if _fingerprint(runtime) != expected:
        raise CaddyError("running Caddy config differs from the validated config")
    after = _service(runner)
    if (
        not after.active
        or after.load != "loaded"
        or after.invocation_id != before.invocation_id
        or after.pid != before.pid
    ):
        raise CaddyError(f"{UNIT} changed invocation during verification")
    return after.invocation_id, hashlib.sha256(runtime.rstrip("\n").encode("utf-8")).hexdigest()


def running_config_fingerprint(runner: Runner) -> RunningConfig | None:
    """Attest to the current managed config, not the operator's ingress topology."""
    try:
        text = _read(CADDYFILE)
        settings = _managed_settings(text)
        if settings is None or _installation_held():
            return None
        fingerprint = _expected(runner, CADDYFILE)
        invocation, wire_fingerprint = _verify_runtime(runner, fingerprint)
        if _read(CADDYFILE) == text and not _installation_held():
            return RunningConfig(invocation, fingerprint, settings[0], ACCESS_LOG, wire_fingerprint)
    except CommandError, OSError, ValueError:
        pass
    return None


def _verify_route(runner: Runner, site: str) -> None:
    result = runner.run(
        [
            *_CURL,
            "--ipv4",
            "--head",
            "--path-as-is",
            "--output",
            "/dev/null",
            "--header",
            f"Host: {site}",
            "--write-out",
            "%{http_code}\n%{redirect_url}",
            f"http://127.0.0.1{_ROUTE_PROBE}",
        ],
        timeout=4.0,
        check=False,
    )
    if not result.ok or result.stdout.strip() != f"308\nhttps://{site}{_ROUTE_PROBE}":
        raise CaddyError("local Caddy HTTP route did not return the expected HTTPS redirect")


PROC = Path("/proc")


def _listener_identity(
    runner: Runner, pid: int, ipv6: network.Capability
) -> tuple[tuple[int, str, str], ...]:
    if ipv6 == "unknown":
        raise CaddyError("IPv6 capability is unknown")
    pid_ns = (PROC / str(pid) / "ns/net").stat()
    self_ns = (PROC / "self/ns/net").stat()
    host_ns = (PROC / "1/ns/net").stat()
    if not os.path.samestat(pid_ns, self_ns) or not os.path.samestat(pid_ns, host_ns):
        raise CaddyError("Caddy does not share the host network namespace")
    output = runner.capture(
        ["ss", "-H", "-lntpe", "-O", "( sport = :80 or sport = :443 )"], timeout=4
    )
    seen: set[tuple[int, str, str]] = set()
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 6 or columns[0] != "LISTEN":
            raise CaddyError("cannot parse a Caddy ingress listener")
        host, _, port = columns[3].rpartition(":")
        v6_only = bool(re.search(r"\bv6only:1\b", line))
        if ipv6 == "disabled" and host.startswith("[") and v6_only:
            continue  # Not an IPv4 listener or a family UFW would open.
        owners = {int(owner) for owner in re.findall(r"\bpid=(\d+),fd=\d+", line)}
        inode = re.search(r"\bino:([1-9]\d*)\b", line)
        if port not in {"80", "443"} or owners != {pid} or inode is None:
            raise CaddyError("a Caddy ingress port has an unverified listener")
        if host in {"*", "[::]"} and re.search(r"\bv6only:0\b", line):
            family = "dual"
        elif host == "[::]" and v6_only:
            family = "v6"
        elif host == "0.0.0.0":
            family = "v4"
        else:
            raise CaddyError("Caddy ingress lacks a verified wildcard listener")
        seen.add((int(port), family, inode[1]))
    for port in (80, 443):
        families = {family for bound, family, _ in seen if port == bound}
        covered = (
            families in ({"dual"}, {"v4", "v6"})
            if ipv6 == "enabled"
            else bool(families & {"dual", "v4"})
        )
        if not covered:
            raise CaddyError("Caddy lacks verified listeners for every required ingress family")
    return tuple(sorted(seen))


def firewall_ingress_identity(runner: Runner) -> str | None:
    """Identity of a verified public site and service invocation, without public probes."""
    settings = _read_managed()
    if settings is None:
        return None
    try:
        ipv6 = network.local_ipv6_capability()
        if ipv6 == "unknown":
            return None
        _verify_exec(runner)
        before = _service(runner)
        if not before.active or before.load != "loaded" or before.enable != "enabled":
            return None
        sockets = _listener_identity(runner, before.pid, ipv6)
        _verify_route(runner, settings[0])
        active = running_config_fingerprint(runner)
        if (
            active is None
            or active.site != settings[0]
            or active.invocation_id != before.invocation_id
        ):
            return None
        service = _service(runner)
        if (
            service.active
            and service.load == "loaded"
            and service.enable == "enabled"
            and service == before
            and network.local_ipv6_capability() == ipv6
            and _listener_identity(runner, service.pid, ipv6) == sockets
        ):
            material = f"{active.invocation_id}:{active.site}:{active.fingerprint}:{ipv6}:{sockets}"
            return hashlib.sha256(material.encode("ascii")).hexdigest()
    except CommandError, OSError, ValueError:
        pass
    return None


def _probe_backend(runner: Runner, *, site: str, upstream: str) -> StepResult:
    result = runner.run(
        [
            *_CURL,
            "--head",
            "--output",
            "/dev/null",
            "--header",
            f"Host: {site}",
            "--write-out",
            "%{http_code}",
            f"http://{upstream}/",
        ],
        timeout=4.0,
        check=False,
    )
    code = result.stdout.strip()
    if not result.ok or not re.fullmatch(r"[1-5][0-9]{2}", code):
        return StepResult(
            "verify upstream", Status.FAIL, "proxy verified; loopback backend unavailable"
        )
    if code.startswith("5"):
        return StepResult(
            "verify upstream", Status.FAIL, f"proxy verified; backend returned HTTP {code}"
        )
    return StepResult("verify upstream", Status.OK, f"HTTP {code} from loopback backend")


def _prepare_log(runner: Runner) -> None:
    if ACCESS_LOG.parent.is_symlink() or ACCESS_LOG.is_symlink():
        raise CaddyError(f"refusing a symlink in access log path: {ACCESS_LOG}")
    if ACCESS_LOG.exists() and not ACCESS_LOG.is_file():
        raise CaddyError(f"not a regular access log file: {ACCESS_LOG}")
    if not ACCESS_LOG.parent.exists():
        runner.run(["install", "-d", "-m", "0750", "-o", "caddy", "-g", "caddy", ACCESS_LOG.parent])


@contextmanager
def _staged(content: str) -> Iterator[Path]:
    fd, name = tempfile.mkstemp(dir=CADDYFILE.parent, prefix=".lhm-caddy-", suffix=".tmp")
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        yield path
    finally:
        path.unlink(missing_ok=True)


def _restore(
    runner: Runner,
    *,
    backup: Path | None,
    previous: str | None,
    desired: str,
    before: _Service,
    previous_fingerprint: str | None,
    was_held: bool,
    boot_enable: _BootEnable | None,
) -> None:
    errors: list[str] = []

    @contextmanager
    def attempt(action: str) -> Iterator[None]:
        try:
            yield
        except (CommandError, OSError, ValueError, KeyboardInterrupt) as exc:
            errors.append(f"{action} failed: {exc or 'interrupted'}")

    if not before.active:
        with attempt("stop"):
            if _service(runner).active:
                _verify_exec(runner)
                runner.run(["systemctl", "stop", UNIT])

    barrier_armed = False
    if was_held:
        # Restore boot state while the validated candidate is still on disk.
        # If the mask was never released, keep it: systemd hides the vendor
        # enable symlinks while masked and cannot remove them by unit name.
        with attempt("boot-state restore"):
            if boot_enable is not None:
                boot_enable.restore_without_unit(runner)
            elif _service(runner).load != "masked":
                _verify_exec(runner)
                _set_enable(runner, "disabled")
        with attempt("persistent start barrier"):
            _set_hold(runner, held=True, require_inactive=False)
            barrier_armed = True
    else:
        with attempt("boot-state restore"):
            if boot_enable is not None:
                boot_enable.restore_without_unit(runner)
            else:
                _verify_exec(runner)
                _set_enable(runner, before.enable)

    config_restored = False
    with attempt("config restore"):
        disk = _read(CADDYFILE)
        if disk != previous:
            if disk != desired:
                raise CaddyError(f"{CADDYFILE} changed during activation; refusing rollback")
            if was_held and not barrier_armed:
                raise CaddyError("refusing to restore the vendor config without a start barrier")
            if backup is None:
                remove_file(CADDYFILE)
            else:
                rollback_file(CADDYFILE, backup=backup)
            _sync_dir(CADDYFILE.parent)
        if _read(CADDYFILE) != previous:
            raise CaddyError("rolled-back Caddyfile could not be verified")
        config_restored = True

    with attempt("active-state restore"):
        if before.active and previous_fingerprint is not None:
            if config_restored:
                _verify_exec(runner)
                runner.run(["systemctl", "reload" if _service(runner).active else "start", UNIT])
            _verify_runtime(runner, previous_fingerprint)
        if _service(runner).active != before.active:
            raise CaddyError(f"could not restore the previous active state of {UNIT}")
    if was_held and barrier_armed and errors:
        errors.append("persistent start barrier verified")
    if errors:
        raise CaddyError("; ".join(errors))


def _publish(
    runner: Runner,
    *,
    desired: str,
    previous: str | None,
    before: _Service,
    previous_fingerprint: str | None,
    held: bool,
    site: str,
    upstream: str,
) -> list[StepResult]:
    from lhm.modules.fail2ban import stop_managed_caddy_access

    changed = previous != desired
    backup: Path | None = None
    attempted = False
    jail_stopped = False
    boot_enable: _BootEnable | None = None
    action = "reload" if before.active else "start"
    try:
        if not held:
            _verify_exec(runner)
        _prepare_log(runner)
        with _staged(desired) as staged:
            # validate provisions the configured log writer. Use the service's
            # account to check permission and avoid creating a root-owned log.
            runner.run(
                [
                    "runuser",
                    "-u",
                    "caddy",
                    "--",
                    "caddy",
                    "validate",
                    "--config",
                    staged,
                    "--adapter",
                    "caddyfile",
                ],
            )
            expected = _expected(runner, staged)
            if _read(CADDYFILE) != previous:
                raise CaddyError(f"{CADDYFILE} changed during validation")
            if changed or not before.active:
                # Already under the Caddy transaction lock; this leaves journald alone.
                try:
                    jail_stopped = stop_managed_caddy_access(runner, revoke=True)
                except (CommandError, OSError, ValueError) as exc:
                    raise CaddyError("could not stop the managed Caddy file jail") from exc
            if changed:
                if previous is not None:
                    backup = backup_file(CADDYFILE)
                attempted = True
                os.replace(staged, CADDYFILE)
                _sync_dir(CADDYFILE.parent)
                notify_file_change(
                    "created" if previous is None else "modified",
                    CADDYFILE,
                    old=previous,
                    new=desired,
                )
        attempted = True
        if held:
            _set_hold(runner, held=False)
        if changed or not before.active:
            _verify_exec(runner)
            runner.run(["systemctl", action, UNIT])
        _verify_runtime(runner, expected)
        _verify_route(runner, site)
        backend = _probe_backend(runner, site=site, upstream=upstream)
        fragment = _verify_exec(runner)
        current = _service(runner).enable
        enabled = current != "enabled"
        if enabled:
            boot_enable = _BootEnable.snapshot(current, fragment)
            try:
                runner.run(["systemctl", "enable", "--no-reload", UNIT])
            finally:
                boot_enable.mark_created()
            # Track the new link before the reload can learn an unsafe unit.
            runner.run(["systemctl", "daemon-reload"])
            _verify_exec(runner)
            if _service(runner).enable != "enabled":
                raise CaddyError(f"could not verify enabled boot state of {UNIT}")
        _verify_runtime(runner, expected)
        if _read(CADDYFILE) != desired:
            raise CaddyError(f"{CADDYFILE} changed during activation")
    except (CommandError, OSError, ValueError, KeyboardInterrupt) as exc:
        detail = "interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc)
        if jail_stopped:
            detail += "; managed Caddy file jail remains stopped pending re-attestation"
        if not attempted:
            return [StepResult("caddy", Status.FAIL, detail)]
        try:
            _restore(
                runner,
                backup=backup,
                previous=previous,
                desired=desired,
                before=before,
                previous_fingerprint=previous_fingerprint,
                was_held=held,
                boot_enable=boot_enable,
            )
        except (CommandError, OSError, ValueError, KeyboardInterrupt) as rollback_error:
            hint = f"; backup: {backup}" if backup is not None else ""
            return [
                StepResult(
                    "caddy", Status.FAIL, f"{detail}; rollback failed: {rollback_error}{hint}"
                )
            ]
        return [StepResult("caddy", Status.FAIL, f"{detail}; prior configuration restored")]

    return [
        *(
            [StepResult("stop managed Caddy file jail", Status.CHANGED, "re-attestation required")]
            if jail_stopped
            else []
        ),
        StepResult(f"write {CADDYFILE}", Status.CHANGED if changed else Status.SKIPPED),
        StepResult(
            f"{action} {UNIT}", Status.CHANGED if changed or not before.active else Status.SKIPPED
        ),
        StepResult(f"enable {UNIT}", Status.CHANGED if enabled else Status.SKIPPED),
        StepResult("verify caddy", Status.OK, "running config and local HTTPS redirect verified"),
        backend,
    ]


def apply_caddy(
    runner: Runner, *, site: str | None = None, upstream: str | None = None
) -> list[StepResult]:
    try:
        previous = _read(CADDYFILE)
        settings = _managed_settings(previous)
        held = _installation_held()
        if previous is not None and settings is None and not held:
            raise CaddyError(f"refusing to overwrite unmanaged {CADDYFILE}")
        if settings is not None:
            site = settings[0] if site is None else site
            upstream = settings[1] if upstream is None else upstream
        if site is None or upstream is None:
            raise CaddyError("first apply requires both --site and --upstream")
        selected_site, selected_upstream = _site(site), _upstream(upstream)
        desired = desired_conf(site=selected_site, upstream=selected_upstream)
        plan = [
            f"Plan (caddy): {selected_site} -> {selected_upstream}",
            f"  - install {PACKAGE} and curl if needed, holding Caddy during install",
            f"  - validate and write {CADDYFILE}, then verify {UNIT}, local redirect and backend",
            f"  - write JSON access logs to {ACCESS_LOG}; firewall unchanged",
        ]
        if runner.dry_run or not mutations_allowed():
            print("\n".join(plan))
            return [StepResult("caddy", Status.PLANNED)]

        backend = AptBackend(runner)
        installed = backend.pkg_installed(PACKAGE)
        have_curl = backend.pkg_installed("curl")
        before = _service(runner)
        if installed and have_curl and before.active and not held and previous == desired:
            _verify_exec(runner)
            if running_config_fingerprint(runner) is None:
                raise CaddyError(
                    "running Caddy config could not be verified; refusing to overwrite it"
                )
            if before.enable == "enabled":
                _verify_route(runner, selected_site)
                return [
                    StepResult(
                        "caddy", Status.SKIPPED, "running managed config and redirect verified"
                    ),
                    _probe_backend(runner, site=selected_site, upstream=selected_upstream),
                ]
        if not confirm_once(plan):
            return [StepResult("caddy", Status.ABORTED, "aborted; no changes made")]

        # /etc exists before installation; /etc/caddy need not.
        with locked_target(CADDYFILE.parent):
            if _read(CADDYFILE) != previous or _installation_held() != held:
                raise CaddyError("Caddy configuration changed since confirmation; retry")
            installed = backend.pkg_installed(PACKAGE)
            have_curl = backend.pkg_installed("curl")
            before = _service(runner)
            if before.active and (settings is None or not installed or held):
                raise CaddyError(f"refusing to take over active {UNIT} without a managed config")
            if not installed and not held and before.load != "not-found":
                raise CaddyError(f"refusing to mask a pre-existing {UNIT}")
            if (
                installed
                and not held
                and before.enable not in {"enabled", "enabled-runtime", "disabled"}
            ):
                raise CaddyError(f"refusing to change unexpected enable state of {UNIT}")
            if (
                previous is not None
                and settings is None
                and not _packaged_default(runner, previous)
            ):
                raise CaddyError(f"refusing to overwrite unmanaged {CADDYFILE}")
            if held or not installed:
                _check_unit_dropins(runner)
                _set_hold(runner, held=True)
                held = True
            if not installed:
                backend.install([PACKAGE] if have_curl else [PACKAGE, "curl"])
                _verify_held(runner)
                after_install = _read(CADDYFILE)
                if after_install != previous and (
                    previous is not None
                    or after_install is None
                    or not _packaged_default(runner, after_install)
                ):
                    raise CaddyError(f"refusing to overwrite unmanaged {CADDYFILE} after install")
                previous = after_install
            elif not have_curl:
                backend.install(["curl"])
            previous_fingerprint = None
            if before.active:
                verified = running_config_fingerprint(runner)
                if verified is None or verified.invocation_id != before.invocation_id:
                    raise CaddyError(
                        "running Caddy config could not be verified; refusing to overwrite it"
                    )
                previous_fingerprint = verified.fingerprint
            with locked_target(CADDYFILE):
                return _publish(
                    runner,
                    desired=desired,
                    previous=previous,
                    before=before,
                    previous_fingerprint=previous_fingerprint,
                    held=held,
                    site=selected_site,
                    upstream=selected_upstream,
                )
    except KeyboardInterrupt:
        return [StepResult("caddy", Status.FAIL, "interrupted before activation")]
    except (CommandError, DistroError, OSError, ValueError) as exc:
        return [StepResult("caddy", Status.FAIL, str(exc))]


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    """Report on-disk settings and systemd status without validating or writing."""
    try:
        installed = AptBackend(runner).pkg_installed(PACKAGE) if probe_package else None
    except DistroError:
        installed = None
    try:
        service = _service(runner)
    except CommandError, ValueError:
        service = None
    settings = _read_managed()
    try:
        held = _installation_held()
    except OSError, ValueError:
        held = None
    return {
        "package": PACKAGE,
        "installed": installed,
        "active": service.active if service else None,
        "enabled": service.enable in {"enabled", "enabled-runtime"} if service else None,
        "config": str(CADDYFILE),
        "config_present": CADDYFILE.exists() or CADDYFILE.is_symlink(),
        "managed": settings is not None,
        "site": settings[0] if settings else None,
        "upstream": settings[1] if settings else None,
        "access_log": str(ACCESS_LOG) if settings else None,
        "access_log_present": ACCESS_LOG.is_file() and not ACCESS_LOG.is_symlink()
        if settings
        else False,
        "roll_size": ROLL_SIZE if settings else None,
        "roll_keep": ROLL_KEEP if settings else None,
        "install_held": held,
    }


class CaddyModule:
    name = "caddy"
    description = "Install and manage an HTTPS reverse proxy with Caddy"
    implemented = True

    def apply(
        self, runner: Runner, *, site: str | None = None, upstream: str | None = None
    ) -> list[StepResult]:
        return apply_caddy(runner, site=site, upstream=upstream)
