"""Caddy transactions exercise only temporary paths and fake system commands."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from lhm.core import network
from lhm.core.files import locked_target
from lhm.core.mutations import mutation_mode
from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import caddy, fail2ban

SITE = "app.example.com"
UPSTREAM = "127.0.0.1:8080"
DEFAULT = ":80 {\n\tfile_server\n}\n"
INVOCATION = "1234567890abcdef" * 2


class Host:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.validated: list[str] = []
        self.reloads: list[str] = []
        self.installed = self.active = self.masked = False
        self.enable_state = "disabled"
        self.mask_effective = True
        self.install_ok = self.validate_ok = self.start_ok = True
        self.service_stays_active = True
        self.first_reload_ok = True
        self.install_default = DEFAULT
        self.runtime_override: str | None = None
        self.route_ok = self.backend_ok = True
        self.interrupt_on: str | None = None
        self.exec_override: str | None = None
        self.unit_override = ""
        self.override_on_enable: str | None = None
        self.replace_boot_link: str | None = None
        self.boot_verification: str | None = None
        self.stop_ok = True
        self.listeners = (
            'LISTEN 0 4096 *:80 *:* users:(("caddy",pid=99,fd=4)) ino:11 v6only:0\n'
            'LISTEN 0 4096 *:443 *:* users:(("caddy",pid=99,fd=5)) ino:12 v6only:0\n'
        )

    @property
    def enabled(self) -> bool:
        return self.current_boot_state == "enabled"

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self.enable_state = "enabled" if value else "disabled"

    @property
    def boot_link(self) -> Path:
        return caddy.INSTALL_HOLD.parent.parent / "multi-user.target.wants" / caddy.UNIT

    @property
    def current_boot_state(self) -> str:
        return "enabled" if self.boot_link.is_symlink() else self.enable_state

    def runtime(self, pid: int) -> str:
        assert self.active and pid == 99
        return self.runtime_override or json.dumps(
            {"apps": {"fixture": caddy.CADDYFILE.read_text()}}
        )

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.commands.append(cmd)
        code, out = 0, ""
        activity: str | None = None
        match cmd:
            case ["apt-get", "--version"]:
                pass
            case ["systemctl", "daemon-reload"]:
                if self.boot_link.is_symlink() and self.override_on_enable is not None:
                    self.unit_override = self.override_on_enable
                    self.override_on_enable = None
                    if self.replace_boot_link is not None:
                        target = self.boot_link.readlink()
                        self.boot_link.rename(self.boot_link.with_suffix(".original"))
                        self.boot_link.symlink_to(
                            target if self.replace_boot_link == "same-target" else "/tmp/foreign"
                        )
            case ["systemctl", "show", "--property=UnitPath", "--value"]:
                out = str(caddy.INSTALL_HOLD.parent.parent)
            case ["systemctl", "show", "--all", option, "caddy.service"] if option == (
                f"--property={caddy._EXEC_FIELDS}"
            ):
                assert not self.masked
                binary, config = caddy.CADDY_BINARY, caddy.CADDYFILE
                start = self.exec_override or f"{binary} run --environ --config {config}"
                out = (
                    f"ExecStart={{ path={binary} ; argv[]={start} ; ignore_errors=no ; pid=0 }}\n"
                    f"ExecReload={{ path={binary} ; argv[]={binary} reload --config {config}"
                    " --force ; ignore_errors=no ; pid=0 }\n"
                    "ExecCondition=\nExecStartPre=\nExecStartPost=\nUser=caddy\n"
                    "RootDirectory=\nRootImage=\n"
                    f"FragmentPath={caddy.VENDOR_UNIT_DIRS[0] / caddy.UNIT}\n"
                    "NeedDaemonReload=no\n"
                    f"{self.unit_override}"
                )
            case ["dpkg-query", "-W", "-f=${Status}", "caddy"]:
                code, out = (0, "install ok installed") if self.installed else (1, "")
            case ["dpkg-query", "-W", "-f=${Status}", "curl"]:
                out = "install ok installed"
            case ["dpkg-query", "-W", "-f=${Conffiles}", "caddy"]:
                checksum = hashlib.md5(DEFAULT.encode(), usedforsecurity=False).hexdigest()
                out = f" {caddy.CADDYFILE} {checksum}\n"
            case ["systemctl", "show", option, "caddy.service"]:
                assert option == f"--property={caddy._SERVICE_FIELDS}"
                load = "masked" if self.masked else "loaded" if self.installed else "not-found"
                enable = (
                    "masked" if self.masked else self.current_boot_state if self.installed else ""
                )
                out = (
                    f"LoadState={load}\nUnitFileState={enable}\n"
                    f"ActiveState={'active' if self.active else 'inactive'}\n"
                    f"InvocationID={INVOCATION if self.active else ''}\n"
                    f"MainPID={99 if self.active else 0}\n"
                )
            case ["systemctl", "mask", "caddy.service"]:
                self.masked = self.mask_effective
                if self.masked:
                    mask = caddy.INSTALL_HOLD.parent.parent / caddy.UNIT
                    if not mask.is_symlink():
                        mask.symlink_to("/dev/null")
            case ["systemctl", "unmask", "caddy.service"]:
                assert caddy.CADDYFILE.read_text() == self.validated[-1]
                self.masked = False
                (caddy.INSTALL_HOLD.parent.parent / caddy.UNIT).unlink()
            case [
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "-q",
                "caddy",
            ]:
                activity = "install"
                assert (
                    f"ConditionPathExists=!{caddy.INSTALL_HOLD}" in caddy.INSTALL_HOLD.read_text()
                )
                assert self.masked
                assert self.commands[-3] == ["systemctl", "daemon-reload"]
                self.installed = self.install_ok
                self.enabled = self.install_ok
                caddy.CADDYFILE.parent.mkdir(mode=0o755, exist_ok=True)
                if not caddy.CADDYFILE.exists():
                    caddy.CADDYFILE.write_text(self.install_default)
                    caddy.CADDYFILE.chmod(0o644)
                code = 0 if self.install_ok else 1
            case ["install", "-d", "-m", "0750", "-o", "caddy", "-g", "caddy", directory]:
                Path(directory).mkdir()
            case [
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
            ]:
                candidate = Path(staged)
                assert candidate != caddy.CADDYFILE
                assert candidate.parent == caddy.CADDYFILE.parent
                assert candidate.stat().st_mode & 0o777 == 0o644
                assert not list(candidate.parent.glob("Caddyfile.bak*"))
                self.validated.append(candidate.read_text())
                code = 0 if self.validate_ok else 1
            case ["caddy", "adapt", "--config", text, "--adapter", "caddyfile"]:
                out = json.dumps({"apps": {"fixture": Path(text).read_text()}}, sort_keys=True)
            case ["curl", *options, url] if url.startswith("http://127.0.0.1/"):
                assert options[: len(caddy._CURL) - 1] == list(caddy._CURL[1:])
                assert "--path-as-is" in options and "--ipv4" in options
                assert url == f"http://127.0.0.1{caddy._ROUTE_PROBE}"
                out = f"308\nhttps://{SITE}{caddy._ROUTE_PROBE}" if self.route_ok else "200\n"
            case ["curl", *options, url] if url.startswith("http://127.0.0.1:"):
                assert "--head" in options
                code, out = (0, "401") if self.backend_ok else (7, "000")
            case ["systemctl", "start", "caddy.service"]:
                activity = "start"
                assert not caddy.INSTALL_HOLD.exists()
                assert caddy.CADDYFILE.read_text() == self.validated[-1]
                code = 0 if self.start_ok else 1
                self.active = self.service_stays_active
            case ["systemctl", "reload", "caddy.service"]:
                activity = "reload"
                self.reloads.append(caddy.CADDYFILE.read_text())
                code = 0 if self.first_reload_ok or len(self.reloads) > 1 else 1
            case ["systemctl", "enable", "--no-reload", "caddy.service"]:
                assert self.active
                self.boot_link.parent.mkdir(mode=0o755, exist_ok=True)
                self.boot_link.symlink_to(caddy.VENDOR_UNIT_DIRS[0] / caddy.UNIT)
                activity = "enable"
            case ["systemctl", "enable", "--runtime", "caddy.service"]:
                self.enable_state = "enabled-runtime"
            case ["systemctl", "disable", *_, "caddy.service"]:
                self.enabled = False
            case ["systemctl", "is-enabled", "caddy.service"]:
                out = self.boot_verification or self.current_boot_state
                code = 0 if out.startswith("enabled") else 1
            case ["systemctl", "stop", "caddy.service"]:
                code = 0 if self.stop_ok else 1
                if self.stop_ok:
                    self.active = False
            case ["ss", "-H", "-lntpe", "-O", "( sport = :80 or sport = :443 )"]:
                out = self.listeners
            case _:
                pytest.fail(f"unexpected command: {cmd}")
        if activity is not None and activity == self.interrupt_on:
            self.interrupt_on = None
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(cmd, code, out, "")


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Host:
    monkeypatch.setattr(caddy, "CADDYFILE", tmp_path / "caddy" / "Caddyfile")
    monkeypatch.setattr(
        caddy, "INSTALL_HOLD", tmp_path / "units" / "caddy.service.d" / "zz-lhm-install-hold.conf"
    )
    monkeypatch.setattr(caddy, "ACCESS_LOG", tmp_path / "log" / "access.log")
    monkeypatch.setattr(caddy, "ADMIN_SOCKET", tmp_path / "admin.sock")
    monkeypatch.setattr(caddy, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(caddy, "confirm_once", lambda _: True)
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(mode=0o755)
    binary = binary_dir / "caddy"
    binary.touch(mode=0o755)
    monkeypatch.setattr(caddy, "CADDY_BINARY", binary)
    fragment = binary_dir / caddy.UNIT
    fragment.write_text("[Service]\nUser=caddy\n[Install]\nWantedBy=multi-user.target\n")
    fragment.chmod(0o644)
    monkeypatch.setattr(caddy, "VENDOR_UNIT_DIRS", (binary_dir,))
    monkeypatch.setattr(network, "local_ipv6_capability", lambda: "enabled")
    unit_dir = caddy.INSTALL_HOLD.parent.parent
    unit_dir.mkdir(mode=0o755)
    net = tmp_path / "network-namespace"
    net.touch()
    proc = tmp_path / "proc"
    for owner in ("1", "99", "self"):
        entry = proc / owner / "ns" / "net"
        entry.parent.mkdir(parents=True)
        entry.hardlink_to(net)
    monkeypatch.setattr(caddy, "PROC", proc)
    host = Host()
    monkeypatch.setattr(caddy, "_runtime_json", host.runtime)
    monkeypatch.setattr(fail2ban, "stop_managed_caddy_access", lambda _, *, revoke: False)
    return host


def _seed(*, upstream: str = UPSTREAM) -> str:
    text = caddy.desired_conf(site=SITE, upstream=upstream)
    caddy.CADDYFILE.parent.mkdir(mode=0o755)
    caddy.CADDYFILE.write_text(text)
    caddy.CADDYFILE.chmod(0o644)
    return text


def _apply(host: Host) -> list[Status]:
    return [
        step.status
        for step in caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    ]


@pytest.mark.parametrize(
    ("upstream", "normalized"),
    [
        ("127.0.1.1:80", "127.0.1.1:80"),
        ("http://LOCALHOST:8100", "127.0.0.1:8100"),
        ("[0:0:0:0:0:0:0:1]:65535", "[::1]:65535"),
    ],
)
def test_complete_config_only_proxies_to_loopback(
    host: Host, upstream: str, normalized: str
) -> None:
    config = caddy.desired_conf(site="App.Example.COM", upstream=upstream)
    assert f"reverse_proxy {normalized} {{" in config
    assert f"redir @site https://{SITE}{{uri}} 308" in config
    assert f"output file {caddy.ACCESS_LOG}" in config
    assert "format json" in config
    assert "roll_size 100MiB" in config and "roll_keep 10" in config
    assert "header -Server" in config and "header_down -Server" in config
    assert "request_header -Forwarded" in config and "request_header -X-Forwarded-*" in config
    assert "respond @connect 405" in config
    assert not {"trusted_proxies", "forward_proxy"} & set(config.split())
    assert f"admin unix/{caddy.ADMIN_SOCKET}" in config


@pytest.mark.parametrize(
    ("site", "upstream"),
    [
        (None, UPSTREAM),
        (SITE, None),
        ("*.example.com", UPSTREAM),
        ("https://example.com", UPSTREAM),
        ("example.com\n:80", UPSTREAM),
        ("example.com:443", UPSTREAM),
        ("127.0.0.1", UPSTREAM),
        ("localhost", UPSTREAM),
        (SITE, "192.168.1.1:80"),
        (SITE, "evil.example.com:80"),
        (SITE, "0.0.0.0:80"),
        (SITE, "[::]:80"),
        (SITE, "localhost:0"),
        (SITE, "localhost:65536"),
        (SITE, "127.0.0.1:80/foo"),
        (SITE, "127.0.0.1:80\nfile_server"),
        (SITE, "127.0.0.1:80@evil.example.com:80"),
        (SITE, "unix//tmp/caddy.sock"),
    ],
)
def test_first_apply_rejects_missing_or_unsafe_inputs(
    host: Host, site: str | None, upstream: str | None
) -> None:
    result = caddy.apply_caddy(Runner(exec_fn=host), site=site, upstream=upstream)
    assert result[0].status is Status.FAIL
    assert host.commands == []
    assert not caddy.CADDYFILE.parent.exists() and not caddy.INSTALL_HOLD.exists()


@pytest.mark.parametrize("dry_run_flag", [True, False])
def test_dry_run_never_touches_host(host: Host, dry_run_flag: bool) -> None:
    with mutation_mode(dry_run=not dry_run_flag):
        result = caddy.apply_caddy(
            Runner(dry_run=dry_run_flag, exec_fn=host), site=SITE, upstream=UPSTREAM
        )
    assert result[0].status is Status.PLANNED
    assert not host.commands and not caddy.CADDYFILE.parent.exists()
    assert not caddy.INSTALL_HOLD.exists()


@pytest.mark.parametrize("edit", [DEFAULT, "# lhm-managed Caddyfile\n:80\n"])
def test_unmanaged_config_is_never_overwritten(host: Host, edit: str) -> None:
    caddy.CADDYFILE.parent.mkdir()
    caddy.CADDYFILE.write_text(edit)
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == edit
    assert not caddy.INSTALL_HOLD.exists() and host.commands == []
    assert caddy.managed_access_log() is None


def test_existing_symlink_is_not_followed(host: Host, tmp_path: Path) -> None:
    target = tmp_path / "external"
    target.write_text(DEFAULT)
    caddy.CADDYFILE.parent.mkdir()
    caddy.CADDYFILE.symlink_to(target)
    assert _apply(host) == [Status.FAIL]
    assert not host.commands and target.read_text() == DEFAULT
    assert caddy.managed_access_log() is None


def test_first_install_guards_vendor_config_then_applies_and_is_idempotent(host: Host) -> None:
    assert _apply(host)[-1] is Status.OK
    desired = caddy.desired_conf(site=SITE, upstream=UPSTREAM)
    assert host.validated == [desired]
    assert caddy.CADDYFILE.read_text() == desired
    assert caddy.CADDYFILE.with_suffix(".bak").read_text() == DEFAULT
    assert not caddy.INSTALL_HOLD.exists()
    assert host.active and host.enabled
    assert not list(caddy.CADDYFILE.parent.glob(".lhm-caddy-*.tmp"))
    assert caddy.apply_caddy(Runner(exec_fn=host))[0].status is Status.SKIPPED
    assert host.validated == [desired]


def test_locked_transaction_cannot_install(host: Host) -> None:
    with locked_target(caddy.CADDYFILE.parent):
        assert _apply(host) == [Status.FAIL]
    assert not host.installed and not caddy.INSTALL_HOLD.exists()


def test_failed_package_install_leaves_persistent_hold(host: Host) -> None:
    host.install_ok = False
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == DEFAULT
    assert caddy.INSTALL_HOLD.is_file() and host.masked and not host.active and not host.validated


def test_install_refuses_non_vendor_default(host: Host) -> None:
    host.install_default = "# operator installed this concurrently\n"
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == host.install_default
    assert caddy.INSTALL_HOLD.is_file() and not host.active and not host.validated


def test_invalid_stage_does_not_publish_or_start(host: Host) -> None:
    host.validate_ok = False
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == DEFAULT
    assert caddy.INSTALL_HOLD.is_file() and not host.active
    assert not list(caddy.CADDYFILE.parent.glob(".lhm-caddy-*.tmp"))
    host.validate_ok = True
    assert _apply(host)[-1] is Status.OK
    assert host.active and not caddy.INSTALL_HOLD.exists()


@pytest.mark.parametrize(("start_ok", "stays_active"), [(False, True), (True, False)])
def test_activation_failure_rolls_back_to_vendor_config_behind_hold(
    host: Host, start_ok: bool, stays_active: bool
) -> None:
    host.start_ok, host.service_stays_active = start_ok, stays_active
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == DEFAULT
    assert caddy.INSTALL_HOLD.exists() and not host.active and not host.enabled
    assert host.masked
    assert (["systemctl", "stop", "caddy.service"] in host.commands) == stays_active
    assert ["systemctl", "disable", "caddy.service"] in host.commands


def test_failed_reload_restores_exact_backup_and_reloads_previous_config(host: Host) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = host.enabled = True
    host.first_reload_ok = False
    assert _apply(host) == [Status.FAIL]
    assert caddy.CADDYFILE.read_text() == old
    assert caddy.CADDYFILE.with_suffix(".bak").read_text() == old
    assert host.reloads == [caddy.desired_conf(site=SITE, upstream=UPSTREAM), old]
    assert host.active and host.enabled


def test_inspect_reports_on_disk_settings_with_read_only_probes(host: Host) -> None:
    _seed()
    host.installed = host.active = host.enabled = True
    data = caddy.inspect(Runner(exec_fn=host))
    assert data["managed"] and data["active"] and data["enabled"] and data["installed"]
    assert data["site"] == SITE and data["upstream"] == UPSTREAM
    assert data["access_log"] == str(caddy.ACCESS_LOG) and data["roll_keep"] == 10
    assert caddy.managed_access_log() == caddy.ACCESS_LOG
    assert not caddy.ACCESS_LOG.parent.exists()
    assert [command[:2] for command in host.commands] == [
        ["apt-get", "--version"],
        ["dpkg-query", "-W"],
        ["systemctl", "show"],
    ]


def test_mismatching_live_config_is_not_skipped_or_overwritten(host: Host) -> None:
    old = _seed()
    host.installed = host.active = host.enabled = True
    host.runtime_override = '{"apps":{"unexpected":{}}}'
    assert _apply(host) == [Status.FAIL]
    assert not host.validated and not host.reloads
    assert caddy.CADDYFILE.read_text() == old
    assert caddy.firewall_ingress_identity(Runner(exec_fn=host)) is None


def test_active_config_evidence_uses_current_invocation_and_exact_content(host: Host) -> None:
    _seed()
    host.installed = host.active = host.enabled = True
    runner = Runner(exec_fn=host)
    info = caddy.running_config_fingerprint(runner)
    assert info is not None
    assert info.invocation_id == INVOCATION and info.site == SITE
    assert info.access_log == caddy.ACCESS_LOG
    assert info.wire_fingerprint == hashlib.sha256(host.runtime(99).encode()).hexdigest()
    assert not any(command[0] == "curl" for command in host.commands)
    identity = caddy.firewall_ingress_identity(runner)
    assert identity
    assert identity == caddy.firewall_ingress_identity(runner)
    host.enabled = False
    assert caddy.firewall_ingress_identity(runner) is None


def test_group_writable_managed_config_is_untrusted(host: Host) -> None:
    _seed()
    caddy.CADDYFILE.chmod(0o664)
    assert caddy.managed_access_log() is None
    assert _apply(host) == [Status.FAIL]
    assert not host.commands


def test_invalid_install_mask_prevents_apt(host: Host) -> None:
    host.mask_effective = False
    assert _apply(host) == [Status.FAIL]
    assert not host.installed and not host.active
    assert not any(command[0] == "env" for command in host.commands)


def test_unavailable_backend_is_reported_without_rollback(host: Host) -> None:
    host.backend_ok = False
    steps = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert steps[-2].status is Status.OK
    assert steps[-1].status is Status.FAIL and "backend unavailable" in steps[-1].detail
    assert host.active and host.enabled and not host.masked


def test_incorrect_redirect_rolls_back_even_if_service_is_active(host: Host) -> None:
    host.route_ok = False
    assert _apply(host) == [Status.FAIL]
    assert not host.active and not host.enabled and host.masked
    assert caddy.CADDYFILE.read_text() == DEFAULT


def test_publication_sync_precedes_unmask(host: Host, monkeypatch: pytest.MonkeyPatch) -> None:
    sync = caddy._sync_dir

    def interrupt(directory: Path) -> None:
        if directory == caddy.CADDYFILE.parent and host.masked:
            assert caddy.CADDYFILE.read_text() == host.validated[-1]
            monkeypatch.setattr(caddy, "_sync_dir", sync)
            raise KeyboardInterrupt
        sync(directory)

    monkeypatch.setattr(caddy, "_sync_dir", interrupt)
    assert _apply(host) == [Status.FAIL]
    assert ["systemctl", "unmask", "caddy.service"] not in host.commands
    assert caddy.CADDYFILE.read_text() == DEFAULT
    assert host.masked and not host.active


@pytest.mark.parametrize("phase", ["install", "start"])
def test_interrupted_first_install_remains_held(host: Host, phase: str) -> None:
    host.interrupt_on = phase
    assert _apply(host) == [Status.FAIL]
    assert host.masked and not host.active
    assert caddy.CADDYFILE.read_text() == DEFAULT


@pytest.mark.parametrize("initial", ["disabled", "enabled-runtime"])
def test_interruption_after_enable_restores_active_and_boot_state(host: Host, initial: str) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = True
    host.enable_state = initial
    host.interrupt_on = "enable"
    assert _apply(host) == [Status.FAIL]
    assert host.active and host.enable_state == initial
    assert caddy.CADDYFILE.read_text() == old


@pytest.mark.parametrize("stop_ok", [True, False])
def test_file_jail_stop_gates_config_publish_and_reload(
    host: Host, monkeypatch: pytest.MonkeyPatch, stop_ok: bool
) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = host.enabled = True

    def stop(runner: Runner, *, revoke: bool) -> bool:
        assert revoke
        assert caddy.CADDYFILE.read_text() == old
        assert not caddy.CADDYFILE.with_suffix(".bak").exists()
        assert not host.reloads
        with pytest.raises(BlockingIOError), locked_target(caddy.CADDYFILE.parent):
            pytest.fail("Caddy and fail2ban were not serialized")
        if not stop_ok:
            raise fail2ban.JailError("stop failed")
        return True

    monkeypatch.setattr(fail2ban, "stop_managed_caddy_access", stop)
    steps = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    if stop_ok:
        assert steps[0].name == "stop managed Caddy file jail"
        assert steps[0].status is Status.CHANGED
        assert host.reloads
    else:
        assert len(steps) == 1 and steps[0].status is Status.FAIL
        assert "could not stop" in steps[0].detail
        assert not host.reloads and caddy.CADDYFILE.read_text() == old


def test_unexpected_effective_start_can_never_run(host: Host) -> None:
    host.exec_override = f"{caddy.CADDY_BINARY} run --config /etc/caddy/operator.conf"
    result = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert result[0].status is Status.FAIL and "unexpected effective ExecStart" in result[0].detail
    assert ["systemctl", "start", caddy.UNIT] not in host.commands
    assert host.masked and caddy.INSTALL_HOLD.exists() and caddy.CADDYFILE.read_text() == DEFAULT


def test_unrecognised_dropin_prevents_package_install(host: Host) -> None:
    caddy.INSTALL_HOLD.parent.mkdir(mode=0o755)
    (caddy.INSTALL_HOLD.parent / "zzz-override.conf").write_text("[Unit]\nConditionPathExists=\n")
    assert _apply(host) == [Status.FAIL]
    assert not host.installed and not caddy.INSTALL_HOLD.exists()


def test_stop_failure_still_retains_verified_persistent_barrier(host: Host) -> None:
    host.start_ok = host.stop_ok = False
    result = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert result[0].status is Status.FAIL
    assert (
        "stop failed:" in result[0].detail
        and "persistent start barrier verified" in result[0].detail
    )
    assert host.active and host.masked and caddy.INSTALL_HOLD.exists()


def test_unit_directory_is_synced_between_unmask_and_hold_removal(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    sync = caddy._sync_dir
    order = []

    def observe(directory: Path) -> None:
        if directory == caddy.INSTALL_HOLD.parent.parent:
            order.append((host.masked, caddy.INSTALL_HOLD.exists()))
        sync(directory)

    monkeypatch.setattr(caddy, "_sync_dir", observe)
    assert _apply(host)[-1] is Status.OK
    assert order[-1] == (False, True)
    assert not caddy.INSTALL_HOLD.exists()


@pytest.mark.parametrize(
    "problem", ["namespace", "foreign", "no-owner", "one-port", "partial-family"]
)
def test_firewall_ingress_rejects_unproven_listener_ownership(host: Host, problem: str) -> None:
    _seed()
    host.installed = host.active = host.enabled = True
    if problem == "namespace":
        entry = caddy.PROC / "99/ns/net"
        entry.unlink()
        entry.touch()
    elif problem == "foreign":
        host.listeners += 'LISTEN 0 4096 127.0.0.2:443 *:* users:(("other",pid=100,fd=4)) ino:13\n'
    elif problem == "no-owner":
        host.listeners = host.listeners.replace('users:(("caddy",pid=99,fd=4)) ', "")
    elif problem == "one-port":
        host.listeners = host.listeners.splitlines()[0]
    else:
        host.listeners = host.listeners.replace("*:443", "[::]:443").replace(
            "ino:12 v6only:0", "ino:12 v6only:1"
        )
    assert caddy.firewall_ingress_identity(Runner(exec_fn=host)) is None


@pytest.mark.parametrize(
    ("ipv6", "allowed"), [("disabled", True), ("unknown", False), ("enabled", False)]
)
def test_ingress_capability_matches_required_listener_families(
    host: Host, monkeypatch: pytest.MonkeyPatch, ipv6: network.Capability, allowed: bool
) -> None:
    _seed()
    host.installed = host.active = host.enabled = True
    monkeypatch.setattr(network, "local_ipv6_capability", lambda: ipv6)
    host.listeners = (
        host.listeners.replace("*:80", "0.0.0.0:80")
        .replace("*:443", "0.0.0.0:443")
        .replace(" v6only:0", "")
    )
    runner = Runner(exec_fn=host)
    assert bool(caddy.firewall_ingress_identity(runner)) is allowed
    if allowed:
        host.listeners = host.listeners.splitlines()[0]
        assert caddy.firewall_ingress_identity(runner) is None
    if ipv6 == "unknown":
        assert not host.commands


@pytest.mark.parametrize(
    "override",
    [
        "BindPaths=/tmp/alternate:/etc/caddy\n",
        "BindReadOnlyPaths=/tmp/alternate:/usr/bin\n",
        "RootDirectory=/alternate\n",
        "RootImage=/alternate.img\n",
        "TemporaryFileSystem=/etc\n",
        "ExtensionImages=/alternate.img\n",
        "DropInPaths=/etc/systemd/system/caddy.service.d/custom.conf\n",
        "FragmentPath=/etc/systemd/system/caddy.service\n",
    ],
)
def test_unchanged_active_caddy_is_never_enabled_under_unit_override(
    host: Host, override: str
) -> None:
    old = _seed()
    host.installed = host.active = True
    host.unit_override = override
    assert _apply(host) == [Status.FAIL]
    assert not host.enabled and caddy.CADDYFILE.read_text() == old
    assert not any(command[1:2] in [["enable"], ["reload"]] for command in host.commands)


def test_boot_restore_failure_does_not_skip_config_or_live_rollback(host: Host) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = True
    host.interrupt_on = "enable"
    host.boot_verification = "static"
    result = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert result[0].status is Status.FAIL and "boot-state restore failed:" in result[0].detail
    assert host.active and caddy.CADDYFILE.read_text() == old and host.reloads[-1] == old


def test_unsafe_unit_during_rollback_blocks_unit_ops_but_restores_disk(host: Host) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = host.enabled = True

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = host(cmd, timeout)
        if cmd == ["systemctl", "reload", caddy.UNIT]:
            host.unit_override = "BindReadOnlyPaths=/tmp/test:/etc/caddy\n"
            raise KeyboardInterrupt
        return result

    result = caddy.apply_caddy(Runner(exec_fn=execute), site=SITE, upstream=UPSTREAM)
    assert result[0].status is Status.FAIL and "active-state restore failed:" in result[0].detail
    assert len(host.reloads) == 1 and caddy.CADDYFILE.read_text() == old


@pytest.mark.parametrize("pending", ["NeedDaemonReload", "disk-only-drop-in"])
def test_pending_unit_changes_prevent_activation_and_ingress(host: Host, pending: str) -> None:
    old = _seed()
    host.installed = host.active = True
    if pending == "NeedDaemonReload":
        host.unit_override = "NeedDaemonReload=yes\n"
    else:
        caddy.INSTALL_HOLD.parent.mkdir(mode=0o755)
        (caddy.INSTALL_HOLD.parent / "90-pending.conf").write_text("[Service]\nExecStart=\n")
    assert _apply(host) == [Status.FAIL]
    assert not host.enabled and not host.reloads and caddy.CADDYFILE.read_text() == old
    host.enabled = True
    assert caddy.firewall_ingress_identity(Runner(exec_fn=host)) is None


def test_change_during_enable_fails_post_enable_verification(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _seed(upstream="127.0.0.1:9090")
    host.installed = host.active = True
    host.override_on_enable = "BindPaths=/tmp/alternate:/etc/caddy\n"
    sync = os.fsync
    synced = []

    def observe(fd: int) -> None:
        if os.path.samestat(os.fstat(fd), host.boot_link.parent.stat()):
            synced.append(not host.boot_link.is_symlink())
        sync(fd)

    def observe_when_created(fd: int) -> None:
        if host.boot_link.parent.exists():
            observe(fd)
        else:
            sync(fd)

    monkeypatch.setattr(os, "fsync", observe_when_created)
    result = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert result[0].status is Status.FAIL and "unexpected Caddy systemd" in result[0].detail
    enable_at = host.commands.index(["systemctl", "enable", "--no-reload", caddy.UNIT])
    assert host.commands[enable_at + 1] == ["systemctl", "daemon-reload"]
    assert ["systemctl", "is-enabled", caddy.UNIT] in host.commands
    assert ["systemctl", "disable", caddy.UNIT] not in host.commands
    assert not host.enabled and not host.boot_link.is_symlink() and synced == [True]
    assert len(host.reloads) == 1 and caddy.CADDYFILE.read_text() == old


@pytest.mark.parametrize("replacement", ["same-target", "other-target"])
def test_restart_link_replaced_after_enable_is_left_for_manual_cleanup(
    host: Host, replacement: str
) -> None:
    _seed()
    host.installed = host.active = True
    host.override_on_enable = "NeedDaemonReload=yes\n"
    host.replace_boot_link = replacement
    result = caddy.apply_caddy(Runner(exec_fn=host), site=SITE, upstream=UPSTREAM)
    assert (
        result[0].status is Status.FAIL and "manual boot-state cleanup required" in result[0].detail
    )
    assert host.boot_link.is_symlink()
    expected = (
        caddy.VENDOR_UNIT_DIRS[0] / caddy.UNIT
        if replacement == "same-target"
        else Path("/tmp/foreign")
    )
    assert host.boot_link.readlink() == expected
    assert ["systemctl", "disable", caddy.UNIT] not in host.commands
