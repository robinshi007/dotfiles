"""Exercise the registered firewall command with real Caddy ingress attestation."""

import errno
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from lhm import cli
from lhm.core import network
from lhm.core.confirm import BYPASS_ENV
from lhm.core.runner import Runner
from lhm.modules import caddy, firewall, ssh, ssh_watchdog

SITE = "app.example.com"
CADDY_PID = 99
ADAPTED = '{"apps":{"http":{"servers":{"http":{"listen":[":80"]},"https":{"listen":[":443"]}}}}}'
UFW_RULE_FILES = {
    f"/etc/ufw/{stage}{suffix}.rules"
    for stage in ("before", "after", "user")
    for suffix in ("", "6")
}
ALLOW_REPLIES = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"


class Host:
    """Emulate command output and UFW state without executing any commands."""

    def __init__(self, *, ipv6: bool, vendor_unit: Path) -> None:
        self.ipv6 = ipv6
        self.vendor_unit = vendor_unit
        self.active = False
        self.rules: list[str] = []
        self.mutations: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        rc, out, err = 0, "", ""
        match cmd:
            case ["ss", "-tlnp"]:
                out = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n'
            case ["systemctl", "is-active", "ssh.socket" | "sshd.socket"]:
                rc, out = 4, "inactive\n"
            case ["systemctl", "show", "--property=UnitPath", "--value"]:
                out = f"{caddy.INSTALL_HOLD.parent.parent} {self.vendor_unit.parent}\n"
            case [
                "systemctl",
                "show",
                "--all",
                properties,
                "caddy.service",
            ] if properties.startswith("--property=ExecStart,"):
                binary, config = caddy.CADDY_BINARY, caddy.CADDYFILE
                out = (
                    f"User=caddy\nFragmentPath={self.vendor_unit}\nDropInPaths=\n"
                    "ExecCondition=\nExecStartPre=\nExecStartPost=\nExecStop=\nExecStopPost=\n"
                    "RootDirectory=\nRootImage=\nRootImageOptions=\nBindPaths=\nBindReadOnlyPaths=\n"
                    "TemporaryFileSystem=\nMountImages=\nExtensionImages=\nExtensionDirectories=\n"
                    "InaccessiblePaths=\nReadOnlyPaths=\nReadWritePaths=\nExecPaths=\nNoExecPaths=\n"
                    "ConfigurationDirectory=\nStateDirectory=\nRuntimeDirectory=\nCacheDirectory=\n"
                    "LogsDirectory=\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nPAMName=\n"
                    f"ExecStart={{ path={binary} ; argv[]={binary} run --environ "
                    f"--config {config} ; ignore_errors=no ; "
                    "start_time=[Wed 2026-11-25 10:00:00 UTC] ; stop_time=[n/a] ; "
                    f"pid={CADDY_PID} ; code=(null) ; status=0/0 }}\n"
                    f"ExecReload={{ path={binary} ; argv[]={binary} reload "
                    f"--config {config} --force ; ignore_errors=no ; "
                    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
                )
            case ["systemctl", "show", _, "caddy.service"]:
                out = (
                    "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n"
                    f"InvocationID=1234567890abcdef1234567890abcdef\nMainPID={CADDY_PID}\n"
                )
            case ["ss", "-H", "-lntpe", "-O", "( sport = :80 or sport = :443 )"]:
                addr, flags = ("*", " v6only:0") if self.ipv6 else ("0.0.0.0", "")
                out = "\n".join(
                    f"LISTEN 0 4096 {addr}:{port} {addr}:* "
                    f'users:(("caddy",pid={CADDY_PID},fd={fd})) ino:{inode}{flags}'
                    for port, fd, inode in ((80, 7, 401), (443, 8, 402))
                )
            case ["caddy", "adapt", "--config", config, "--adapter", "caddyfile"]:
                assert Path(config) == caddy.CADDYFILE
                out = ADAPTED
            case ["curl", *options, url] if url.startswith("http://127.0.0.1/"):
                assert "--header" in options and f"Host: {SITE}" in options
                out = f"308\n{url.replace('http://127.0.0.1', f'https://{SITE}', 1)}"
            case ["cat", "/etc/default/ufw"]:
                out = f'IPV6={"yes" if self.ipv6 else "no"}\nMANAGE_BUILTINS=no\nIPT_SYSCTL=""\n'
            case ["cat", "/etc/ufw/ufw.conf"]:
                out = "ENABLED=yes\n" if self.active else "ENABLED=no\n"
            case ["test", "!", "-x", "/etc/ufw/before.init" | "/etc/ufw/after.init"]:
                pass
            case ["cat", path] if path in UFW_RULE_FILES:
                stem = Path(path).stem
                prefix = "ufw6" if stem.endswith("6") else "ufw"
                assert self.ipv6 or prefix == "ufw"
                stage = stem.removesuffix("6")
                chain = f"{prefix}-{stage}"
                out = "\n".join(
                    [
                        "*filter",
                        *(
                            f":{chain}-{direction} - [0:0]"
                            for direction in ("input", "output", "forward")
                        ),
                        *([f"-A {chain}-output {ALLOW_REPLIES}"] if stage == "before" else []),
                        *(self._filter_rules(prefix) if stage == "user" else []),
                        "COMMIT",
                    ]
                )
            case ["iptables" | "ip6tables" as tool, "-w", "2", "-S"]:
                assert self.ipv6 or tool == "iptables"
                out = self._runtime_filter("ufw6" if tool == "ip6tables" else "ufw")
            case ["ip6tables", "-w", "2", "-L", "INPUT", "-n"] if not self.ipv6:
                rc, err = 1, "Address family not supported by protocol\n"
            case ["ufw", "status", "verbose"]:
                out = "Status: inactive\n"
                if self.active:
                    out = (
                        "Status: active\n"
                        "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                        "To   Action   From\n"
                        "--   ------   ----\n"
                        + "".join(
                            f"{rule}{suffix}   ALLOW IN   Anywhere{suffix}\n"
                            for rule in self.rules
                            for suffix in (("", " (v6)") if self.ipv6 else ("",))
                        )
                    )
            case ["ufw", "allow", rule]:
                self.mutations.append(cmd)
                self.rules.append(rule)
            case ["ufw", "default", *_]:
                self.mutations.append(cmd)
            case ["ufw", "--force", "enable"]:
                self.mutations.append(cmd)
                self.active = True
            case _:
                pytest.fail(f"unexpected host command: {cmd}")
        if cmd[:2] == ["systemctl", "show"] and cmd[-1] == "caddy.service":
            if "NeedDaemonReload" in cmd[-2].removeprefix("--property=").split(","):
                out += "NeedDaemonReload=no\n"
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def _filter_rules(self, prefix: str) -> list[str]:
        return [
            f"-A {prefix}-user-input -p {proto} -m {proto} --dport {port} -j ACCEPT"
            for port, proto in (rule.split("/") for rule in self.rules)
        ]

    def _runtime_filter(self, prefix: str) -> str:
        if not self.active:
            return "-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n"
        hooks = ("before-logging", "before", "after", "after-logging", "reject", "track")
        chains = [
            (direction, f"{prefix}-{hook}-{direction}")
            for direction in ("input", "output")
            for hook in hooks
        ]
        return "\n".join(
            [
                "-P INPUT DROP",
                "-P OUTPUT ACCEPT",
                *(f"-N {chain}" for _, chain in chains),
                f"-N {prefix}-user-input",
                *(f"-A {direction.upper()} -j {chain}" for direction, chain in chains),
                f"-A {prefix}-before-input -j {prefix}-user-input",
                f"-A {prefix}-before-output {ALLOW_REPLIES}",
                *self._filter_rules(prefix),
            ]
        )


@pytest.mark.parametrize(
    ("ipv6", "runtime_port", "web_rules"),
    [
        pytest.param(True, 443, ("80/tcp", "443/tcp"), id="dual-stack-matches"),
        pytest.param(True, 8443, (), id="dual-stack-mismatches"),
        pytest.param(False, 443, ("80/tcp", "443/tcp"), id="ipv4-only-matches"),
    ],
)
def test_apply_firewall_uses_live_managed_caddy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ipv6: bool,
    runtime_port: int,
    web_rules: tuple[str, ...],
) -> None:
    config = tmp_path / "caddy" / "Caddyfile"
    config.parent.mkdir(mode=0o700)
    monkeypatch.setattr(caddy, "CADDYFILE", config)
    install_hold = tmp_path / "units" / "caddy.service.d" / "zz-lhm-install-hold.conf"
    install_hold.parent.parent.mkdir(mode=0o700)
    install_hold.parent.mkdir(mode=0o700)
    monkeypatch.setattr(caddy, "INSTALL_HOLD", install_hold)
    monkeypatch.setattr(caddy, "ADMIN_SOCKET", tmp_path / "admin.sock")
    monkeypatch.setattr(caddy, "ACCESS_LOG", tmp_path / "access.log")
    monkeypatch.setattr(caddy, "ROOT_UID", os.geteuid())
    config.write_text(caddy.desired_conf(site=SITE, upstream="127.0.0.1:8080"), encoding="utf-8")
    config.chmod(0o644)
    binary = tmp_path / "caddy-bin"
    binary.touch(mode=0o700)
    monkeypatch.setattr(caddy, "CADDY_BINARY", binary)
    vendor_unit = tmp_path / "vendor-units" / "caddy.service"
    vendor_unit.parent.mkdir(mode=0o700)
    vendor_unit.write_text(
        "[Service]\nType=notify\nUser=caddy\nGroup=caddy\n"
        f"ExecStart={binary} run --environ --config {config}\n"
        f"ExecReload={binary} reload --config {config} --force\n",
        encoding="utf-8",
    )
    vendor_unit.chmod(0o644)
    monkeypatch.setattr(caddy, "VENDOR_UNIT_DIRS", (vendor_unit.parent,))
    proc = tmp_path / "proc"
    netns = proc / "1/ns/net"
    netns.parent.mkdir(parents=True)
    netns.touch()
    for member in (str(CADDY_PID), "self"):
        namespace = proc / member / "ns/net"
        namespace.parent.mkdir(parents=True)
        namespace.hardlink_to(netns)
    monkeypatch.setattr(caddy, "PROC", proc)

    runtime = tmp_path / "running.json"
    servers = {"http": {"listen": [":80"]}, "https": {"listen": [f":{runtime_port}"]}}
    runtime.write_text(
        json.dumps({"apps": {"http": {"servers": servers}}}),
        encoding="utf-8",
    )
    runtime_pids: list[int] = []

    def read_admin_socket(pid: int) -> str:
        runtime_pids.append(pid)
        return runtime.read_text(encoding="utf-8")

    monkeypatch.setattr(caddy, "_runtime_json", read_admin_socket)
    ipv6_conf = tmp_path / "ipv6"
    (ipv6_conf / "default").mkdir(parents=True)
    (ipv6_conf / "default" / "disable_ipv6").write_text("0\n", encoding="ascii")
    monkeypatch.setattr(network, "IPV6_CONF", ipv6_conf)
    module_disable = tmp_path / "ipv6-module-disable"
    module_disable.write_text("0\n" if ipv6 else "1\n", encoding="ascii")
    monkeypatch.setattr(network, "IPV6_MODULE_DISABLE", module_disable)
    if not ipv6:

        def unavailable_socket(family: int, kind: int) -> None:
            assert (family, kind) == (socket.AF_INET6, socket.SOCK_DGRAM)
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported by protocol")

        monkeypatch.setattr(socket, "socket", unavailable_socket)
    monkeypatch.setattr(firewall, "UFW_LOCK_TARGET", tmp_path / "ufw.conf")
    ssh_config = tmp_path / "sshd_config.d"
    ssh_config.mkdir(mode=0o700)
    monkeypatch.setattr(ssh, "SSHD_DROPIN", ssh_config / "99-lhm.conf")
    watchdog_state = tmp_path / "lhm-ssh-rollback"
    watchdog_state.mkdir(mode=0o700)
    monkeypatch.setattr(ssh_watchdog, "_STATE_DIR", watchdog_state)
    monkeypatch.setattr(ssh_watchdog, "_ROOT_UID", os.geteuid())

    def trust_watchdog_parent(path: Path, *, directory: bool) -> None:
        # pytest's ancestors do not have the ownership and permissions of /run.
        assert path == tmp_path and directory
        ssh_watchdog._trusted(path.lstat(), path, directory=directory)

    monkeypatch.setattr(ssh_watchdog, "_trusted_path", trust_watchdog_parent)
    monkeypatch.setenv(BYPASS_ENV, "1")
    monkeypatch.setattr(cli, "is_root", lambda: True)
    host = Host(ipv6=ipv6, vendor_unit=vendor_unit)

    def make_runner(*, dry_run: bool, verbose: bool) -> Runner:
        return Runner(dry_run=dry_run, verbose=verbose, exec_fn=host)

    monkeypatch.setattr(cli, "Runner", make_runner)
    # The SSH, Caddy and UFW production locks are confined to tmp_path.
    assert cli.main(["apply", "firewall"]) == cli.EXIT_OK
    assert runtime_pids and set(runtime_pids) == {CADDY_PID}
    assert host.mutations == [
        ["ufw", "allow", "22345/tcp"],
        ["ufw", "allow", "22/tcp"],
        *(["ufw", "allow", rule] for rule in web_rules),
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "allow", "outgoing"],
        ["ufw", "--force", "enable"],
    ]
