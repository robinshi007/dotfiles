import configparser
import hashlib
import json
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from lhm.core import caddy_guard
from lhm.core.files import locked_target
from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import caddy, fail2ban

JAIL_STATUS = """Status for the jail: sshd
|- Filter
|  |- Currently failed: 3
|  |- Total failed:     12
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 1
   |- Total banned:     4
   `- Banned IP list:   203.0.113.9
"""

DEBUG_DUMP = """['set', 'sshd', 'maxretry', 3]
['set', 'sshd', 'findtime', '30m']
['set', 'sshd', 'bantime', '8h']
['set', 'sshd', 'bantime.increment', True]
['set', 'sshd', 'bantime.factor', '3']
"""


@pytest.fixture
def jail_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "fail2ban" / "jail.d" / "99-lhm.local"
    monkeypatch.setattr(fail2ban, "JAIL_DROPIN", target)
    return target


@pytest.fixture
def filter_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "fail2ban" / "filter.d" / "caddy-lhm.conf"
    monkeypatch.setattr(fail2ban, "CADDY_FILTER", target)
    return target


@pytest.fixture
def files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Drop-in, filter, dbfile and the legacy jail.local under one tmp root."""
    root = tmp_path / "etc" / "fail2ban"
    root.parent.mkdir(mode=0o755)
    monkeypatch.setattr(caddy, "CADDYFILE", root.parent / "caddy" / "Caddyfile")
    monkeypatch.setattr(fail2ban, "JAIL_DROPIN", root / "jail.d" / "99-lhm.local")
    monkeypatch.setattr(fail2ban, "CADDY_FILTER", root / "filter.d" / "caddy-lhm.conf")
    monkeypatch.setattr(
        fail2ban, "CADDY_ACCESS_FILTER", root / "filter.d" / "caddy-lhm-access.conf"
    )
    monkeypatch.setattr(fail2ban, "CADDY_ACCESS_LOG", tmp_path / "log" / "access.log")
    monkeypatch.setattr(fail2ban, "LEGACY_JAIL_LOCAL", root / "jail.local")
    monkeypatch.setattr(fail2ban, "DBFILE", tmp_path / "lib" / "fail2ban.sqlite3")
    return root


def _fake_tools(fake_exec: Any, *, active: bool = True) -> None:
    """Baseline probe answers: installed, active, sshd jail, increment active."""
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            (
                "systemctl is-active fail2ban",
                0 if active else 3,
                "active\n" if active else "inactive\n",
                "",
            ),
            ("fail2ban-client status sshd", 0, JAIL_STATUS, ""),
            ("fail2ban-client get sshd bantime", 0, "28800\n", ""),
            ("fail2ban-client -d", 0, DEBUG_DUMP, ""),
            ("systemctl list-unit-files caddy.service", 0, "UNIT FILE STATE PRESET\n", ""),
        ]
    )


def test_template_has_strict_sshd_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fail2ban.socket, "gethostname", lambda: "box1")
    text = fail2ban.desired_conf()
    assert "port = 22345" in text
    assert "mode = aggressive" in text
    assert "maxretry = 3" in text
    assert "findtime = 30m" in text
    assert "bantime = 8h" in text
    assert "bantime.increment = true" in text
    assert "bantime.factor = 3" in text
    assert "bantime.maxtime = 4w" in text
    assert "bantime.rndtime = 30m" in text
    assert "sender = fail2ban@box1" in text
    assert "backend = systemd" in text
    assert "banaction = nftables-multiport" in text
    # bantime/findtime/maxretry belong per jail, not in [DEFAULT].
    default = text.split("[sshd]")[0]
    assert "bantime" not in default
    assert "findtime" not in default
    assert "maxretry" not in default
    # dbfile stays at the packaging default: no active setting for it.
    assert "dbfile =" not in text


def test_template_renders_caddy_disabled_by_default() -> None:
    text = fail2ban.desired_conf()
    caddy = text.split("[caddy]")[1]
    assert "enabled = false" in caddy
    assert "port = 80,443" in caddy
    assert "journalmatch = _SYSTEMD_UNIT=caddy.service" in caddy
    assert "filter = caddy-lhm" in caddy
    assert "bantime = 1h" in caddy
    assert "bantime.increment = true" in caddy


def test_template_renders_caddy_enabled() -> None:
    text = fail2ban.desired_conf(caddy=True, caddy_maxretry="7")
    caddy = text.split("[caddy]")[1]
    assert "enabled = true" in caddy
    assert "maxretry = 7" in caddy


def test_bantime_seconds_helper() -> None:
    assert fail2ban._seconds("8h") == 28800
    assert fail2ban._seconds("4w") == 2419200
    assert fail2ban._seconds("30m") == 1800
    assert fail2ban._seconds("3600") == 3600
    assert fail2ban._seconds("soon") is None


def test_caddy_filter_matches_abuse_statuses() -> None:
    text = fail2ban.desired_caddy_filter()
    assert "datepattern = {NONE}" in text
    assert '"remote_ip":"<HOST>"' in text
    assert "(?:401|403|404|429)" in text


def _match(pattern: str, line: str) -> str | None:
    """Mimic fail2ban's <HOST> capture with a simple IPv4 group."""
    import re

    source = pattern.replace("<HOST>", r"(?P<host>\d{1,3}(?:\.\d{1,3}){3})")
    match = re.search(source, line)
    return match.group("host") if match else None


def test_caddy_regex_matches_each_status_with_correct_host() -> None:
    import re

    text = fail2ban.desired_caddy_filter()
    body = text.split("failregex =", 1)[1]
    patterns = [" ".join(line.split()) for line in body.strip().splitlines()]
    assert len(patterns) == 2

    def host_of(line: str) -> str | None:
        for pattern in patterns:
            host = _match(pattern, line)
            if host is not None:
                return host
        return None

    for status in (401, 403, 404, 429):
        line = (
            '{"level":"info","ts":1,"logger":"http.log.access","msg":"handled request",'
            '"request":{"remote_ip":"203.0.113.9","remote_port":"1","proto":"HTTP/1.1",'
            '"method":"GET","host":"x","uri":"/y"},"status":'
            f"{status}"
            ',"size":1}'
        )
        assert host_of(line) == "203.0.113.9"
    # status before remote_ip must match through the second pattern.
    reversed_line = '{"status":403,"request":{"remote_ip":"198.51.100.4","uri":"/z"},"size":0}'
    assert host_of(reversed_line) == "198.51.100.4"
    assert re.search(r"<HOST>", text)


def test_caddy_regex_ignores_benign_lines() -> None:
    text = fail2ban.desired_caddy_filter()
    body = text.split("failregex =", 1)[1]
    patterns = [" ".join(line.split()) for line in body.strip().splitlines()]

    def host_of(line: str) -> str | None:
        for pattern in patterns:
            host = _match(pattern, line)
            if host is not None:
                return host
        return None

    benign = [
        '{"request":{"remote_ip":"198.51.100.21","uri":"/ok"},"status":200,"size":5}',
        '{"request":{"remote_ip":"198.51.100.22","uri":"/404"},"status":200,"size":5}',
        'time=2024-01-01T00:00:00Z level=info msg="handled" remote_ip=198.51.100.24 status=404',
        '{"request":{"remote_ip":"198.51.100.25","uri":"/a"},"status":302,"size":0}',
    ]
    for line in benign:
        assert host_of(line) is None, line


CADDY_26_401 = (
    '{"level":"error","ts":1795575108.713024,"logger":"http.log.access.log0",'
    '"msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"47700",'
    '"proto":"HTTP/1.1","method":"GET","host":"127.0.0.1:35263",'
    '"uri":"/private?target=%22status%22","headers":{"User-Agent":["Python-urllib/3.15"],'
    '"X-Forwarded-For":["198.51.100.4"],"Authorization":[],"Connection":["close"],'
    '"Accept-Encoding":["identity"]}},"user_id":"","duration":0.000004969,"size":0,"status":401,'
    '"resp_headers":{"Www-Authenticate":["Basic"],"Content-Type":[],"Server":["Caddy"]}}'
)


def _access_sample(
    remote_ip: str,
    *,
    status: int = 401,
    path: str = "/private",
    ts: float = 1795597219.1234567,
) -> str:
    record: dict[str, object] = {
        "level": "info",
        "ts": ts,
        "logger": "http.log.access.log0",
        "msg": "handled request",
        "request": {
            "remote_ip": remote_ip,
            "remote_port": "53451",
            "client_ip": "192.0.2.70",
            "proto": "HTTP/2.0",
            "method": "GET",
            "host": "edge.example",
            "uri": f'{path}?x=","status":401,"uri":"/private"',
            "headers": {
                "X-Forwarded-For": ["198.51.100.40"],
                "Authorization": ["REDACTED"],
                "Lhm_Auth": ["protected"],
            },
            "tls": {
                "resumed": False,
                "version": 772,
                "cipher_suite": 4865,
                "proto": "h2",
                "server_name": "edge.example",
            },
        },
        "bytes_read": 0,
        "user_id": "",
        "duration": 0.004031863,
        "size": 0,
        "status": status,
        "resp_headers": {"Www-Authenticate": ['Basic realm="restricted"']},
    }
    return json.dumps(record, separators=(",", ":"))


@pytest.mark.parametrize("ts", [1795597219, 1795597219.1, 1795597219.1234567])
def test_access_filter_uses_only_socket_peer_for_protected_401(ts: float) -> None:
    parser = configparser.ConfigParser()
    parser.read_string(fail2ban.desired_caddy_filter(protected_paths=("/private", "/other/auth")))
    date = parser["Definition"]["datepattern"].replace("{EPOCH}", r"\d{10,11}\b(?:\.\d{3,6})?")
    fail = parser["Definition"]["failregex"].replace("<ADDR>", r"(?P<ip>[\dA-Fa-f.:]+)")

    def peer(line: str) -> str | None:
        without_date = re.sub(date, lambda match: match[0][: match.start(1) - match.start()], line)
        match = re.fullmatch(fail, without_date)
        return match.group("ip") if match else None

    assert peer(CADDY_26_401) == "127.0.0.1"
    for ip in ("203.0.113.9", "2001:db8::9"):
        assert peer(_access_sample(ip, ts=ts)) == ip
        assert peer(_access_sample(ip, path="/other/auth", ts=ts)) == ip
        for path in ("/private/no", "/private-other", "/%70rivate", "/public"):
            assert peer(_access_sample(ip, path=path, ts=ts)) is None
        for status in (200, 403, 404, 429):
            assert peer(_access_sample(ip, status=status, ts=ts)) is None


def test_invalid_duration_is_refused(fake_exec: Any, files: Path) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), bantime="soon")
    assert results[0].status is Status.FAIL
    assert "invalid bantime" in results[0].detail
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()


@pytest.mark.parametrize("value", ["0", "0s", "0m", "0h", "0d", "0w"])
@pytest.mark.parametrize("field", ["bantime", "findtime"])
def test_zero_duration_is_refused(
    fake_exec: Any, files: Path, field: str, value: str
) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), **{field: value})
    assert results[0].status is Status.FAIL
    assert f"invalid {field}" in results[0].detail
    assert "strictly positive" in results[0].detail
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()


@pytest.mark.parametrize("field", ["maxretry", "caddy_maxretry"])
def test_zero_retry_is_refused(fake_exec: Any, files: Path, field: str) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), caddy=True, **{field: "0"})
    assert results[0].status is Status.FAIL
    assert f"invalid {field}" in results[0].detail
    assert "strictly positive" in results[0].detail
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()


@pytest.mark.parametrize("value", ["3h", "3s", "3m", "3d", "3w", "1.5", "-1", "abc", ""])
@pytest.mark.parametrize("field", ["maxretry", "caddy_maxretry"])
def test_unit_suffixed_or_non_numeric_retry_is_refused(
    fake_exec: Any, files: Path, field: str, value: str
) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), caddy=True, **{field: value})
    assert results[0].status is Status.FAIL
    assert f"invalid {field}" in results[0].detail
    assert "positive integer" in results[0].detail
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()


def test_valid_durations_and_retries_still_render() -> None:
    text = fail2ban.desired_conf(
        bantime="3600", findtime="1h", maxretry="7", caddy=True, caddy_maxretry="9"
    )
    sshd = text.split("[sshd]")[1].split("[caddy]")[0]
    assert "bantime = 3600" in sshd
    assert "findtime = 1h" in sshd
    assert "maxretry = 7" in sshd
    assert "maxretry = 9" in text.split("[caddy]")[1]


def test_legacy_jail_local_is_never_written(fake_exec: Any, files: Path) -> None:
    legacy = files / "jail.local"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[dropbear]\nenabled = true\n", encoding="utf-8")
    with pytest.raises(fail2ban.JailError, match="refusing to write"):
        fail2ban._write_managed(legacy, "overwritten")
    assert legacy.read_text(encoding="utf-8") == "[dropbear]\nenabled = true\n"


def test_apply_never_writes_the_legacy_jail_local(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lhm.modules import fail2ban as module

    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)

    written: list[Path] = []
    real = module.write_dropin

    def spy(path: Path, content: str, mode: int | None = None) -> str:
        written.append(Path(path))
        return real(path, content, mode)

    legacy = files / "jail.local"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[dropbear]\nenabled = true\n", encoding="utf-8")
    module.write_dropin = spy
    try:
        _fake_tools(fake_exec)
        fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    finally:
        module.write_dropin = real
    assert written == [files / "jail.d" / "99-lhm.local"]
    assert legacy.read_text(encoding="utf-8") == "[dropbear]\nenabled = true\n"


def test_dry_run_records_no_commands(fake_exec: Any, files: Path) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = fail2ban.apply_fail2ban(runner)
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()
    assert [r.status for r in results] == [
        Status.PLANNED,
        Status.PLANNED,
        Status.PLANNED,
    ]
    planned = [" ".join(cmd) for cmd in runner.planned]
    assert any("apt-get install" in cmd and "fail2ban" in cmd for cmd in planned)
    assert "systemctl enable --now fail2ban" in planned


def test_dry_run_with_caddy_plans_both_files(
    fake_exec: Any, files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = fail2ban.apply_fail2ban(runner, caddy=True)
    out = capsys.readouterr().out
    assert str(files / "jail.d" / "99-lhm.local") in out
    assert str(files / "filter.d" / "caddy-lhm.conf") in out
    assert "caddy jail enabled in the drop-in" in out
    assert "caddy jail disabled (pass --caddy)" not in out
    # install, drop-in, filter and the activation command are all planned.
    assert [r.status for r in results] == [
        Status.PLANNED,
        Status.PLANNED,
        Status.PLANNED,
        Status.PLANNED,
    ]
    assert fake_exec.calls == []


def test_plan_mentions_legacy_jail_local(
    fake_exec: Any, files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fail2ban.apply_fail2ban(Runner(dry_run=True, exec_fn=fake_exec))
    out = capsys.readouterr().out
    assert "preserved untouched" in out
    assert "jail.d/*.local wins" in out


def test_caddy_warns_when_unit_cannot_be_probed(
    fake_exec: Any, files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # In a dry-run the unit is never probed, so the plan warns instead.
    fail2ban.apply_fail2ban(Runner(dry_run=True, exec_fn=fake_exec), caddy=True)
    out = capsys.readouterr().out
    assert "WARNING" in out


def test_apply_installs_writes_and_verifies(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query -W -f=${Status} fail2ban", 1, "", "not installed"),
            ("dpkg-query -W -f=${Status} nftables", 1, "", "not installed"),
            ("systemctl is-active fail2ban", 3, "inactive\n", ""),
            ("systemctl is-enabled fail2ban", 1, "disabled\n", ""),
            ("fail2ban-client status sshd", 0, JAIL_STATUS, ""),
            ("fail2ban-client get sshd bantime", 0, "28800\n", ""),
            ("fail2ban-client -d", 0, DEBUG_DUMP, ""),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    dropin = files / "jail.d" / "99-lhm.local"
    assert names["install fail2ban nftables"] is Status.CHANGED
    assert names[f"write {dropin}"] is Status.CHANGED
    assert names["enable --now fail2ban"] is Status.CHANGED
    assert results[-4].status is Status.OK
    assert "currently banned: 1" in results[-4].detail
    assert "8h effective" in results[-3].detail
    assert "incrementing bans active" in results[-2].detail
    assert results[-1].status is Status.SKIPPED
    content = dropin.read_text(encoding="utf-8")
    assert "port = 22345" in content
    assert "bantime.increment = true" in content
    assert not (files / "jail.local").exists()
    executed = [" ".join(call) for call in fake_exec.calls]
    assert any("apt-get install" in call and "nftables" in call for call in executed)
    assert "systemctl enable --now fail2ban" in executed
    assert "systemctl reload fail2ban" not in executed


def test_apply_caddy_writes_filter_and_enables_jail(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_tools(fake_exec)
    fake_exec.responses.extend(
        [
            ("fail2ban-client status caddy", 0, "Status for the jail: caddy\n", ""),
            (
                "systemctl list-unit-files caddy.service",
                0,
                "caddy.service enabled enabled\n",
                "",
            ),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), caddy=True)
    dropin = files / "jail.d" / "99-lhm.local"
    caddy_filter = files / "filter.d" / "caddy-lhm.conf"
    assert caddy_filter.is_file()
    assert "datepattern = {NONE}" in caddy_filter.read_text(encoding="utf-8")
    assert "enabled = true" in dropin.read_text(encoding="utf-8").split("[caddy]")[1]
    names = {r.name: r.status for r in results}
    assert names[f"write {caddy_filter}"] is Status.CHANGED
    assert names["verify caddy jail"] is Status.OK


CADDY_RUNTIME = '{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}}}}'
CADDY_RUNTIME_PROBE = "fake-caddy-runtime-fingerprint"
DIRECT_GENERATION = "1" * 32


@pytest.fixture
def direct_access(files: Path, monkeypatch: pytest.MonkeyPatch) -> fail2ban.DirectAccess:
    log = fail2ban.CADDY_ACCESS_LOG
    log.parent.mkdir()
    log.parent.chmod(0o750)
    log.write_text(CADDY_26_401 + "\n", encoding="utf-8")
    log.chmod(0o640)

    def probe(runner: Runner) -> caddy.RunningConfig | None:
        result = runner.run([CADDY_RUNTIME_PROBE], check=False)
        if not result.ok or not result.stdout:
            return None
        digest = hashlib.sha256(result.stdout.encode()).hexdigest()
        return caddy.RunningConfig("1" * 32, digest, "edge.example", log, digest)

    monkeypatch.setattr(caddy, "running_config_fingerprint", probe)
    monkeypatch.setattr(fail2ban.secrets, "token_hex", lambda size: DIRECT_GENERATION)
    monkeypatch.setattr(fail2ban.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(
        caddy_guard,
        "trusted_log",
        lambda path, uid: path.is_file() and not path.stat().st_mode & 0o022,
    )
    digest = hashlib.sha256(CADDY_RUNTIME.encode()).hexdigest()
    return fail2ban.DirectAccess(digest, ("/private",), DIRECT_GENERATION)


def _fake_access_tools(
    fake_exec: Any,
    *,
    runtime: str = CADDY_RUNTIME,
    verified: bool = True,
    missing_rule: bool = False,
    absent: bool = False,
    new_jail: str | None = None,
    nft_cleanup: tuple[int, str] = (0, '{"nftables":[]}'),
    mismatch: str | None = None,
) -> Runner:
    _fake_tools(fake_exec)
    digest = hashlib.sha256(CADDY_RUNTIME.encode()).hexdigest()
    policy = fail2ban.DirectAccess(digest, ("/private",), DIRECT_GENERATION)
    jail = policy.jail
    chain = """table inet f2b-table {
    chain f2b-chain {
        type filter hook input priority -1; policy accept;
        tcp dport { 80, 443 } ip saddr @addr-set-caddy-lhm-access reject
        tcp dport { 80, 443 } ip6 saddr @addr6-set-caddy-lhm-access reject
        udp dport 443 ip saddr @addr-set-caddy-lhm-access-quic reject
        udp dport 443 ip6 saddr @addr6-set-caddy-lhm-access-quic reject
    }
}
"""
    if missing_rule:
        chain = chain.replace("udp dport 443 ip6 saddr @addr6-set-caddy-lhm-access-quic reject", "")
    effective = new_jail or jail
    chain = chain.replace(fail2ban.ACCESS_JAIL, effective)
    expected_regex = "(?P<ip4>mock-compiled-attested-regex)"
    guard = fail2ban._access_guard(policy).replace("%%", "%")
    fake_exec.responses.extend(
        [
            ("systemctl is-enabled fail2ban", 1, "disabled\n", ""),
            ("/usr/bin/python3 -I -c", 0, expected_regex, ""),
            (CADDY_RUNTIME_PROBE, 0 if verified else 1, runtime, ""),
            (f"fail2ban-client status {jail}", 0, f"Status for the jail: {jail}\n", ""),
            (f"fail2ban-client status {effective}", 0, f"Status for the jail: {effective}\n", ""),
            (
                f"fail2ban-client get {effective} logpath",
                0,
                f"Current monitored log file(s):\n`- {fail2ban.CADDY_ACCESS_LOG}\n",
                "",
            ),
            (
                f"fail2ban-client get {effective} actions",
                0,
                "The jail has the following actions:\nnftables-multiport, nftables-caddy-quic",
                "",
            ),
            (
                f"fail2ban-client get {effective} failregex",
                0,
                "The following regular expression are defined:\n"
                f"`- [0]: {'wrong' if mismatch == 'regex' else expected_regex}\n",
                "",
            ),
            (
                f"fail2ban-client get {effective} ignorecommand",
                0,
                "" if mismatch == "guard" else guard,
                "",
            ),
            ("nft --numeric list chain inet f2b-table f2b-chain", 0, chain, ""),
            ("nft --json list ruleset", nft_cleanup[0], nft_cleanup[1], ""),
        ]
    )

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = fake_exec(cmd, timeout)
        if cmd[:2] == ["fail2ban-client", "status"] and cmd[-1] in {jail, effective}:
            queried = cmd[-1]
            stopped = absent
            for call in fake_exec.calls:
                if call == ["fail2ban-client", "stop", queried]:
                    stopped = True
                if call == ["fail2ban-client", "reload", "--restart"]:
                    stopped = False
            if stopped:
                return subprocess.CompletedProcess(cmd, 1, "", f"jail '{queried}' does not exist")
        return result

    return Runner(exec_fn=execute)


@pytest.mark.parametrize("missing_rule", [False, True])
def test_auto_caddy_verifies_effective_firewall_and_exact_file(
    fake_exec: Any,
    files: Path,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    missing_rule: bool,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    runner = _fake_access_tools(fake_exec, missing_rule=missing_rule)
    results = fail2ban.apply_fail2ban(
        runner, caddy_direct=True, caddy_protected_paths=("/private",)
    )
    names = {r.name: r.status for r in results}
    assert names["verify caddy log path"] is Status.OK
    assert names["verify caddy nftables action"] is (Status.FAIL if missing_rule else Status.OK)
    assert ["fail2ban-client", "-t"] in fake_exec.calls
    assert not any("banip" in cmd for cmd in fake_exec.calls)
    if missing_rule:
        assert not fail2ban.JAIL_DROPIN.exists()
        assert not fail2ban.CADDY_ACCESS_FILTER.exists()
        assert ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
        return
    dropin = fail2ban.JAIL_DROPIN.read_text(encoding="utf-8")
    section = dropin.split(f"[{direct_access.jail}]")[1]
    assert "enabled = true\n" in section
    assert "backend = polling\n" in section
    assert f"logpath = {fail2ban.CADDY_ACCESS_LOG} tail\n" in section
    assert "usedns = no\n" in section
    assert "maxretry = 5\n" in section
    assert direct_access.digest in section
    assert "ignorecommand = " in section
    assert fail2ban.CADDY_ACCESS_FILTER.is_file()
    assert not fail2ban.CADDY_FILTER.exists()
    fake_exec.calls.clear()
    results = fail2ban.apply_fail2ban(runner)
    assert all(r.status is not Status.FAIL for r in results)
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


@pytest.mark.parametrize("unsafe", ["stale", "changed", "unmanaged", "unsafe-log", "missing"])
def test_auto_caddy_fails_closed_and_removes_own_stale_jail(
    fake_exec: Any,
    files: Path,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    if unsafe == "unmanaged":
        monkeypatch.setattr(caddy, "running_config_fingerprint", lambda runner: None)
    elif unsafe == "unsafe-log":
        fail2ban.CADDY_ACCESS_LOG.chmod(0o666)
    elif unsafe == "missing":
        fail2ban.CADDY_ACCESS_LOG.unlink()
    changed = CADDY_RUNTIME.replace("443", "444")
    runner = _fake_access_tools(
        fake_exec,
        runtime=changed if unsafe in {"stale", "changed"} else CADDY_RUNTIME,
        verified=unsafe != "stale",
    )
    path = fail2ban.JAIL_DROPIN
    path.parent.mkdir(parents=True)
    desired = fail2ban.desired_conf(bantime="16h", caddy_mode="file", direct=direct_access)
    path.write_text(desired, encoding="utf-8")
    fail2ban.apply_fail2ban(runner)
    assert f"[{direct_access.jail}]" not in path.read_text(encoding="utf-8")
    assert not fail2ban.CADDY_ACCESS_FILTER.exists()
    assert ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
    assert ["fail2ban-client", "reload", "--restart"] in fake_exec.calls


def test_existing_legacy_journald_mode_is_not_migrated(
    fake_exec: Any,
    files: Path,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_access_tools(fake_exec)
    jail = fail2ban.JAIL_DROPIN
    jail.parent.mkdir(parents=True)
    legacy = fail2ban.desired_conf(caddy=True)
    jail.write_text(legacy, encoding="utf-8")
    fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert jail.read_text(encoding="utf-8") == legacy
    assert fail2ban.CADDY_FILTER.is_file()
    assert not fail2ban.CADDY_ACCESS_FILTER.exists()


def test_caddy_never_infers_topology_from_managed_log_and_samples(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_access_tools(fake_exec)
    fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert not fail2ban.CADDY_ACCESS_FILTER.exists()
    assert fail2ban.ACCESS_JAIL not in fail2ban.JAIL_DROPIN.read_text(encoding="utf-8")
    assert [CADDY_RUNTIME_PROBE] not in fake_exec.calls


def test_revoke_caddy_attestation_stops_file_jail_without_legacy_fallback(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    runner = _fake_access_tools(fake_exec)
    jail = fail2ban.JAIL_DROPIN
    jail.parent.mkdir(parents=True)
    desired = fail2ban.desired_conf(bantime="16h", caddy_mode="file", direct=direct_access)
    jail.write_text(desired, encoding="utf-8")
    results = fail2ban.apply_fail2ban(runner, caddy_revoke_direct=True)
    assert all(r.status is not Status.FAIL for r in results)
    assert jail.read_text(encoding="utf-8") == fail2ban.desired_conf(
        bantime="16h",
        caddy_mode="unmanaged",
    )
    assert ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
    assert not fail2ban.CADDY_FILTER.exists()
    assert [CADDY_RUNTIME_PROBE] not in fake_exec.calls
    assert not any(cmd[0] == "dpkg-query" for cmd in fake_exec.calls)
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


def _seed_file_jail(policy: fail2ban.DirectAccess) -> None:
    jail, filter_path = fail2ban.JAIL_DROPIN, fail2ban.CADDY_ACCESS_FILTER
    jail.parent.mkdir(parents=True)
    filter_path.parent.mkdir(parents=True)
    jail.write_text(fail2ban.desired_conf(caddy_mode="file", direct=policy), encoding="utf-8")
    filter_path.write_text(
        fail2ban.desired_caddy_filter(protected_paths=policy.protected_paths), encoding="utf-8"
    )


@pytest.mark.parametrize("leftover", ["set", "rule", "unreadable"])
def test_revoke_refuses_unverified_nft_cleanup_and_retains_retry_marker(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    leftover: str,
) -> None:
    _seed_file_jail(direct_access)
    name = f"addr6-set-{direct_access.jail}-quic"
    if leftover == "set":
        ruleset = {"nftables": [{"set": {"name": name, "table": "f2b-table"}}]}
    else:
        ruleset = {"nftables": [{"rule": {"expr": [{"match": {"right": f"@{name}"}}]}}]}
    cleanup = (1, "") if leftover == "unreadable" else (0, json.dumps(ruleset))
    runner = _fake_access_tools(fake_exec, nft_cleanup=cleanup)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    result = fail2ban.apply_fail2ban(runner, caddy_revoke_direct=True)[-1]
    assert result.status is Status.FAIL and "nftables" in result.detail
    revoked = fail2ban.JAIL_DROPIN.read_text()
    assert f"[{direct_access.jail}]" not in revoked
    assert fail2ban._pending_access_cleanup(revoked) == direct_access.jail
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls
    fake_exec.responses.insert(0, ("nft --json list ruleset", 0, '{"nftables":[]}', ""))
    assert fail2ban.apply_fail2ban(runner, caddy_revoke_direct=True)[-1].status is Status.CHANGED
    assert fail2ban._pending_access_cleanup(fail2ban.JAIL_DROPIN.read_text()) is None


def test_revocation_fsync_orders_marker_stop_and_clear(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_file_jail(direct_access)
    runner = _fake_access_tools(fake_exec)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    observed: list[tuple[str | None, bool]] = []
    sync = fail2ban._sync_jail_directory

    def record_sync() -> None:
        sync()
        pending = fail2ban._pending_access_cleanup(fail2ban.JAIL_DROPIN.read_text())
        stopped = ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
        observed.append((pending, stopped))

    monkeypatch.setattr(fail2ban, "_sync_jail_directory", record_sync)
    assert fail2ban.apply_fail2ban(runner, caddy_revoke_direct=True)[-1].status is Status.CHANGED
    assert observed == [(direct_access.jail, False), (None, True)]


def test_revoke_does_not_stop_when_marker_fsync_fails(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_file_jail(direct_access)
    runner = _fake_access_tools(fake_exec)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)

    def failed_fsync() -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(fail2ban, "_sync_jail_directory", failed_fsync)
    assert fail2ban.apply_fail2ban(runner, caddy_revoke_direct=True)[-1].status is Status.FAIL
    assert not any(cmd[:2] == ["fail2ban-client", "stop"] for cmd in fake_exec.calls)


@pytest.mark.parametrize("override", ["filter", "precedence"])
def test_rechecks_override_after_config_validation_before_reload(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    host = _fake_access_tools(fake_exec)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    external = (
        fail2ban.CADDY_ACCESS_FILTER.with_suffix(".local")
        if override == "filter"
        else fail2ban.JAIL_DROPIN.parent / "zzz-unmanaged.local"
    )

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if cmd == ["fail2ban-client", "-t"]:
            external.write_text("[caddy]\nenabled = true\n")
        return host.exec_fn(cmd, timeout)

    results = fail2ban.apply_fail2ban(
        Runner(exec_fn=execute),
        caddy_direct=True,
        caddy_protected_paths=direct_access.protected_paths,
    )
    assert results[-1].status is Status.FAIL
    assert "override" in results[-1].detail or "precedence" in results[-1].detail
    assert external.exists()
    assert not fail2ban.JAIL_DROPIN.exists()
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


def test_reload_failure_restores_prior_ssh_without_resurrecting_revoked_caddy(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = direct_access
    new = fail2ban.DirectAccess(old.digest, old.protected_paths, "2" * 32)
    _seed_file_jail(old)
    jail_path = fail2ban.JAIL_DROPIN
    jail_path.write_text(fail2ban.desired_conf(bantime="16h", caddy_mode="file", direct=old))
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    monkeypatch.setattr(fail2ban.secrets, "token_hex", lambda size: new.generation)
    host = _fake_access_tools(fake_exec, new_jail=new.jail)
    reloads: list[str] = []

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        result = host.exec_fn(cmd, timeout)
        if cmd == ["fail2ban-client", "reload", "--restart"]:
            reloads.append(jail_path.read_text())
            if len(reloads) == 1:
                return subprocess.CompletedProcess(cmd, 1, "", "reload failed")
        return result

    results = fail2ban.apply_fail2ban(
        Runner(exec_fn=execute),
        caddy_direct=True,
        caddy_protected_paths=old.protected_paths,
    )
    assert results[-1].status is Status.FAIL
    assert len(reloads) == 2
    assert new.jail in reloads[0]
    assert reloads[1] == fail2ban.desired_conf(bantime="16h", caddy_mode="unmanaged")
    assert all(old.jail not in conf for conf in reloads)
    assert ["fail2ban-client", "stop", new.jail] in fake_exec.calls


@pytest.mark.parametrize("mismatch", ["regex", "guard"])
def test_bad_live_policy_is_revoked_even_with_same_policy_identity(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    _seed_file_jail(direct_access)
    runner = _fake_access_tools(fake_exec, mismatch=mismatch)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    results = fail2ban.apply_fail2ban(runner, bantime="16h")
    assert results[-1].status is Status.FAIL
    assert mismatch in results[-1].detail
    assert ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
    assert fail2ban.JAIL_DROPIN.read_text() == fail2ban.desired_conf(caddy_mode="unmanaged")


def test_restore_ssh_atomically_preserves_pending_new_jail_cleanup(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = fail2ban.JAIL_DROPIN
    path.parent.mkdir(parents=True)
    previous = fail2ban.desired_conf(bantime="16h")
    path.write_text(previous)
    runner = _fake_access_tools(fake_exec, mismatch="guard", nft_cleanup=(1, ""))
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    original = fail2ban._write_managed
    rollback = fail2ban.rollback_file
    replacements: list[str] = []

    def write(path_to_write: Path, content: str, **kwargs: Any) -> str:
        result = original(path_to_write, content, **kwargs)
        if path_to_write == path:
            replacements.append(path.read_text())
        return result

    def restore(path_to_restore: Path, *, backup: Path | None = None) -> Path:
        assert path_to_restore != path, "must not replace the jail file with an unmarked backup"
        return rollback(path_to_restore, backup=backup)

    monkeypatch.setattr(fail2ban, "_write_managed", write)
    monkeypatch.setattr(fail2ban, "rollback_file", restore)
    results = fail2ban.apply_fail2ban(
        runner, caddy_direct=True, caddy_protected_paths=direct_access.protected_paths
    )
    assert results[-1].status is Status.FAIL
    assert len(replacements) >= 3
    assert all(
        fail2ban._pending_access_cleanup(text) == direct_access.jail for text in replacements[1:]
    )
    assert "bantime = 16h" in replacements[-1]
    assert f"[{direct_access.jail}]" not in replacements[-1]


@pytest.mark.parametrize("request_type", ["direct", "ssh", "default"])
def test_apply_with_pending_cleanup_cannot_report_ignored_settings_as_success(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    request_type: str,
) -> None:
    _seed_file_jail(direct_access)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    pending = fail2ban._record_access_revocation(
        fail2ban.JAIL_DROPIN.read_text(), direct_access.jail
    )
    assert fail2ban._pending_access_cleanup(pending) == direct_access.jail
    host = _fake_access_tools(fake_exec)
    fake_exec.responses.insert(0, ("nft --json list ruleset", 0, '{"nftables":[]}', ""))
    direct = request_type == "direct"
    results = fail2ban.apply_fail2ban(
        host,
        bantime="16h" if request_type == "ssh" else fail2ban.SSHD_BANTIME,
        caddy_direct=direct,
        caddy_protected_paths=direct_access.protected_paths if direct else (),
    )
    assert results[-1].status is Status.FAIL and "rerun" in results[-1].detail
    assert fail2ban._pending_access_cleanup(fail2ban.JAIL_DROPIN.read_text()) is None
    assert "bantime = 16h" not in fail2ban.JAIL_DROPIN.read_text()
    assert [CADDY_RUNTIME_PROBE] not in fake_exec.calls
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


@pytest.mark.parametrize("fail_at", ["install", "config-test"])
@pytest.mark.parametrize("previously_absent", [True, False])
def test_first_install_autostart_is_reversed_on_failure_before_activation(
    fake_exec: Any,
    files: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_at: str,
    previously_absent: bool,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    installed, active = False, False
    enable = "not-found" if previously_absent else "enabled-runtime"
    initial_enable = enable

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        fake_exec(cmd, timeout)

        def result(code: int = 0, text: str = "") -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(cmd, code, text, "")

        nonlocal installed, active, enable
        if cmd == ["dpkg-query", "-W", "-f=${Status}", "fail2ban"]:
            return result(1)
        if cmd == ["systemctl", "is-active", "fail2ban"]:
            if enable == "not-found":
                return result(4, "unknown")
            return result(0, "active") if active else result(3, "inactive")
        if cmd == ["systemctl", "is-enabled", "fail2ban"]:
            return result(1 if enable in {"not-found", "disabled"} else 0, enable)
        if cmd == ["systemctl", "show", "--property=LoadState", "--value", "fail2ban"]:
            return result(0, "not-found" if enable == "not-found" else "loaded")
        if cmd[:4] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"]:
            installed, active, enable = True, True, "enabled"
            return result(1 if fail_at == "install" else 0)
        if cmd == ["fail2ban-client", "-t"]:
            return result(1)
        if cmd == ["systemctl", "stop", "fail2ban"]:
            active = False
        if cmd == ["systemctl", "disable", "fail2ban"]:
            enable = "disabled"
        if cmd == ["systemctl", "enable", "--runtime", "fail2ban"]:
            enable = "enabled-runtime"
        return result()

    results = fail2ban.apply_fail2ban(Runner(exec_fn=execute))
    assert results[-1].status is Status.FAIL
    assert "packages may remain" in results[-1].detail
    assert installed and not active
    assert enable == ("disabled" if previously_absent else initial_enable)
    assert not fail2ban.JAIL_DROPIN.exists()
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls
    assert ["systemctl", "enable", "--now", "fail2ban"] not in fake_exec.calls


@pytest.mark.parametrize("boot_state", ["enabled", "disabled", "enabled-runtime"])
@pytest.mark.parametrize("fail_at", ["enable", "verify"])
def test_activation_failure_restores_boot_and_active_state_independently(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    boot_state: str,
    fail_at: str,
) -> None:
    host = _fake_access_tools(fake_exec, mismatch="guard")
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    active, enable = False, boot_state

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal active, enable
        result = host.exec_fn(cmd, timeout)
        if cmd == ["systemctl", "is-active", "fail2ban"]:
            state = "active" if active else "inactive"
            return subprocess.CompletedProcess(cmd, 0 if active else 3, state)
        if cmd == ["systemctl", "is-enabled", "fail2ban"]:
            return subprocess.CompletedProcess(cmd, 0 if enable != "disabled" else 1, enable)
        if cmd == ["systemctl", "enable", "--now", "fail2ban"]:
            active, enable = True, "enabled"
            if fail_at == "enable":
                return subprocess.CompletedProcess(cmd, 1, "", "partially applied")
        elif cmd == ["systemctl", "stop", "fail2ban"]:
            active = False
        elif cmd == ["systemctl", "disable", "fail2ban"]:
            enable = "disabled"
        elif cmd == ["systemctl", "enable", "--runtime", "fail2ban"]:
            enable = "enabled-runtime"
        return result

    results = fail2ban.apply_fail2ban(
        Runner(exec_fn=execute),
        caddy_direct=True,
        caddy_protected_paths=direct_access.protected_paths,
    )
    assert results[-1].status is Status.FAIL
    assert not active and enable == boot_state


def test_explicit_reassurance_uses_new_ticket_namespace_even_for_same_config(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = direct_access
    new = fail2ban.DirectAccess(old.digest, old.protected_paths, "2" * 32)
    _seed_file_jail(old)
    runner = _fake_access_tools(fake_exec, new_jail=new.jail)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    monkeypatch.setattr(fail2ban.secrets, "token_hex", lambda size: new.generation)
    results = fail2ban.apply_fail2ban(
        runner, caddy_direct=True, caddy_protected_paths=old.protected_paths
    )
    assert all(r.status is not Status.FAIL for r in results)
    assert old.jail != new.jail
    assert ["fail2ban-client", "stop", old.jail] in fake_exec.calls
    assert fail2ban.inspect(runner)["caddy_jail"] == new.jail
    assert fail2ban.inspect(runner)["caddy_mode"] == "file"


def test_unchanged_policy_restarts_a_stopped_file_jail(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_file_jail(direct_access)
    runner = _fake_access_tools(fake_exec, absent=True)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    before = fail2ban.JAIL_DROPIN.read_bytes()
    results = fail2ban.apply_fail2ban(runner)
    assert all(r.status is not Status.FAIL for r in results)
    assert ["fail2ban-client", "reload", "--restart"] in fake_exec.calls
    assert fail2ban.JAIL_DROPIN.read_bytes() == before


def test_file_config_validation_failure_restores_previous_ssh_and_filter(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _fake_access_tools(fake_exec)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    fake_exec.responses.insert(0, ("fail2ban-client -t", 1, "", "invalid full configuration"))
    jail, filter_path = fail2ban.JAIL_DROPIN, fail2ban.CADDY_ACCESS_FILTER
    jail.parent.mkdir(parents=True)
    filter_path.parent.mkdir(parents=True)
    jail.write_text(fail2ban.desired_conf(bantime="16h"), encoding="utf-8")
    filter_path.write_text(
        fail2ban.desired_caddy_filter(protected_paths=("/previous",)), encoding="utf-8"
    )
    baseline = (jail.read_bytes(), filter_path.read_bytes())
    results = fail2ban.apply_fail2ban(
        runner, caddy_direct=True, caddy_protected_paths=direct_access.protected_paths
    )
    assert results[-1].status is Status.FAIL
    assert (jail.read_bytes(), filter_path.read_bytes()) == baseline
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


def test_apply_does_not_interleave_with_caddy_transaction(fake_exec: Any, files: Path) -> None:
    with locked_target(caddy.CADDYFILE.parent):
        (result,) = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert result.status is Status.FAIL
    assert "locked" in result.detail
    assert fake_exec.calls == []


def test_apply_keeps_both_locks_through_final_verification(
    fake_exec: Any,
    files: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_tools(fake_exec)
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    verified = False

    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal verified
        if cmd == ["fail2ban-client", "status", "sshd"]:
            verified = True
            for path in (caddy.CADDYFILE.parent, fail2ban.JAIL_DROPIN.parents[1]):
                with pytest.raises(BlockingIOError), locked_target(path):
                    pytest.fail("verification must still hold both locks")
        return fake_exec(cmd, timeout)

    results = fail2ban.apply_fail2ban(Runner(exec_fn=execute))
    assert all(r.status is not Status.FAIL for r in results)
    assert verified


def test_caddy_transition_can_revoke_only_the_file_jail(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
) -> None:
    _seed_file_jail(direct_access)
    dropin = fail2ban.JAIL_DROPIN
    dropin.write_text(
        fail2ban.desired_conf(bantime="16h", caddy_mode="file", direct=direct_access),
        encoding="utf-8",
    )
    runner = _fake_access_tools(fake_exec)
    with locked_target(caddy.CADDYFILE.parent):
        assert fail2ban.stop_managed_caddy_access(runner, revoke=True)
    assert dropin.read_text(encoding="utf-8") == fail2ban.desired_conf(
        bantime="16h",
        caddy_mode="unmanaged",
    )
    assert ["fail2ban-client", "stop", direct_access.jail] in fake_exec.calls
    assert ["nft", "--json", "list", "ruleset"] in fake_exec.calls
    assert ["fail2ban-client", "reload", "--restart"] not in fake_exec.calls


def test_apply_reprobes_running_attestation_after_confirmation(
    fake_exec: Any,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _fake_access_tools(fake_exec)

    def confirm(plan: list[str]) -> bool:
        fake_exec.responses.insert(0, (CADDY_RUNTIME_PROBE, 0, '{"changed":true}', ""))
        return True

    monkeypatch.setattr(fail2ban, "confirm_once", confirm)
    results = fail2ban.apply_fail2ban(
        runner, caddy_direct=True, caddy_protected_paths=direct_access.protected_paths
    )
    assert results[-1].status is Status.FAIL
    assert "eligibility changed" in results[-1].detail
    assert not fail2ban.JAIL_DROPIN.exists()


@pytest.mark.parametrize(("rc", "state"), [(1, ""), (3, "activating"), (0, ""), (4, "unknown")])
def test_unknown_fail2ban_service_status_cannot_trigger_activation(
    fake_exec: Any,
    files: Path,
    rc: int,
    state: str,
) -> None:
    _fake_tools(fake_exec)
    fake_exec.responses.insert(0, ("systemctl is-active fail2ban", rc, state, ""))
    (result,) = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert result.status is Status.FAIL
    assert "cannot determine stable" in result.detail
    assert not fail2ban.JAIL_DROPIN.exists()
    assert not any(cmd[:2] == ["systemctl", "enable"] for cmd in fake_exec.calls)


def test_guard_reopens_rotated_file_and_refuses_writable_or_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "caddy"
    directory.mkdir(mode=0o750)
    log = directory / "access.log"
    log.write_text("first\n", encoding="utf-8")
    log.chmod(0o640)
    original = os.fstat

    def ancestors(fd: int) -> os.stat_result:
        meta = original(fd)
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if path not in {directory, log}:
            fields = list(meta)
            fields[0] &= ~0o022
            fields[4] = 0
            return os.stat_result(fields)
        return meta

    monkeypatch.setattr(caddy_guard.os, "fstat", ancestors)
    assert caddy_guard.trusted_log(log, os.getuid())
    original_log = log.rename(directory / "rolled.log")
    log.write_text("rotated\n", encoding="utf-8")
    log.chmod(0o640)
    assert caddy_guard.trusted_log(log, os.getuid())
    assert not caddy_guard.trusted_log(log, os.getuid() + 1)
    log.chmod(0o660)
    assert not caddy_guard.trusted_log(log, os.getuid())
    log.unlink()
    log.symlink_to(original_log)
    with pytest.raises(OSError):
        caddy_guard.trusted_log(log, os.getuid())


def test_guard_binds_unix_admin_response_to_main_pid(tmp_path: Path) -> None:
    body = b'{"apps":{}}'
    path = tmp_path / "admin.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen()
        server.settimeout(2)
        with pytest.raises(ValueError, match="wrong Caddy admin socket peer"):
            caddy_guard.runtime_digest(str(path), os.getpid() + 1)
        stale, _ = server.accept()
        stale.close()

        def respond() -> None:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(2)
                assert connection.recv(1024).startswith(b"GET /config/ HTTP/1.0")
                connection.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + body + b"\n")

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(respond)
            expected = hashlib.sha256(body).hexdigest()
            assert caddy_guard.runtime_digest(str(path), os.getpid()) == expected
            response.result(timeout=2)


def test_guard_rejects_service_replaced_during_admin_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = iter([(42, "a" * 32), (43, "b" * 32)])
    monkeypatch.setattr(caddy_guard, "service", lambda: next(states))
    monkeypatch.setattr(caddy_guard.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=7))
    monkeypatch.setattr(caddy_guard, "trusted_log", lambda path, uid: True)
    monkeypatch.setattr(caddy_guard, "runtime_digest", lambda path, pid: "2" * 64)
    assert not caddy_guard.permits("2" * 64, "/socket", tmp_path / "access.log")


@pytest.mark.parametrize("path", ["/admin/../login", "/login?token=x", "/api/*", "/a//b"])
def test_direct_attestation_refuses_nonliteral_paths(
    fake_exec: Any,
    files: Path,
    path: str,
) -> None:
    (result,) = fail2ban.apply_fail2ban(
        Runner(exec_fn=fake_exec), caddy_direct=True, caddy_protected_paths=(path,)
    )
    assert result.status is Status.FAIL
    assert "literal protected paths" in result.detail
    assert fake_exec.calls == []


def test_auto_caddy_refuses_single_retry(
    fake_exec: Any,
    files: Path,
    direct_access: fail2ban.DirectAccess,
) -> None:
    _fake_access_tools(fake_exec)
    (result,) = fail2ban.apply_fail2ban(
        Runner(exec_fn=fake_exec),
        caddy_maxretry="1",
        caddy_direct=True,
        caddy_protected_paths=("/private",),
    )
    assert result.status is Status.FAIL
    assert "at least 2" in result.detail
    assert not fail2ban.JAIL_DROPIN.exists()


@pytest.mark.parametrize("relative", ["jail.conf", "jail.local", "jail.d/admin.local"])
def test_external_caddy_jail_remains_authoritative(
    fake_exec: Any,
    files: Path,
    direct_access: fail2ban.DirectAccess,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_access_tools(fake_exec)
    external = files / relative
    external.parent.mkdir(parents=True, exist_ok=True)
    baseline = "[caddy]\nenabled = true\n"
    external.write_text(baseline, encoding="utf-8")
    fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), caddy=True)
    assert external.read_text(encoding="utf-8") == baseline
    assert "\n[caddy" not in fail2ban.JAIL_DROPIN.read_text(encoding="utf-8")
    assert not fail2ban.CADDY_FILTER.exists()
    assert not fail2ban.CADDY_ACCESS_FILTER.exists()


def test_refuses_unmanaged_file_at_managed_jail_path(fake_exec: Any, files: Path) -> None:
    path = fail2ban.JAIL_DROPIN
    path.parent.mkdir(parents=True)
    baseline = "[caddy]\nenabled = true\n"
    path.write_text(baseline, encoding="utf-8")
    (result,) = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert result.status is Status.FAIL
    assert "unmanaged" in result.detail
    assert path.read_text(encoding="utf-8") == baseline
    assert fake_exec.calls == []


def test_restart_jails_when_already_active(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain `systemctl reload` leaves the jail with no action (see _activate).

    fail2ban 1.0.2 reload never runs actionstart, and when banaction resolves to
    a new action name it deletes both the old and the new action: the jail then
    has no action at all, every ban only lands in the DB and the nftables table
    is never created.
    """
    (files / "jail.d").mkdir(parents=True)
    (files / "jail.d" / "99-lhm.local").write_text(fail2ban.JAIL_HEADER, encoding="utf-8")
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_tools(fake_exec, active=True)
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "fail2ban-client reload --restart" in executed
    # The failure mode: neither a unit reload nor a jail-less `fail2ban-client
    # reload` re-runs the action's actionstart, which creates the nftables table.
    assert "systemctl reload fail2ban" not in executed
    # A bare `fail2ban-client reload` (no --restart) keeps the broken action.
    reloads = [call for call in executed if call.startswith("fail2ban-client reload")]
    assert reloads == ["fail2ban-client reload --restart"]
    assert "systemctl enable --now fail2ban" not in executed
    assert {r.name: r.status for r in results}["reload --restart fail2ban"] is Status.CHANGED


def test_restart_path_enables_when_inactive(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (files / "jail.d").mkdir(parents=True)
    (files / "jail.d" / "99-lhm.local").write_text(fail2ban.JAIL_HEADER, encoding="utf-8")
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_tools(fake_exec, active=False)
    fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "systemctl enable --now fail2ban" in executed
    assert "fail2ban-client reload --restart" not in executed
    assert "systemctl reload fail2ban" not in executed


def test_second_run_is_idempotent(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dropin = files / "jail.d" / "99-lhm.local"
    dropin.parent.mkdir(parents=True)
    dropin.write_text(fail2ban.desired_conf(), encoding="utf-8")
    dbfile = files.parent / "lib" / "fail2ban.sqlite3"
    dbfile.parent.mkdir(parents=True)
    dbfile.write_bytes(b"db")
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_tools(fake_exec)
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    statuses = [r.status for r in results]
    # install, write drop-in and reload are skipped; the caddy jail is not enabled.
    assert statuses.count(Status.SKIPPED) == 4
    assert results[-4].status is Status.OK
    assert not (dropin.parent / "99-lhm.local.bak").exists()
    executed = [" ".join(call) for call in fake_exec.calls]
    assert not any("apt-get install" in call for call in executed)
    assert "systemctl enable --now fail2ban" not in executed
    assert "fail2ban-client reload --restart" not in executed
    assert "systemctl reload fail2ban" not in executed


def test_verify_fails_without_sshd_jail(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client status sshd", 1, "", "Sorry but the jail 'sshd' does not exist"),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.FAIL
    assert "does not exist" in results[-1].detail


def test_verify_degrades_to_skipped_without_client(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify degrades to SKIPPED when fail2ban-client cannot be probed.

    The service is inactive here: with an active daemon the jail restart goes
    through fail2ban-client, so a missing client is a hard failure, not a skip.
    """
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 3, "inactive\n", ""),
            ("fail2ban-client", 127, "", "fail2ban-client: command not found"),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.SKIPPED
    assert "fail2ban-client unavailable" in results[-1].detail


def test_verify_skips_bantime_when_client_cannot_read(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_once", lambda plan: True)
    _fake_tools(fake_exec)
    fake_exec.responses.insert(
        3, ("fail2ban-client get sshd bantime", 255, "", "permission denied")
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["verify bantime"] is Status.SKIPPED


def test_inspect_reports_new_paths(fake_exec: Any, files: Path) -> None:
    _fake_tools(fake_exec)
    state = fail2ban.inspect(Runner(exec_fn=fake_exec))
    assert state["jail_dropin"] == str(files / "jail.d" / "99-lhm.local")
    assert state["caddy_filter"] == str(files / "filter.d" / "caddy-lhm.conf")
    assert state["jail_current"] is False
    # no drop-in yet, so the caddy jail state is simply unknown.
    assert state["caddy_enabled"] is None
    assert state["legacy_jail_local_present"] is False
    assert state["dbfile_present"] is False


def test_dbfile_comes_from_the_daemon_dump(
    fake_exec: Any, files: Path, tmp_path: Path
) -> None:
    real_db = tmp_path / "var" / "lib" / "fail2ban.sqlite3"
    real_db.parent.mkdir(parents=True)
    real_db.write_bytes(b"db")
    fake_exec.responses.append(
        (
            "fail2ban-client -d",
            0,
            f"['set', 'dbfile', '{real_db}']\n",
            "",
        )
    )
    path, present = fail2ban.dbfile_path(Runner(exec_fn=fake_exec))
    assert path == real_db
    assert present is True


def test_dbfile_falls_back_to_the_packaging_default(
    fake_exec: Any, files: Path, tmp_path: Path
) -> None:
    fake_exec.responses.append(("fail2ban-client -d", 127, "", "not found"))
    path, present = fail2ban.dbfile_path(Runner(exec_fn=fake_exec))
    assert path == tmp_path / "lib" / "fail2ban.sqlite3"
    assert present is False


def test_check_includes_dropin_filter_and_dbfile(
    fake_exec: Any, files: Path, tmp_path: Path
) -> None:
    from lhm import cli

    dropin = files / "jail.d" / "99-lhm.local"
    dropin.parent.mkdir(parents=True)
    dropin.write_text(fail2ban.desired_conf(caddy=True), encoding="utf-8")
    dbfile = tmp_path / "lib" / "fail2ban.sqlite3"
    dbfile.parent.mkdir(parents=True)
    dbfile.write_bytes(b"db")
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client -d", 0, f"['set', 'dbfile', '{dbfile}']\n", ""),
        ]
    )
    ok, detail = cli._check_fail2ban(Runner(exec_fn=fake_exec))
    # caddy is enabled in the drop-in but filter.d/caddy-lhm.conf is missing.
    assert ok is False
    assert "caddy-lhm.conf missing" in detail


def test_check_reports_ok_when_everything_is_in_place(
    fake_exec: Any, files: Path, tmp_path: Path
) -> None:
    from lhm import cli

    dropin = files / "jail.d" / "99-lhm.local"
    dropin.parent.mkdir(parents=True)
    dropin.write_text(fail2ban.desired_conf(), encoding="utf-8")
    dbfile = tmp_path / "lib" / "fail2ban.sqlite3"
    dbfile.parent.mkdir(parents=True)
    dbfile.write_bytes(b"db")
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 0, "active\n", ""),
            ("fail2ban-client -d", 0, f"['set', 'dbfile', '{dbfile}']\n", ""),
        ]
    )
    ok, detail = cli._check_fail2ban(Runner(exec_fn=fake_exec))
    assert ok is True, detail
    assert "sshd jail configured and active" in detail
