from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import fail2ban

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
    monkeypatch.setattr(fail2ban, "JAIL_DROPIN", root / "jail.d" / "99-lhm.local")
    monkeypatch.setattr(fail2ban, "CADDY_FILTER", root / "filter.d" / "caddy-lhm.conf")
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
                0 if active else 1,
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


def test_invalid_duration_is_refused(fake_exec: Any, files: Path) -> None:
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec), bantime="soon")
    assert results[0].status is Status.FAIL
    assert "invalid bantime" in results[0].detail
    assert fake_exec.calls == []
    assert not (files / "jail.d" / "99-lhm.local").exists()


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

    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)

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
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query -W -f=${Status} fail2ban", 1, "", "not installed"),
            ("dpkg-query -W -f=${Status} nftables", 1, "", "not installed"),
            ("systemctl is-active fail2ban", 1, "inactive\n", ""),
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
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
    (files / "jail.d" / "99-lhm.local").write_text("[DEFAULT]\n", encoding="utf-8")
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
    (files / "jail.d" / "99-lhm.local").write_text("[DEFAULT]\n", encoding="utf-8")
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active fail2ban", 1, "inactive\n", ""),
            ("fail2ban-client", 127, "", "fail2ban-client: command not found"),
        ]
    )
    results = fail2ban.apply_fail2ban(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.SKIPPED
    assert "fail2ban-client unavailable" in results[-1].detail


def test_verify_skips_bantime_when_client_cannot_read(
    fake_exec: Any, files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fail2ban, "confirm_twice", lambda plan: True)
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
