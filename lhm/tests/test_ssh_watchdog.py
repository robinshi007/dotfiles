import json
import os
import stat
import subprocess
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from lhm.core.mutations import mutation_mode
from lhm.core.runner import Runner
from lhm.modules import ssh
from lhm.modules import ssh_watchdog as watchdog

NOW = 44_000.0
TXID = "1a" * 16
UNIT = f"lhm-ssh-rollback-{TXID}"
TIMER = f"{UNIT}.timer"
SERVICE = f"{UNIT}.service"


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    python_root = tmp_path / "python"
    executable = python_root / "bin/python3.15"
    package = tmp_path / "src"
    entry = package / "lhm/modules/ssh_watchdog.py"
    executable.parent.mkdir(parents=True)
    entry.parent.mkdir(parents=True)
    executable.touch(mode=0o700)
    entry.touch()
    init = package / "lhm/__init__.py"
    init.touch()
    for directory in (executable.parent, python_root, package, entry.parent, entry.parent.parent):
        directory.chmod(0o755)
    entry.chmod(0o644)
    init.chmod(0o644)
    monkeypatch.setattr(watchdog, "_STATE_DIR", state)
    monkeypatch.setattr(watchdog, "_ROOT_UID", os.geteuid())
    monkeypatch.setattr(watchdog, "_PYTHON_ROOT", python_root)
    monkeypatch.setattr(watchdog, "_PYTHON", executable)
    monkeypatch.setattr(watchdog, "_PACKAGE", package)
    monkeypatch.setattr(watchdog, "time", SimpleNamespace(monotonic=lambda: NOW))
    monkeypatch.setattr(watchdog, "secrets", SimpleNamespace(token_hex=lambda _: TXID))
    trusted = watchdog._trusted

    def trust_tmp_ancestors(info: os.stat_result, path: Path, *, directory: bool) -> None:
        if path not in tmp_path.parents:
            trusted(info, path, directory=directory)

    monkeypatch.setattr(watchdog, "_trusted", trust_tmp_ancestors)
    return state


def _systemd_properties(unit: str, interface: str, failure: str) -> dict[str, tuple[str, object]]:
    timer = unit == TIMER
    if interface == "Unit":
        return {
            "Id": ("s", unit),
            "LoadState": ("s", "loaded"),
            "ActiveState": ("s", "active" if timer else "inactive"),
            "SubState": (
                "s",
                "waiting" if timer else ("running" if failure == "service" else "dead"),
            ),
            "Transient": ("b", True),
            "DropInPaths": (
                "as",
                [f"/etc/systemd/system/{unit}.d/test.conf"]
                if failure == ("timer-dropin" if timer else "service-dropin")
                else [],
            ),
            "TriggeredBy": ("as", [TIMER]),
            "StartLimitIntervalUSec": ("t", 5_000_000 if failure == "rate-limit" else 0),
        }
    if timer:
        assert interface == "Timer"
        deadline = {"past": NOW - 1, "wrong-delay": NOW + 60, "late": NOW + 601}.get(
            failure, NOW + 600
        )
        return {
            "Unit": ("s", "other.service" if failure == "timer" else SERVICE),
            "AccuracyUSec": ("t", 1_000_000),
            "WakeSystem": ("b", False),
            "NextElapseUSecMonotonic": (
                ("s", "10min") if failure == "malformed-clock" else ("t", int(deadline * 1e6))
            ),
        }
    assert interface == "Service"
    path = str(watchdog._PYTHON)
    command = [
        path,
        "-I",
        "-S",
        "-B",
        "-c",
        watchdog._BOOTSTRAP,
        str(watchdog._PACKAGE),
        "expire",
        TXID,
    ]
    if failure == "wrong-argv":
        command[-2] = "probe"
    return {
        "Type": ("s", "exec"),
        "User": ("s", "nobody" if failure == "user" else "root"),
        "Group": ("s", "nogroup" if failure == "group" else "root"),
        "DynamicUser": ("b", False),
        "WorkingDirectory": ("s", "/"),
        "RootDirectory": ("s", ""),
        "RootImage": ("s", ""),
        "Environment": ("as", ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]),
        "Restart": ("s", "no"),
        "RestartUSec": ("t", 1_000_000 if failure == "retry-delay" else 5_000_000),
        "RestartForceExitStatus": (
            "(aiai)",
            [[], [75]] if failure == "retry-status" else [[75], []],
        ),
        "ExecStart": ("a(sasbttttuii)", [[path, command, False, *([0] * 7)]]),
    }


FakeRunner = Callable[..., Runner]


@pytest.fixture
def fake_runner(layout: Path) -> FakeRunner:
    def make(*, fail: str = "", stop_rc: int = 0, dry_run: bool = False) -> Runner:
        def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
            assert 0 < timeout <= 10
            if cmd[0] == str(watchdog._PYTHON):
                assert not layout.exists() or watchdog.current() is None
                assert cmd[1:5] == ["-I", "-S", "-B", "-c"]
                assert cmd[-3:] == [str(watchdog._PACKAGE), "probe", TXID]
                identity = json.loads(watchdog._runtime_identity())
                if fail in {"protocol", "schema"}:
                    identity[fail] += 1
                elif fail == "build":
                    identity["build"] = "0" * 64
                output = json.dumps(identity, separators=(",", ":"), sort_keys=True)
                return subprocess.CompletedProcess(cmd, 1 if fail == "python" else 0, output, "")
            if cmd[0] == "/usr/bin/systemd-run":
                # Even an ambiguous manager request must begin with an inert marker.
                assert watchdog.current() == watchdog.Pending(
                    TXID, NOW + 600, "prepared", {"attempted": []}
                )
                assert f"--unit={UNIT}" in cmd
                assert "--system" in cmd
                assert "--on-active=600s" in cmd
                assert "--timer-property=AccuracySec=1s" in cmd
                assert "--property=User=root" in cmd
                assert "--property=Group=root" in cmd
                assert "--property=StartLimitIntervalSec=0" in cmd
                assert "--property=RestartSec=5s" in cmd
                assert "--property=RestartForceExitStatus=75" in cmd
                assert "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin" in cmd
                assert cmd[-8:] == [
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    watchdog._BOOTSTRAP,
                    str(watchdog._PACKAGE),
                    "expire",
                    TXID,
                ]
                assert cmd[cmd.index("--") + 1] == str(watchdog._PYTHON)
                return subprocess.CompletedProcess(cmd, 124 if fail == "schedule" else 0, "", "")
            if cmd[0] == "/usr/bin/busctl":
                assert "--json=short" in cmd
                verb = cmd.index("get-property")
                destination, path, interface, *names = cmd[verb + 1 :]
                assert destination == "org.freedesktop.systemd1"
                base = f"/org/freedesktop/systemd1/unit/lhm_2dssh_2drollback_2d{TXID}_2e"
                assert path in {base + "timer", base + "service"}
                unit = TIMER if path == base + "timer" else SERVICE
                assert interface.startswith("org.freedesktop.systemd1.")
                properties = _systemd_properties(unit, interface.rsplit(".", 1)[-1], fail)
                rows = (
                    dict(zip(("type", "data"), properties[name], strict=True)) for name in names
                )
                # Older busctl releases may concatenate short JSON documents.
                output = "".join(json.dumps(row) for row in rows)
                return subprocess.CompletedProcess(cmd, 0, output, "")
            assert cmd == ["/usr/bin/systemctl", "--system", "stop", TIMER]
            assert watchdog.current() is None
            return subprocess.CompletedProcess(cmd, stop_rc, "", "")

        return Runner(exec_fn=execute, dry_run=dry_run)

    return make


def test_watchdog_round_trip(layout: Path, fake_runner: FakeRunner) -> None:
    assert watchdog.current() is None
    assert not layout.exists()
    runner = fake_runner()
    data: dict[str, object] = {"attempted": []}
    pending = watchdog.arm(runner, data)
    assert pending == watchdog.Pending(TXID, NOW + 600, "armed", data)
    assert watchdog.current() == pending
    assert stat.S_IMODE(layout.stat().st_mode) == 0o700
    marker = layout / "pending.json"
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600

    data["attempted"] = ["caller-only"]
    copy = pending.data
    attempted = copy["attempted"]
    assert isinstance(attempted, list)
    attempted.append("local-only")
    assert pending.data == {"attempted": []}
    with pytest.raises(FrozenInstanceError):
        setattr(pending, "phase", "failed")

    watchdog.update(pending, attempted=["drop-in"])
    waiting = watchdog.update(pending, phase="awaiting-confirm", socket="ssh.socket")
    assert waiting == watchdog.current()
    assert waiting.phase == "awaiting-confirm"
    assert waiting.data == {"attempted": ["drop-in"], "socket": "ssh.socket"}
    watchdog.clear(runner, pending)
    assert not marker.exists()
    assert watchdog.current() is None


@pytest.mark.parametrize(
    "failure",
    [
        "schedule",
        "timer",
        "service",
        "past",
        "wrong-delay",
        "late",
        "malformed-clock",
        "user",
        "group",
        "timer-dropin",
        "service-dropin",
        "wrong-argv",
        "rate-limit",
        "retry-delay",
        "retry-status",
    ],
)
def test_unverified_timer_is_inert(fake_runner: FakeRunner, failure: str) -> None:
    runner = fake_runner(fail=failure, stop_rc=1)
    with pytest.raises(watchdog.WatchdogError):
        watchdog.arm(runner, {"attempted": []})
    assert watchdog.current() is None
    assert runner.history[-1].cmd[-2:] == ["stop", TIMER]


def test_runtime_preflight_failure_creates_no_state(layout: Path, fake_runner: FakeRunner) -> None:
    runner = fake_runner(fail="python")
    with pytest.raises(watchdog.WatchdogError, match="standalone CPython 3.15"):
        watchdog.arm(runner, {"attempted": []})
    assert not layout.exists()
    assert len(runner.history) == 1


@pytest.mark.parametrize("mismatch", ["protocol", "schema", "build"])
def test_incompatible_runtime_creates_no_state(
    layout: Path, fake_runner: FakeRunner, mismatch: str
) -> None:
    runner = fake_runner(fail=mismatch)
    with pytest.raises(watchdog.WatchdogError, match="protocol/schema or build mismatch"):
        watchdog.arm(runner, {"attempted": []})
    assert not layout.exists()
    assert len(runner.history) == 1


def test_dry_run_creates_no_state_or_commands(layout: Path, fake_runner: FakeRunner) -> None:
    dry_runner = fake_runner(dry_run=True)
    with pytest.raises(watchdog.WatchdogError, match="live root"):
        watchdog.arm(dry_runner, {})
    runner = fake_runner()
    with mutation_mode(dry_run=True), pytest.raises(watchdog.WatchdogError, match="live root"):
        watchdog.arm(runner, {})
    assert runner.history == dry_runner.history == runner.planned == dry_runner.planned == []
    assert not layout.exists()


def test_stale_id_cannot_change_marker_or_stop_timer(fake_runner: FakeRunner) -> None:
    runner = fake_runner()
    actual = watchdog.arm(runner, {"attempted": []})
    stale = watchdog.Pending("3c" * 16, actual.deadline, actual.phase, actual.data)
    with pytest.raises(watchdog.WatchdogError, match="already|another"):
        watchdog.arm(runner, {"attempted": []})
    with pytest.raises(watchdog.WatchdogError, match="stale"):
        watchdog.update(stale, phase="failed")
    watchdog.clear(runner, stale)
    assert watchdog.current() == actual
    assert not any("stop" in result.cmd for result in runner.history)


@pytest.mark.parametrize("bad", ["link", "writable", "symbol", "ancestor", "bytecode"])
def test_untrusted_runtime_never_executes(
    layout: Path, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    if bad == "link":
        (watchdog._PACKAGE / "evil.py").symlink_to(watchdog._PYTHON)
    elif bad == "writable":
        (watchdog._PACKAGE / "lhm").chmod(0o775)
    elif bad == "symbol":
        monkeypatch.setattr(watchdog, "_PACKAGE", layout.parent / "$package")
    elif bad == "bytecode":
        bytecode = watchdog._PACKAGE / "lhm/modules/ssh.pyc"
        bytecode.touch(mode=0o600)
    else:
        layout.parent.chmod(0o777)
    runner = fake_runner()
    with pytest.raises(watchdog.WatchdogError, match="unsafe or missing|journal|untrusted"):
        watchdog.arm(runner, {"attempted": []})
    assert runner.history == []
    assert not layout.exists()


@pytest.mark.parametrize("unsafe", ["symlink-dir", "symlink-file", "hardlink", "directory-mode"])
def test_unsafe_journal_paths_fail_closed(layout: Path, unsafe: str) -> None:
    real = layout.parent / "real"
    marker = layout / "pending.json"
    if unsafe == "symlink-dir":
        real.mkdir(mode=0o700)
        layout.symlink_to(real, target_is_directory=True)
    else:
        layout.mkdir(mode=0o755 if unsafe == "directory-mode" else 0o700)
        real.write_text("{}")
        real.chmod(0o600)
        if unsafe == "symlink-file":
            marker.symlink_to(real)
        elif unsafe == "hardlink":
            os.link(real, marker)
    with pytest.raises(watchdog.WatchdogError):
        watchdog.current()


@pytest.mark.parametrize(
    "corrupt",
    [
        {"version": True},
        {"unknown": 1},
        {"phase": "bad phase"},
        {"id": "../bad"},
        {"deadline": float("nan")},
        {"deadline": NOW + 800},
        {"data": []},
        {"data": {"effect": 2**64}},
        {"data": {"effect": float("inf")}},
    ],
)
def test_invalid_marker_schema_fails_closed(layout: Path, corrupt: dict[str, object]) -> None:
    layout.mkdir(mode=0o700)
    marker = layout / "pending.json"
    valid: dict[str, object] = {
        "version": 1,
        "id": TXID,
        "deadline": NOW + 600,
        "phase": "prepared",
        "data": {},
    }
    marker.write_text(json.dumps(valid | corrupt))
    marker.chmod(0o600)
    with pytest.raises(watchdog.WatchdogError):
        watchdog.current()


def test_failed_atomic_replace_keeps_old_state(
    layout: Path, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    pending = watchdog.arm(fake_runner(), {"attempted": []})

    def fail(src: str, dst: str, **fds: int) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(watchdog.os, "replace", fail)
    with pytest.raises(watchdog.WatchdogError, match="replace failure"):
        watchdog.update(pending, phase="failed")
    assert watchdog.current() == pending
    assert [path.name for path in layout.iterdir()] == ["pending.json"]


def test_build_identity_tracks_relative_source_not_caches(tmp_path: Path) -> None:
    source, mirror = tmp_path / "source", tmp_path / "mirror"
    for package, order in ((source, ("a", "b")), (mirror, ("b", "a"))):
        package.mkdir()
        for name in order:
            (package / f"{name}.py").write_text(f"# {name}\n")
    cache = mirror / "__pycache__"
    cache.mkdir()
    (cache / "unrelated.py").write_text("excluded")
    assert watchdog._build_id(source) == watchdog._build_id(mirror)
    (mirror / "b.py").write_text("# patched\n")
    assert watchdog._build_id(source) != watchdog._build_id(mirror)


def test_bootstrap_dispatches_only_valid_expiry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[str] = []

    def expire(txid: str) -> int:
        seen.append(txid)
        return 75

    monkeypatch.setattr(ssh, "expire_watchdog", expire, raising=False)
    assert watchdog.main("other", TXID) == 64
    assert watchdog.main("expire", "../bad") == 64
    assert watchdog.main("probe", TXID) == 0
    assert json.loads(capsys.readouterr().out) == {
        "protocol": 1,
        "schema": 1,
        "build": watchdog._build_id(Path(watchdog.__file__).parents[1]),
    }
    assert seen == []
    assert watchdog.main("expire", TXID) == 75
    assert seen == [TXID]
