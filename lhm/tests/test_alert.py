import io
from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import alert


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    script = tmp_path / "usr" / "local" / "lib" / "lhm" / "lhm-alert.sh"
    unit_dir = tmp_path / "systemd"
    monkeypatch.setattr(alert, "SCRIPT", script)
    monkeypatch.setattr(alert, "UNIT_DIR", unit_dir)
    monkeypatch.setattr(alert, "TIMER_UNIT", unit_dir / "lhm-alert.timer")
    monkeypatch.setattr(alert, "SERVICE_UNIT", unit_dir / "lhm-alert.service")
    return {
        "script": script,
        "timer": unit_dir / "lhm-alert.timer",
        "service": unit_dir / "lhm-alert.service",
    }


@pytest.mark.parametrize(
    "url",
    ["http://hooks.example/x", "hooks.example", "ftp://x/y", "", " https://ok"],
)
def test_https_only_enforcement(url: str, fake_exec: Any, paths: dict[str, Path]) -> None:
    if url == " https://ok":
        assert alert.apply_alert(Runner(dry_run=True, exec_fn=fake_exec), webhook=url)
        return
    results = alert.apply_alert(Runner(exec_fn=fake_exec), webhook=url)
    assert results[0].status is Status.FAIL
    assert "https://" in results[0].detail
    assert fake_exec.calls == []
    assert not paths["script"].exists()


def test_apply_installs_script_and_units(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alert, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(("systemctl is-active lhm-alert.timer", 0, "active\n", ""))
    results = alert.apply_alert(
        Runner(exec_fn=fake_exec), webhook="https://hooks.example/services/abc"
    )
    names = {r.name: r.status for r in results}
    assert names["install " + str(paths["script"])] is Status.CHANGED
    assert names["write " + str(paths["timer"])] is Status.CHANGED
    assert names["write " + str(paths["service"])] is Status.CHANGED
    assert names["enable --now lhm-alert.timer"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert paths["script"].stat().st_mode & 0o777 == 0o700
    text = paths["script"].read_text(encoding="utf-8")
    assert "WEBHOOK_URL='https://hooks.example/services/abc'" in text
    assert 'SINCE=$(cat "$STATE_FILE" 2>/dev/null' in text  # shell vars survive rendering
    assert "22345" in text
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "systemctl daemon-reload" in executed
    assert "systemctl enable --now lhm-alert.timer" in executed


def test_rotated_script_backup_keeps_0700(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alert, "confirm_twice", lambda plan: True)
    paths["script"].parent.mkdir(parents=True)
    paths["script"].write_text("WEBHOOK_URL='https://old.example/x'\n", encoding="utf-8")
    paths["script"].chmod(0o644)  # e.g. an older, world-readable install
    alert.apply_alert(Runner(exec_fn=fake_exec), webhook="https://hooks.example/new")
    backup = paths["script"].with_name(paths["script"].name + ".bak")
    assert backup.is_file()
    assert backup.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.example/a'b",
        "https://hooks.example/a\nb",
    ],
)
def test_quote_or_control_chars_in_webhook_are_refused(
    url: str, fake_exec: Any, paths: dict[str, Path]
) -> None:
    results = alert.apply_alert(Runner(exec_fn=fake_exec), webhook=url)
    assert results[0].status is Status.FAIL
    assert fake_exec.calls == []
    assert not paths["script"].exists()


def test_verify_fails_when_timer_inactive(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alert, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(("systemctl is-active lhm-alert.timer", 3, "inactive\n", ""))
    results = alert.apply_alert(Runner(exec_fn=fake_exec), webhook="https://hooks.example/x")
    assert results[-1].status is Status.FAIL


def test_dry_run_writes_nothing(fake_exec: Any, paths: dict[str, Path]) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = alert.apply_alert(runner, webhook="https://hooks.example/x")
    assert fake_exec.calls == []
    assert all(r.status is Status.PLANNED for r in results)
    assert not paths["script"].exists()
    assert ["systemctl", "enable", "--now", "lhm-alert.timer"] in runner.planned


@pytest.mark.parametrize(
    "url",
    ["http://hooks.example/secret", "https://hooks.example/a'b", "https://hooks.example/a\nb"],
)
def test_error_messages_never_echo_path_or_token(url: str, fake_exec: Any) -> None:
    results = alert.apply_alert(Runner(exec_fn=fake_exec), webhook=url)
    assert results[0].status is Status.FAIL
    detail = results[0].detail
    assert "hooks.example" in detail
    assert "secret" not in detail
    assert "a'b" not in detail


def test_verbose_install_hides_the_webhook_script(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from lhm.core import colors

    monkeypatch.setattr(alert, "confirm_twice", lambda plan: True)
    colors.configure("always", verbose=True)
    stream = io.StringIO()
    colors.set_output(stream)
    try:
        alert.apply_alert(Runner(exec_fn=fake_exec), webhook="https://hooks.example/tok3n")
    finally:
        colors.set_output(None)
    out = stream.getvalue()
    assert "(content hidden" in out
    assert "tok3n" not in out


def test_verbose_script_backup_hides_the_old_webhook(
    fake_exec: Any, paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from lhm.core import colors

    monkeypatch.setattr(alert, "confirm_twice", lambda plan: True)
    paths["script"].parent.mkdir(parents=True)
    paths["script"].write_text("WEBHOOK_URL='https://old.example/oldtok'\n", encoding="utf-8")
    colors.configure("always", verbose=True)
    stream = io.StringIO()
    colors.set_output(stream)
    try:
        alert.apply_alert(Runner(exec_fn=fake_exec), webhook="https://hooks.example/newtok")
    finally:
        colors.set_output(None)
    out = stream.getvalue()
    assert "(content hidden" in out
    assert "oldtok" not in out
    assert "newtok" not in out
