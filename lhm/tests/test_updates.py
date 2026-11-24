from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import updates


@pytest.fixture
def conf_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "apt.conf.d" / "51-lhm"
    target.parent.mkdir(parents=True)
    monkeypatch.setattr(updates, "APT_CONF", target)
    return target


def test_dry_run_plans_without_commands(fake_exec: Any, conf_path: Path) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = updates.UpdatesModule().apply(runner, security_only=True)
    assert fake_exec.calls == []
    assert all(r.status is Status.PLANNED for r in results)
    assert not conf_path.exists()


def test_apply_writes_conf_and_verifies(
    fake_exec: Any, conf_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(updates, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query -W -f=${Status} unattended-upgrades", 1, "", "not installed"),
            ("systemctl is-active unattended-upgrades", 0, "active\n", ""),
            ("systemctl is-enabled unattended-upgrades", 0, "enabled\n", ""),
        ]
    )
    results = updates.UpdatesModule().apply(Runner(exec_fn=fake_exec), security_only=False)
    names = {r.name: r.status for r in results}
    assert names["apt update"] is Status.CHANGED
    assert names["apt upgrade"] is Status.CHANGED
    assert names["install unattended-upgrades"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert conf_path.read_text(encoding="utf-8") == updates.desired_conf()

    executed = [" ".join(call) for call in fake_exec.calls]
    assert any("apt-get update" in call for call in executed)
    assert any("apt-get upgrade" in call for call in executed)
    assert any("apt-get install" in call and "unattended-upgrades" in call for call in executed)


def test_security_only_uses_unattended_upgrade(
    fake_exec: Any, conf_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(updates, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active unattended-upgrades", 0, "active\n", ""),
            ("systemctl is-enabled unattended-upgrades", 0, "enabled\n", ""),
        ]
    )
    updates.UpdatesModule().apply(Runner(exec_fn=fake_exec), security_only=True)
    executed = [" ".join(call) for call in fake_exec.calls]
    assert any("unattended-upgrade" in call for call in executed)
    assert not any("apt-get upgrade" in call for call in executed)


def test_second_run_is_idempotent(
    fake_exec: Any, conf_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conf_path.write_text(updates.desired_conf(), encoding="utf-8")
    monkeypatch.setattr(updates, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active unattended-upgrades", 0, "active\n", ""),
            ("systemctl is-enabled unattended-upgrades", 0, "enabled\n", ""),
        ]
    )
    results = updates.UpdatesModule().apply(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["install unattended-upgrades"] is Status.SKIPPED
    assert names["write " + str(conf_path)] is Status.SKIPPED
    assert not (conf_path.parent / "51-lhm.bak").exists()


def test_refusal_makes_no_changes(
    fake_exec: Any, conf_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(updates, "confirm_once", lambda plan: False)
    fake_exec.responses.append(("dpkg-query", 1, "", ""))
    results = updates.UpdatesModule().apply(Runner(exec_fn=fake_exec))
    assert results[0].status is Status.ABORTED
    assert not conf_path.exists()
    mutating = [c for c in fake_exec.calls if "--version" not in c]
    assert not any("apt-get" in " ".join(c) for c in mutating)


def test_verify_fails_when_service_inactive(
    fake_exec: Any, conf_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(updates, "confirm_once", lambda plan: True)
    fake_exec.responses.extend(
        [
            ("dpkg-query", 0, "install ok installed", ""),
            ("systemctl is-active unattended-upgrades", 3, "inactive\n", ""),
            ("systemctl is-enabled unattended-upgrades", 1, "disabled\n", ""),
        ]
    )
    results = updates.UpdatesModule().apply(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.FAIL
    assert "not active or enabled" in results[-1].detail
