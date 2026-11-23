from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import audit


@pytest.fixture
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "audit" / "rules.d" / "99-lhm.rules"
    monkeypatch.setattr(audit, "RULES_DROPIN", target)
    return target


def _active(fake_exec: Any) -> None:
    fake_exec.responses.append(("systemctl is-active auditd", 0, "active\n", ""))
    fake_exec.responses.append(("systemctl is-enabled auditd", 0, "enabled\n", ""))
    fake_exec.responses.append(("dpkg-query", 0, "install ok installed", ""))


def test_identical_file_with_immutable_rules_skips_load(
    fake_exec: Any, rules: Path
) -> None:
    rules.parent.mkdir(parents=True)
    rules.write_text(audit.desired_rules(), encoding="utf-8")
    _active(fake_exec)
    fake_exec.responses.append(("augenrules --check", 0, "", ""))
    results = audit.apply_audit(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["write " + str(rules)] is Status.SKIPPED
    assert names["augenrules --load"] is Status.SKIPPED
    assert "immutable" in next(r for r in results if r.name == "augenrules --load").detail
    assert names["verify"] is Status.OK
    executed = [" ".join(call) for call in fake_exec.calls]
    assert not any(call.startswith("augenrules --load") for call in executed)


def test_apply_loads_rules_and_verifies(
    fake_exec: Any, rules: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(("dpkg-query", 1, "", "not installed"))
    fake_exec.responses.append(("systemctl is-active auditd", 3, "inactive\n", ""))
    fake_exec.responses.append(("augenrules --load", 0, "", ""))
    fake_exec.responses.append(("augenrules --check", 0, "", ""))
    results = audit.apply_audit(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["install auditd"] is Status.CHANGED
    assert names["write " + str(rules)] is Status.CHANGED
    assert names["augenrules --load"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert rules.read_text(encoding="utf-8").rstrip().endswith("-e 2")


def test_load_failure_with_identical_file_is_a_warning(
    fake_exec: Any, rules: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules.parent.mkdir(parents=True)
    rules.write_text(audit.desired_rules(), encoding="utf-8")
    monkeypatch.setattr(audit, "confirm_twice", lambda plan: True)
    # auditd not active -> load is attempted even though the file is current.
    fake_exec.responses.append(("dpkg-query", 0, "install ok installed", ""))
    fake_exec.responses.append(("systemctl is-active auditd", 3, "inactive\n", ""))
    fake_exec.responses.append(
        ("augenrules --load", 1, "", "Error - auditing already enabled\n")
    )
    fake_exec.responses.append(("augenrules --check", 0, "", ""))
    fake_exec.responses.append(("auditctl -s", 0, "enabled 2\naudit_enabled 1\n", ""))
    results = audit.apply_audit(Runner(exec_fn=fake_exec))
    load = next(r for r in results if r.name == "augenrules --load")
    assert load.status is Status.OK
    assert "warning" in load.detail
    assert all(r.status is not Status.FAIL for r in results)


def test_load_failure_without_confirmed_immutability_fails(
    fake_exec: Any, rules: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identical file but auditctl -s does not confirm enabled=2 -> FAIL."""
    rules.parent.mkdir(parents=True)
    rules.write_text(audit.desired_rules(), encoding="utf-8")
    monkeypatch.setattr(audit, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(("dpkg-query", 0, "install ok installed", ""))
    fake_exec.responses.append(("systemctl is-active auditd", 3, "inactive\n", ""))
    fake_exec.responses.append(("augenrules --load", 1, "", "Error - auditing already enabled\n"))
    fake_exec.responses.append(("auditctl -s", 0, "enabled 1\n", ""))
    results = audit.apply_audit(Runner(exec_fn=fake_exec))
    load = next(r for r in results if r.name == "augenrules --load")
    assert load.status is Status.FAIL
    assert "not confirmed" in load.detail


def test_load_failure_after_new_file_fails(
    fake_exec: Any, rules: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "confirm_twice", lambda plan: True)
    fake_exec.responses.append(("dpkg-query", 0, "install ok installed", ""))
    fake_exec.responses.append(("systemctl is-active auditd", 3, "inactive\n", ""))
    fake_exec.responses.append(("augenrules --load", 1, "", "syntax error\n"))
    results = audit.apply_audit(Runner(exec_fn=fake_exec))
    assert results[-1].status is Status.FAIL


def test_dry_run_needs_no_writes(fake_exec: Any, rules: Path) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = audit.apply_audit(runner)
    assert all(result.status is not Status.FAIL for result in results)
    assert fake_exec.calls == []
    assert not rules.exists()
    assert any(["augenrules", "--load"] == call for call in runner.planned)
