from pathlib import Path
from typing import Any

import pytest

from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import sysctl

VALUES_OK = {
    "kernel.kptr_restrict": "2\n",
    "kernel.dmesg_restrict": "1\n",
    "net.ipv4.conf.all.rp_filter": "1\n",
}


@pytest.fixture
def dropin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "etc" / "sysctl.d" / "99-lhm.conf"
    monkeypatch.setattr(sysctl, "SYSCTL_DROPIN", target)
    return target


def _spot_responses(fake_exec: Any, overrides: dict[str, str] | None = None) -> None:
    values = {**VALUES_OK, **(overrides or {})}
    for key, value in values.items():
        fake_exec.responses.append((f"sysctl -n {key}", 0, value, ""))


def test_dry_run_records_commands_and_writes_nothing(
    fake_exec: Any, dropin: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    results = sysctl.apply_sysctl(runner)
    assert fake_exec.calls == []
    assert not dropin.exists()
    assert [r.status for r in results] == [Status.PLANNED, Status.PLANNED, Status.PLANNED]
    assert ["sysctl", "--system"] in runner.planned
    assert "kernel.kptr_restrict=2" in capsys.readouterr().out


def test_apply_writes_tolerates_missing_userns_key_and_verifies(
    fake_exec: Any, dropin: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sysctl, "confirm_once", lambda plan: True)
    fake_exec.responses.append(
        (
            "sysctl --system",
            1,
            "",
            "sysctl: cannot stat /proc/sys/kernel/unprivileged_userns_clone: "
            "No such file or directory\n",
        )
    )
    _spot_responses(fake_exec)
    results = sysctl.apply_sysctl(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["write " + str(dropin)] is Status.CHANGED
    assert names["sysctl --system"] is Status.CHANGED
    assert names["verify"] is Status.OK
    assert "tolerated" in next(r for r in results if r.name == "sysctl --system").detail
    assert dropin.read_text(encoding="utf-8") == sysctl.desired_conf()


def test_identical_file_refreshes_then_verifies(
    fake_exec: Any, dropin: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dropin.parent.mkdir(parents=True)
    dropin.write_text(sysctl.desired_conf(), encoding="utf-8")
    monkeypatch.setattr(sysctl, "confirm_once", lambda plan: True)
    # Existing values drift from the wanted ones.
    _spot_responses(fake_exec, {"kernel.kptr_restrict": "0\n"})
    fake_exec.responses.append(("sysctl --system", 0, "", ""))
    results = sysctl.apply_sysctl(Runner(exec_fn=fake_exec))
    names = {r.name: r.status for r in results}
    assert names["write " + str(dropin)] is Status.SKIPPED
    assert names["sysctl --system"] is Status.CHANGED
    executed = [" ".join(call) for call in fake_exec.calls]
    assert "sysctl --system" in executed


def test_verify_fails_on_wrong_spot_check_value(
    fake_exec: Any, dropin: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sysctl, "confirm_once", lambda plan: True)
    fake_exec.responses.append(("sysctl --system", 0, "", ""))
    _spot_responses(fake_exec, {"net.ipv4.conf.all.rp_filter": "0\n"})
    results = sysctl.apply_sysctl(Runner(exec_fn=fake_exec))
    verify = next(r for r in results if r.name == "verify")
    assert verify.status is Status.FAIL
    assert "net.ipv4.conf.all.rp_filter=0" in verify.detail


def test_unknown_key_warning_does_not_fail_load(
    fake_exec: Any, dropin: Path
) -> None:
    assert sysctl._tolerated(
        "sysctl: cannot stat /proc/sys/kernel/unprivileged_userns_clone: No such file\n"
    )
    assert not sysctl._tolerated("sysctl: permission denied on /proc/sys/kernel/kptr_restrict\n")
