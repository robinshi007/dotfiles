import subprocess
from pathlib import Path

import pytest

from lhm.core import apt_timer
from lhm.core.distro import DistroError
from lhm.core.runner import Runner


@pytest.mark.parametrize(
    "override",
    [
        "none",
        "before",
        "after",
        "inactive",
        "wrong-trigger",
        "fingerprint",
    ],
)
def test_apt_daily_preserves_unknown_execstart_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    helper = tmp_path / "helper"
    primary = tmp_path / "apt-daily-upgrade.service.d/51-lhm.conf"
    download = tmp_path / "apt-daily.service.d/51-lhm.conf"
    monkeypatch.setattr(apt_timer, "HELPER", helper)
    monkeypatch.setattr(apt_timer, "DROPIN", primary)
    monkeypatch.setattr(apt_timer, "DOWNLOAD_DROPIN", download)
    monkeypatch.setattr(apt_timer, "_trusted_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(apt_timer, "verify_runtime_tree", lambda path: None)
    monkeypatch.setattr(
        apt_timer, "runtime_identity", lambda root=None: "lhm-apt-security-v1 fixture"
    )
    runtime = tmp_path / ".lhm-apt-security.ABCDEF12"
    helper.write_text(apt_timer.LAUNCHER.format(runtime=runtime), encoding="ascii")
    reloads = []

    def exec_fn(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        out = ""
        if cmd == [str(helper), "--probe"]:
            out = "different\n" if override == "fingerprint" else "lhm-apt-security-v1 fixture\n"
        elif cmd[1:3] == ["show", "--property=Triggers"]:
            out = "other.service\n" if override == "wrong-trigger" else f"{apt_timer.UNIT}\n"
        elif cmd[1] == "show":
            unit = cmd[-1]
            path = primary if unit == apt_timer.UNIT else download
            if unit == apt_timer.UNIT and (
                override == "before" or (override == "after" and path.exists())
            ):
                executable, argv = "/local/custom", "/local/custom"
            elif path.exists():
                argv = path.read_text(encoding="utf-8").splitlines()[-1].removeprefix("ExecStart=")
                executable = argv.split()[0]
            else:
                executable = apt_timer.STOCK
                mode = "install" if unit == apt_timer.UNIT else "update"
                argv = f"{executable} {mode}"
            out = f"{{ path={executable} ; argv[]={argv} ; ignore_errors=no ; start_time=[n/a] }}"
        elif cmd[1] == "daemon-reload":
            reloads.append(cmd)
        elif cmd[1] == "is-enabled":
            assert cmd == ["systemctl", "is-enabled", "apt-daily-upgrade.timer"]
            out = "enabled\n"
        else:
            assert cmd == ["systemctl", "is-active", "apt-daily-upgrade.timer"]
            if override == "inactive":
                return subprocess.CompletedProcess(cmd, 3, "inactive\n", "")
            out = "active\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    runner = Runner(exec_fn=exec_fn)
    if override == "none":
        assert apt_timer.configure_timer(runner) is True
        assert primary.read_text().endswith(f"ExecStart={helper}\n")
        assert download.read_text().endswith("ExecStart=/usr/bin/apt-get -q update\n")
        assert apt_timer.configure_timer(runner) is False
        assert len(reloads) == 1
    else:
        with pytest.raises(
            DistroError, match="local|trusted isolated|not active|not trigger|fingerprint"
        ):
            apt_timer.configure_timer(runner)
        assert not primary.exists() and not download.exists()
        assert len(reloads) == (2 if override == "after" else 0)


def test_no_op_root_helper_conflict_stops_before_executing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = tmp_path / "lhm-apt-security"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    monkeypatch.setattr(apt_timer, "HELPER", helper)
    monkeypatch.setattr(apt_timer, "_trusted_path", lambda *args, **kwargs: None)

    def unexpected(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        pytest.fail(f"unverified helper or systemd command was executed: {cmd}")

    with pytest.raises(DistroError, match="dedicated installer's launcher"):
        apt_timer.configure_timer(Runner(exec_fn=unexpected))


def test_timer_refuses_symlinked_or_writable_helper(tmp_path: Path) -> None:
    checkout = tmp_path / "helper"
    checkout.write_text("not a trusted executable\n")
    checkout.chmod(0o777)
    link = tmp_path / "link"
    link.symlink_to(checkout)
    for path in (checkout, link):
        with pytest.raises(DistroError, match="untrusted"):
            apt_timer._trusted_path(path, executable=True)
