"""Manage the apt-daily upgrade entry point without trusting a checkout."""

import re
import stat
from pathlib import Path

from lhm.core.apt_runtime import LAUNCHER, runtime_identity, verify_runtime_tree
from lhm.core.distro import DistroError
from lhm.core.files import ensure_dir, locked_target, remove_file, write_dropin
from lhm.core.runner import CommandError, Runner

HELPER = Path("/usr/local/libexec/lhm-apt-security")
DROPIN = Path("/etc/systemd/system/apt-daily-upgrade.service.d/51-lhm.conf")
DOWNLOAD_DROPIN = Path("/etc/systemd/system/apt-daily.service.d/51-lhm.conf")
UNIT = "apt-daily-upgrade.service"
DOWNLOAD_UNIT = "apt-daily.service"
STOCK = "/usr/lib/apt/apt.systemd.daily"
DOWNLOAD = "/usr/bin/apt-get"
TIMER = "apt-daily-upgrade.timer"


def _trusted_path(path: Path, *, executable: bool = False, file: bool = False) -> None:
    for directory in reversed(path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise DistroError(f"untrusted systemd/helper parent: {directory}")
    info = path.lstat()
    expected = stat.S_ISREG if executable or file else stat.S_ISDIR
    if (
        not expected(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or (executable and not info.st_mode & 0o100)
        or ((executable or file) and info.st_nlink != 1)
    ):
        raise DistroError(f"untrusted systemd/helper path: {path}")


def _exec_start(runner: Runner, unit: str) -> tuple[str, str] | None:
    text = runner.capture(["systemctl", "show", "--property=ExecStart", "--value", unit])
    commands = re.findall(
        r"\{\s*path=([^;]+);\s*argv\[\]=([^;]+);\s*ignore_errors=no\s*;",
        text,
    )
    if len(commands) != 1 or len(re.findall(r"\{\s*path=", text)) != 1:
        return None
    executable, argv = commands[0]
    return executable.strip(), argv.strip()


def _verify_helper(runner: Runner) -> None:
    _trusted_path(HELPER, executable=True)
    with HELPER.open(encoding="ascii", newline="") as contents:
        script = contents.read(4096)
    prefix = re.escape(str(HELPER.parent / ".lhm-apt-security."))
    match = re.search(rf'^runtime="({prefix}[a-zA-Z0-9]{{8}})"$', script, re.MULTILINE)
    if not match or script != LAUNCHER.format(runtime=match[1]):
        raise DistroError("APT helper does not match the dedicated installer's launcher")
    runtime = Path(match[1])
    _trusted_path(runtime)
    verify_runtime_tree(runtime)
    _trusted_path(runtime / "entry.py", file=True)
    _trusted_path(runtime / "python/bin/python3.15", executable=True)
    expected = runtime_identity()
    if runtime_identity(runtime) != expected:
        raise DistroError("APT worker release fingerprint differs; reinstall the dedicated helper")
    observed = runner.capture([str(HELPER), "--probe"], timeout=30.0)
    if observed != f"{expected}\n":
        raise DistroError("APT worker release fingerprint differs; reinstall the dedicated helper")


def preflight_timer(runner: Runner) -> None:
    _verify_helper(runner)
    for action, expected in (("is-enabled", "enabled"), ("is-active", "active")):
        timer = runner.run(["systemctl", action, TIMER], check=False)
        if not timer.ok or timer.stdout.strip() != expected:
            raise DistroError(f"{TIMER} is not {expected}; left unchanged")
    triggers = runner.capture(
        [
            "systemctl",
            "show",
            "--property=Triggers",
            "--value",
            TIMER,
        ]
    )
    if triggers.strip() != UNIT:
        raise DistroError(f"{TIMER} does not trigger the isolated upgrade unit")


def verify_timer(runner: Runner) -> None:
    preflight_timer(runner)
    if _exec_start(runner, UNIT) != (str(HELPER), str(HELPER)):
        raise DistroError(f"{UNIT} does not execute the trusted isolated APT helper")
    if _exec_start(runner, DOWNLOAD_UNIT) != (DOWNLOAD, f"{DOWNLOAD} -q update"):
        raise DistroError(f"{DOWNLOAD_UNIT} may prefetch unisolated packages")


def configure_timer(runner: Runner) -> bool:
    """Replace only the verified distro ExecStart, never an unknown local command."""
    preflight_timer(runner)
    pending = []
    for unit, path, stock, executable, argv in (
        # The stock "update" script also invokes unattended-upgrade --download-only.
        (DOWNLOAD_UNIT, DOWNLOAD_DROPIN, "update", DOWNLOAD, f"{DOWNLOAD} -q update"),
        (UNIT, DROPIN, "install", str(HELPER), str(HELPER)),
    ):
        current = _exec_start(runner, unit)
        if current == (executable, argv):
            continue
        if current != (STOCK, f"{STOCK} {stock}") or path.exists() or path.is_symlink():
            raise DistroError(f"local {unit} ExecStart or managed drop-in conflict; left unchanged")
        _trusted_path(path.parent.parent)
        pending.append((path, argv))
    if not pending:
        verify_timer(runner)
        return False
    written = []
    try:
        for path, argv in pending:
            ensure_dir(path.parent)
            _trusted_path(path.parent)
            with locked_target(path):
                if path.exists():
                    raise DistroError(f"concurrent systemd drop-in conflict: {path}")
                write_dropin(path, f"[Service]\nExecStart=\nExecStart={argv}\n", mode=0o644)
                written.append(path)
        runner.run(["systemctl", "daemon-reload"])
        verify_timer(runner)
    except CommandError, DistroError, OSError:
        for path in written:
            remove_file(path)
        if written:
            runner.run(["systemctl", "daemon-reload"])
        raise
    return True
