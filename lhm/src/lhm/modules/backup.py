"""Backup module: systemd timer + tar script with sha256 manifest and rotation."""

import re
from pathlib import Path

from lhm.core.checks import probe_service
from lhm.core.confirm import confirm_once
from lhm.core.files import (
    ensure_dir,
    render_shell_template,
    render_template,
    set_mode,
    write_dropin,
)
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

SCRIPT_TEMPLATE = "lhm-backup.sh.tmpl"
SERVICE_TEMPLATE = "lhm-backup.service.tmpl"
TIMER_TEMPLATE = "lhm-backup.timer.tmpl"
SCRIPT = Path("/usr/local/lib/lhm/lhm-backup.sh")
UNIT_DIR = Path("/etc/systemd/system")
SERVICE_UNIT = UNIT_DIR / "lhm-backup.service"
TIMER_UNIT = UNIT_DIR / "lhm-backup.timer"
UNIT = "lhm-backup.timer"
DEFAULT_KEEP = 7
TEST_RUN_TIMEOUT = 3600.0
ARCHIVE_GLOB = "lhm-backup-*.tar.gz"


class TargetError(ValueError):
    """Raised when the backup target is not an acceptable absolute directory."""


SAFE_TARGET = re.compile(r"[A-Za-z0-9/_.-]+")


def validate_target(value: str) -> Path:
    target = Path(value)
    if not target.is_absolute():
        raise TargetError(f"refusing backup target {value!r}: must be an absolute path")
    if ".." in target.parts:
        raise TargetError(f"refusing backup target {value!r}: contains '..'")
    if "'" in str(target):
        raise TargetError(f"refusing backup target {value!r}: contains a single quote")
    if any(character < " " or character == "\x7f" for character in str(target)):
        raise TargetError(f"refusing backup target {value!r}: contains control characters")
    if not SAFE_TARGET.fullmatch(str(target)):
        # A space splits systemd's ReadWritePaths=, % is a specifier expansion.
        raise TargetError(
            f"refusing backup target {value!r}: only [A-Za-z0-9/_.-] are allowed "
            "(no spaces or '%')"
        )
    # Resolve '//etc' and symlinked parents before the guards: Path('//') != Path('/').
    resolved = target.resolve(strict=False)
    if resolved == Path("/"):
        raise TargetError("refusing backup target '/': use a dedicated directory")
    for guarded in (Path("/home"), Path("/etc")):
        if resolved == guarded or guarded in resolved.parents:
            raise TargetError(
                f"refusing backup target {value!r}: it is inside {guarded} "
                "(tar would archive the growing archive itself)"
            )
    return target


def desired_script(target: Path, keep: int = DEFAULT_KEEP) -> str:
    return render_shell_template(SCRIPT_TEMPLATE, target_dir=str(target), keep=str(keep))


def desired_service(target: Path) -> str:
    return render_template(SERVICE_TEMPLATE, target_dir=str(target))


def desired_timer() -> str:
    return render_template(TIMER_TEMPLATE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def newest_archive(target: Path) -> Path | None:
    """Newest ``lhm-backup-*.tar.gz`` in ``target``, or None."""
    try:
        archives = [path for path in target.glob(ARCHIVE_GLOB) if path.is_file()]
    except OSError:
        return None
    if not archives:
        return None
    return max(archives, key=lambda path: path.stat().st_mtime)

def verify_archive(target: Path) -> StepResult:
    """FAIL-gating: the test run must leave an archive plus its sha256 manifest."""
    archive = newest_archive(target)
    if archive is None:
        return StepResult("verify", Status.FAIL, f"no {ARCHIVE_GLOB} in {target}")
    manifest = archive.with_name(archive.name + ".sha256")
    if not manifest.is_file():
        return StepResult("verify", Status.FAIL, f"manifest missing: {manifest.name}")
    if archive.stat().st_size == 0:
        return StepResult("verify", Status.FAIL, f"archive is empty: {archive.name}")
    return StepResult("verify", Status.OK, f"{archive.name} + {manifest.name} present")


def apply_backup(
    runner: Runner, *, target: str = "", keep: int = DEFAULT_KEEP
) -> list[StepResult]:
    try:
        target_dir = validate_target(target)
    except TargetError as exc:
        return [StepResult("backup", Status.FAIL, str(exc))]
    if keep < 1:
        return [StepResult("backup", Status.FAIL, f"invalid --keep {keep}: must be >= 1")]

    script = desired_script(target_dir, keep)
    service = desired_service(target_dir)
    timer = desired_timer()
    script_needed = _read(SCRIPT) != script
    service_needed = _read(SERVICE_UNIT) != service
    timer_needed = _read(TIMER_UNIT) != timer

    plan = ["Plan (backup):"]
    plan.append(f"  - mkdir -p {target_dir} (0700)")
    plan.append(
        f"  - install {SCRIPT} (0755, keep {keep} archives)"
        if script_needed
        else f"  - {SCRIPT} already current (skip)"
    )
    plan.append(
        f"  - write {SERVICE_UNIT}" if service_needed else f"  - {SERVICE_UNIT} current (skip)"
    )
    plan.append(f"  - write {TIMER_UNIT}" if timer_needed else f"  - {TIMER_UNIT} current (skip)")
    plan.append("  - systemctl daemon-reload")
    plan.append(f"  - systemctl enable --now {UNIT} (daily 02:00, random delay 15m)")
    plan.append(f"  - test run: {SCRIPT} once, then check {target_dir}/{ARCHIVE_GLOB} + .sha256")
    plan.append("  - risk: the first archive holds /etc and /home; ensure the target has space")

    if runner.dry_run:
        for line in plan:
            print(line)
        runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "enable", "--now", UNIT])
        return [
            StepResult(f"mkdir {target_dir}", Status.PLANNED),
            StepResult(
                f"install {SCRIPT}",
                Status.PLANNED if script_needed else Status.SKIPPED,
                "" if script_needed else "already current",
            ),
            StepResult(
                f"write {SERVICE_UNIT}",
                Status.PLANNED if service_needed else Status.SKIPPED,
                "" if service_needed else "already current",
            ),
            StepResult(
                f"write {TIMER_UNIT}",
                Status.PLANNED if timer_needed else Status.SKIPPED,
                "" if timer_needed else "already current",
            ),
            StepResult("daemon-reload", Status.PLANNED),
            StepResult(f"enable --now {UNIT}", Status.PLANNED),
            StepResult("verify", Status.PLANNED, "test run + archive/manifest check"),
        ]

    if not script_needed and not service_needed and not timer_needed:
        if runner.run(["systemctl", "is-active", UNIT], check=False).ok:
            verify = verify_archive(target_dir)
            return [
                StepResult(f"mkdir {target_dir}", Status.SKIPPED, "exists"),
                StepResult(f"install {SCRIPT}", Status.SKIPPED, "already current"),
                StepResult(f"write {SERVICE_UNIT}", Status.SKIPPED, "already current"),
                StepResult(f"write {TIMER_UNIT}", Status.SKIPPED, "already current"),
                StepResult("daemon-reload", Status.SKIPPED, "no unit changed"),
                StepResult(f"enable --now {UNIT}", Status.SKIPPED, "already active"),
                verify,
            ]

    if not confirm_once(plan):
        return [StepResult("backup", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        ensure_dir(target_dir, mode=0o700)
        # 0700: archives hold /etc (shadow, keys), keep them root-only.
        set_mode(target_dir, 0o700)
        results.append(StepResult(f"mkdir {target_dir}", Status.OK, "0700"))
        if script_needed:
            ensure_dir(SCRIPT.parent)
            write_dropin(SCRIPT, script)
            set_mode(SCRIPT, 0o755)
            results.append(StepResult(f"install {SCRIPT}", Status.CHANGED, "0755"))
        else:
            results.append(StepResult(f"install {SCRIPT}", Status.SKIPPED, "already current"))
        if service_needed:
            write_dropin(SERVICE_UNIT, service)
            results.append(StepResult(f"write {SERVICE_UNIT}", Status.CHANGED))
        else:
            results.append(StepResult(f"write {SERVICE_UNIT}", Status.SKIPPED, "already current"))
        if timer_needed:
            write_dropin(TIMER_UNIT, timer)
            results.append(StepResult(f"write {TIMER_UNIT}", Status.CHANGED))
        else:
            results.append(StepResult(f"write {TIMER_UNIT}", Status.SKIPPED, "already current"))
        runner.run(["systemctl", "daemon-reload"])
        results.append(StepResult("daemon-reload", Status.CHANGED))
        runner.run(["systemctl", "enable", "--now", UNIT])
        results.append(StepResult(f"enable --now {UNIT}", Status.CHANGED))
        active = runner.run(["systemctl", "is-active", UNIT], check=False)
        if not active.ok:
            results.append(StepResult(f"verify {UNIT}", Status.FAIL, f"{UNIT} is not active"))
            return results
        results.append(StepResult(f"verify {UNIT}", Status.OK, f"{UNIT} active"))
        # Test run through the runner instead of `systemctl start`: the unit is
        # Type=oneshot, so this avoids polling a transient unit with a sleep and
        # gives a deterministic archive check.
        runner.run([str(SCRIPT)], timeout=TEST_RUN_TIMEOUT)
        results.append(StepResult("test run", Status.OK, f"executed {SCRIPT}"))
    except (CommandError, OSError) as exc:
        results.append(StepResult("backup", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {SCRIPT}", flush=True)
        return results

    results.append(verify_archive(target_dir))
    return results


def inspect(runner: Runner, *, target: str = "") -> dict[str, object]:
    """Read-only state used by ``check``."""
    state = probe_service(runner, UNIT)
    payload: dict[str, object] = {
        "script": str(SCRIPT),
        "script_present": SCRIPT.is_file(),
        "service": str(SERVICE_UNIT),
        "service_present": SERVICE_UNIT.is_file(),
        "timer": str(TIMER_UNIT),
        "timer_present": TIMER_UNIT.is_file(),
        "active": state.active,
    }
    if target:
        try:
            target_dir: Path | None = validate_target(target)
        except TargetError:
            target_dir = None
        archive = newest_archive(target_dir) if target_dir is not None else None
        payload["target"] = target
        payload["latest_archive"] = archive.name if archive is not None else ""
    return payload


class BackupModule:
    name = "backup"
    description = "systemd timer + tar backup with sha256 manifest and rotation"
    implemented = True

    def apply(
        self, runner: Runner, *, target: str = "", keep: int = DEFAULT_KEEP
    ) -> list[StepResult]:
        return apply_backup(runner, target=target, keep=keep)
