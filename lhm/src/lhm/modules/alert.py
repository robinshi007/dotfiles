"""Alert module: systemd timer + script posting journal errors and bans to a webhook."""

import socket
from pathlib import Path

from lhm.core.checks import probe_service
from lhm.core.confirm import confirm_once
from lhm.core.files import (
    ensure_dir,
    render_shell_template,
    render_template,
    restrict,
    write_dropin,
)
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

SCRIPT_TEMPLATE = "lhm-alert.sh.tmpl"
TIMER_TEMPLATE = "lhm-alert.timer.tmpl"
SERVICE_TEMPLATE = "lhm-alert.service.tmpl"
SCRIPT = Path("/usr/local/lib/lhm/lhm-alert.sh")
UNIT_DIR = Path("/etc/systemd/system")
TIMER_UNIT = UNIT_DIR / "lhm-alert.timer"
SERVICE_UNIT = UNIT_DIR / "lhm-alert.service"
SSH_PORT = 22345
UNIT = "lhm-alert.timer"


class WebhookError(ValueError):
    """Raised when the webhook URL is not an https:// URL."""


def _host(url: str) -> str:
    """URL host with any ``user:password@`` prefix removed."""
    return url.split("://", 1)[-1].split("/", 1)[0].rpartition("@")[2]


def _redacted(url: str) -> str:
    """Scheme + host only: a webhook URL's path/query (and credentials) is the secret."""
    value = url.strip()
    prefix = "https://" if value.startswith("https://") else ""
    host = _host(value)
    if not host:
        return "(no host)"
    return f"{prefix}{host}/..." if prefix else f"{host}/..."


def validate_webhook(url: str) -> str:
    """Refuse anything but https:// (no plaintext webhook credentials)."""
    value = url.strip()
    if not value.startswith("https://"):
        raise WebhookError(
            f"refusing webhook {_redacted(url)}: only https:// URLs are accepted "
            "(plaintext credentials are not allowed)"
        )
    host = value.removeprefix("https://").split("/", 1)[0]
    if not host:
        raise WebhookError(f"refusing webhook {_redacted(url)}: missing host")
    if "'" in value:
        raise WebhookError(f"refusing webhook {_redacted(url)}: contains a single quote")
    if any(character <= " " or character == "\x7f" for character in value):
        raise WebhookError(
            f"refusing webhook {_redacted(url)}: contains whitespace/control characters"
        )
    return value


def desired_script(webhook_url: str) -> str:
    return render_shell_template(
        SCRIPT_TEMPLATE,
        webhook_url=webhook_url,
        ssh_port=str(SSH_PORT),
        hostname=socket.gethostname(),
    )


def desired_timer() -> str:
    return render_template(TIMER_TEMPLATE)


def desired_service() -> str:
    return render_template(SERVICE_TEMPLATE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def apply_alert(runner: Runner, *, webhook: str = "") -> list[StepResult]:
    try:
        url = validate_webhook(webhook)
    except WebhookError as exc:
        return [StepResult("alert", Status.FAIL, str(exc))]

    script = desired_script(url)
    timer = desired_timer()
    service = desired_service()
    script_needed = _read(SCRIPT) != script
    timer_needed = _read(TIMER_UNIT) != timer
    service_needed = _read(SERVICE_UNIT) != service

    plan = ["Plan (alert):"]
    plan.append(
        f"  - install {SCRIPT} (0700 root:root, webhook host {_host(url)})"
        if script_needed
        else f"  - {SCRIPT} already current (skip)"
    )
    plan.append(f"  - write {TIMER_UNIT}" if timer_needed else f"  - {TIMER_UNIT} current (skip)")
    plan.append(
        f"  - write {SERVICE_UNIT}" if service_needed else f"  - {SERVICE_UNIT} current (skip)"
    )
    plan.append("  - systemctl daemon-reload")
    plan.append(f"  - systemctl enable --now {UNIT} (daily 09:00, random delay 30m)")

    if runner.dry_run:
        for line in plan:
            print(line)
        runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "enable", "--now", UNIT])
        return [
            StepResult(
                f"install {SCRIPT}",
                Status.PLANNED if script_needed else Status.SKIPPED,
                "" if script_needed else "already current",
            ),
            StepResult(
                f"write {TIMER_UNIT}",
                Status.PLANNED if timer_needed else Status.SKIPPED,
                "" if timer_needed else "already current",
            ),
            StepResult(
                f"write {SERVICE_UNIT}",
                Status.PLANNED if service_needed else Status.SKIPPED,
                "" if service_needed else "already current",
            ),
            StepResult("daemon-reload", Status.PLANNED),
            StepResult(f"enable --now {UNIT}", Status.PLANNED),
        ]

    if not script_needed and not timer_needed and not service_needed:
        if runner.run(["systemctl", "is-active", UNIT], check=False).ok:
            return [
                StepResult(f"install {SCRIPT}", Status.SKIPPED, "already current"),
                StepResult(f"write {TIMER_UNIT}", Status.SKIPPED, "already current"),
                StepResult(f"write {SERVICE_UNIT}", Status.SKIPPED, "already current"),
                StepResult("daemon-reload", Status.SKIPPED, "no unit changed"),
                StepResult(f"enable --now {UNIT}", Status.SKIPPED, "already active"),
                _verify(runner),
            ]

    if not confirm_once(plan):
        return [StepResult("alert", Status.ABORTED, "aborted; no changes made")]

    results: list[StepResult] = []
    try:
        if script_needed:
            ensure_dir(SCRIPT.parent)
            # 0700 (and root:root): the script embeds the webhook URL, and its
            # .bak copy gets the same mode. ``secret`` keeps --verbose from
            # echoing the URL (content and diff are suppressed).
            write_dropin(SCRIPT, script, mode=0o700, secret=True)
            restrict(SCRIPT, 0o700)
            results.append(StepResult(f"install {SCRIPT}", Status.CHANGED, "0700 root:root"))
        else:
            results.append(StepResult(f"install {SCRIPT}", Status.SKIPPED, "already current"))
        if timer_needed:
            write_dropin(TIMER_UNIT, timer)
            results.append(StepResult(f"write {TIMER_UNIT}", Status.CHANGED))
        else:
            results.append(StepResult(f"write {TIMER_UNIT}", Status.SKIPPED, "already current"))
        if service_needed:
            write_dropin(SERVICE_UNIT, service)
            results.append(StepResult(f"write {SERVICE_UNIT}", Status.CHANGED))
        else:
            results.append(StepResult(f"write {SERVICE_UNIT}", Status.SKIPPED, "already current"))
        runner.run(["systemctl", "daemon-reload"])
        results.append(StepResult("daemon-reload", Status.CHANGED))
        runner.run(["systemctl", "enable", "--now", UNIT])
        results.append(StepResult(f"enable --now {UNIT}", Status.CHANGED))
    except (CommandError, OSError) as exc:
        results.append(StepResult("alert", Status.FAIL, str(exc)))
        print(f"lhm: rollback hint: lhm rollback {SCRIPT}", flush=True)
        return results

    results.append(_verify(runner))
    return results


def _verify(runner: Runner) -> StepResult:
    active = runner.run(["systemctl", "is-active", UNIT], check=False)
    if not active.ok:
        return StepResult("verify", Status.FAIL, f"{UNIT} is not active")
    return StepResult("verify", Status.OK, f"{UNIT} active")


def inspect(runner: Runner) -> dict[str, object]:
    """Read-only state used by ``check`` (no webhook secret is printed)."""
    state = probe_service(runner, UNIT)
    return {
        "script": str(SCRIPT),
        "script_present": SCRIPT.is_file(),
        "timer": str(TIMER_UNIT),
        "timer_present": TIMER_UNIT.is_file(),
        "service": str(SERVICE_UNIT),
        "service_present": SERVICE_UNIT.is_file(),
        "active": state.active,
    }


class AlertModule:
    name = "alert"
    description = "systemd timer + script alerting on errors and bans"
    implemented = True

    def apply(self, runner: Runner, *, webhook: str = "") -> list[StepResult]:
        return apply_alert(runner, webhook=webhook)
