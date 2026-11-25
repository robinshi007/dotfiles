import errno
import io
import os
import re
import stat
from pathlib import Path

import pytest

from lhm.core import colors
from lhm.core.backup import backup_file, rollback_file
from lhm.core.files import (
    append_marked,
    ensure_dir,
    locked_target,
    remove_file,
    render_shell_template,
    render_template,
    restrict,
    set_mode,
    write_dropin,
)
from lhm.core.mutations import mutation_mode


@pytest.mark.parametrize("require_backup", [False, True])
def test_dropin_identical_content_is_skipped(tmp_path: Path, require_backup: bool) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("Port 22345\n", encoding="utf-8")
    assert write_dropin(target, "Port 22345\n", require_backup=require_backup) == "skipped"
    assert not (tmp_path / "99-lhm.conf.bak").exists()


def test_dropin_changed_content_backs_up_and_writes(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)
    assert write_dropin(target, "new\n") == "written"
    assert target.read_text(encoding="utf-8") == "new\n"
    assert (tmp_path / "99-lhm.conf.bak").read_text(encoding="utf-8") == "old\n"
    assert target.stat().st_mode & 0o777 == 0o600


def test_dropin_required_backup_is_reported_before_replacement(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("old\n", encoding="utf-8")
    backups: list[Path] = []

    def record_backup(backup: Path) -> None:
        assert target.read_text(encoding="utf-8") == "old\n"
        assert backup.read_text(encoding="utf-8") == "old\n"
        backups.append(backup)

    assert write_dropin(target, "new\n", require_backup=True, on_backup=record_backup) == "written"
    assert backups == [tmp_path / "99-lhm.conf.bak"]
    assert target.read_text(encoding="utf-8") == "new\n"


def test_dropin_new_file_gets_default_mode(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "99-lhm.conf"
    assert write_dropin(target, "x\n") == "written"
    assert target.stat().st_mode & 0o777 == 0o644
    assert not list(target.parent.glob("*.bak*"))


def test_dropin_rejects_relative_path() -> None:
    with pytest.raises(ValueError):
        write_dropin("relative.conf", "x")


@pytest.mark.parametrize("append", [False, True])
def test_managed_write_rejects_file_symlink_with_eloop(tmp_path: Path, append: bool) -> None:
    missing = tmp_path / "missing"
    target = tmp_path / "config"
    target.symlink_to(missing)
    with pytest.raises(OSError, match="symlink") as caught:
        if append:
            append_marked(target, "x", "new")
        else:
            write_dropin(target, "new")
    assert caught.value.errno == errno.ELOOP
    assert target.is_symlink()
    assert not missing.exists()
    assert not list(tmp_path.glob("*.bak*"))


@pytest.mark.parametrize("append", [False, True])
@pytest.mark.parametrize("output_errno", [errno.EPIPE, errno.ENOSPC])
def test_managed_write_returns_success_when_reporting_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, append: bool, output_errno: int
) -> None:
    target = tmp_path / "config"
    target.write_text("old\n", encoding="utf-8")
    backups: list[Path] = []

    def fail_notification(kind: str, path: Path, **kwargs: object) -> None:
        assert kind == "modified"
        assert path == target
        assert "new" in target.read_text(encoding="utf-8")
        raise OSError(output_errno, "stdout write failed")

    monkeypatch.setattr(colors, "file_change", fail_notification)
    if append:
        assert append_marked(target, "x", "new") == "appended"
        backup = tmp_path / "config.bak"
    else:
        assert write_dropin(target, "new", on_backup=backups.append) == "written"
        (backup,) = backups
    assert rollback_file(target, backup=backup) == backup
    assert target.read_text(encoding="utf-8") == "old\n"


def test_locked_target_refuses_contention_and_reuses_private_inode(tmp_path: Path) -> None:
    target = tmp_path / "config"
    lock = tmp_path / ".config.lhm.lock"
    with locked_target(target):
        first = lock.stat()
        assert stat.S_IMODE(first.st_mode) == 0o600
        assert first.st_nlink == 1
        with pytest.raises(BlockingIOError, match="managed target is locked"):
            with locked_target(target):
                pytest.fail("contender acquired the lock")
        with locked_target(tmp_path / "other"):
            pass
    with locked_target(target):
        assert os.path.samestat(first, lock.stat())


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo"])
def test_locked_target_refuses_unsafe_lockfile(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "config"
    target.write_bytes(b"do not touch")
    target.chmod(0o600)
    lock = tmp_path / ".config.lhm.lock"
    if kind == "symlink":
        lock.symlink_to(target)
    elif kind == "hardlink":
        lock.hardlink_to(target)
    elif kind == "public":
        lock.touch()
        lock.chmod(0o644)
    else:
        os.mkfifo(lock)

    with pytest.raises(OSError, match="lock file") as caught:
        with locked_target(target):
            pytest.fail("unsafe lock accepted")
    if kind == "symlink":
        assert caught.value.errno == errno.ELOOP
    assert target.read_bytes() == b"do not touch"


def test_locked_target_refuses_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "config-dir"
    parent.mkdir()
    parent.chmod(0o777)
    try:
        with pytest.raises(PermissionError, match="unsafe managed directory"):
            with locked_target(parent / "config"):
                pytest.fail("unsafe parent accepted")
    finally:
        parent.chmod(0o700)
    assert not list(parent.iterdir())


def test_locked_target_dry_run_creates_nothing(tmp_path: Path) -> None:
    with mutation_mode(dry_run=True), locked_target(tmp_path / "missing" / "config"):
        pass
    assert not list(tmp_path.iterdir())


def test_append_marked_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "jail.local"
    target.write_text("[DEFAULT]\nbantime = 1h", encoding="utf-8")
    assert append_marked(target, "fail2ban", "enabled = true") == "appended"
    first = target.read_text(encoding="utf-8")
    assert re.search(r"^# ===== lhm \S+ fail2ban begin =====$", first, re.M)
    assert "# ===== lhm fail2ban end =====" in first
    assert first.startswith("[DEFAULT]\nbantime = 1h\n")
    # Existing file is backed up before the append.
    backup = tmp_path / "jail.local.bak"
    assert backup.read_text(encoding="utf-8") == "[DEFAULT]\nbantime = 1h"
    # Second call is a no-op: no write, no new backup.
    assert append_marked(target, "fail2ban", "enabled = true") == "skipped"
    assert target.read_text(encoding="utf-8") == first
    assert not (tmp_path / "jail.local.bak.1").exists()


def test_append_marked_updates_only_managed_body(tmp_path: Path) -> None:
    target = tmp_path / "config"
    old = (
        b"outside\r\n# ===== lhm 2026-11-23T00:00:00Z one begin =====\r\n"
        b"before\r\n# ===== lhm one end =====\r\noutside without newline"
    )
    target.write_bytes(old)
    assert append_marked(target, "one", "after") == "appended"
    assert target.read_bytes() == old.replace(b"before", b"after")
    assert target.with_suffix(".bak").read_bytes() == old
    assert append_marked(target, "one", "after") == "skipped"


@pytest.mark.parametrize(
    "lines",
    [
        "# ===== lhm stamp x begin =====\n",
        "# ===== lhm x end =====\n",
        "# ===== lhm stamp x begin =====\n# ===== lhm z end =====\n",
        "# ===== lhm stamp x begin =====\n# ===== lhm stamp z begin =====\n",
        ("# ===== lhm stamp x begin =====\n# ===== lhm x end =====\n") * 2,
    ],
)
def test_append_marked_refuses_malformed_blocks(tmp_path: Path, lines: str) -> None:
    target = tmp_path / "config"
    target.write_text(lines, encoding="utf-8")
    with pytest.raises(ValueError, match="marker"):
        append_marked(target, "x", "body")
    assert target.read_text(encoding="utf-8") == lines
    assert list(tmp_path.iterdir()) == [target]


def test_nested_dry_run_blocks_all_managed_writes(tmp_path: Path) -> None:
    target = tmp_path / "config"
    target.write_text("old", encoding="utf-8")
    target.chmod(0o600)
    with mutation_mode(dry_run=True), mutation_mode(dry_run=False):
        assert write_dropin(target, "new") == "planned"
        assert write_dropin(tmp_path / "missing", "new", require_backup=True) == "planned"
        assert append_marked(target, "x", "body") == "planned"
        restrict(target, 0o700)
        ensure_dir(tmp_path / "newdir")
        set_mode(target, 0o744)
        assert not remove_file(target)
        with pytest.raises(RuntimeError, match="dry-run"):
            backup_file(target)
        with pytest.raises(RuntimeError, match="dry-run"):
            rollback_file(target)
    assert target.read_text(encoding="utf-8") == "old"
    assert target.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [target]
    assert write_dropin(target, "new") == "written"


def test_append_marked_second_marker_appends(tmp_path: Path) -> None:
    target = tmp_path / "multi.conf"
    append_marked(target, "one", "a = 1")
    text = target.read_text(encoding="utf-8")
    append_marked(target, "two", "b = 2")
    updated = target.read_text(encoding="utf-8")
    assert updated.startswith(text)
    assert "lhm" in updated and re.search(r"lhm \S+ two begin", updated)


def test_append_marked_creates_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "new.conf"
    assert append_marked(target, "x", "body") == "appended"
    assert not (tmp_path / "new.conf.bak").exists()


def test_render_template() -> None:
    rendered = render_template("unattended-upgrades.conf.tmpl")
    assert "#clear Unattended-Upgrade::Allowed-Origins;" in rendered
    assert "#clear Unattended-Upgrade::Origins-Pattern;" in rendered
    assert "APT::Periodic::Unattended-Upgrade \"1\";" in rendered


def test_ssh_template_includes_hardening_defaults() -> None:
    settings = render_template(
        "ssh-hardening.conf.tmpl", port="22345", allow_users="admin"
    ).splitlines()
    assert not any(line.startswith("ChallengeResponseAuthentication ") for line in settings)
    for line in (
        "Protocol 2",
        "MaxAuthTries 3",
        "PermitEmptyPasswords no",
        "KbdInteractiveAuthentication no",
        "X11Forwarding no",
        "LoginGraceTime 30",
        "MaxStartups 3:50:10",
    ):
        assert settings.count(line) == 1


@pytest.mark.parametrize("character", ["'", '"', "\n", "\x1b", "\u2028"])
def test_config_template_rejects_unsafe_value_without_echoing_it(character: str) -> None:
    with pytest.raises(ValueError, match="hostname") as failure:
        render_template("99-lhm.local.tmpl", hostname=f"sensitive{character}value")
    assert "sensitive" not in str(failure.value)


def test_render_shell_template_leaves_shell_vars_alone() -> None:
    rendered = render_shell_template("lhm-backup.sh.tmpl", target_dir="/srv/b", keep="7")
    assert "TARGET_DIR='/srv/b'" in rendered
    assert "KEEP=7" in rendered
    # Shell-only constructs survive: $VAR, $(...), $((...)), ${VAR}
    assert 'OUT="$TARGET_DIR/lhm-backup-$STAMP.tar.gz"' in rendered
    assert 'STAMP=$(date -u' in rendered
    assert "tail -n +$((KEEP + 1))" in rendered


def test_render_shell_template_requires_all_variables() -> None:
    with pytest.raises(KeyError):
        render_shell_template("lhm-backup.sh.tmpl", target_dir="/srv/b")


@pytest.mark.parametrize("value", ["/srv/a'b", "/srv/a\nb", "/srv/a\tb"])
def test_render_shell_template_refuses_quote_or_control_chars(value: str) -> None:
    """Values are single-quoted in the templates: refuse instead of escaping."""
    with pytest.raises(ValueError):
        render_shell_template("lhm-backup.sh.tmpl", target_dir=value, keep="7")


def test_dropin_backup_of_0700_file_keeps_mode(tmp_path: Path) -> None:
    target = tmp_path / "secret.sh"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o700)
    write_dropin(target, "new\n", mode=0o700)
    backup = tmp_path / "secret.sh.bak"
    assert target.stat().st_mode & 0o777 == 0o700
    assert backup.stat().st_mode & 0o777 == 0o700


def test_dropin_forced_mode_applies_to_new_file(tmp_path: Path) -> None:
    target = tmp_path / "new" / "secret.sh"
    write_dropin(target, "x\n", mode=0o700)
    assert target.stat().st_mode & 0o777 == 0o700


def _capture(*, verbose: bool = False) -> io.StringIO:
    stream = io.StringIO()
    colors.configure("always", verbose=verbose)
    colors.set_output(stream)
    return stream


def test_write_dropin_requires_a_fresh_backup(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    stale = target.with_suffix(".conf.bak")
    stale.write_text("stale\n", encoding="utf-8")
    backups: list[Path] = []
    stream = _capture()
    try:
        with pytest.raises(FileNotFoundError):
            write_dropin(target, "new\n", require_backup=True, on_backup=backups.append)
    finally:
        colors.set_output(None)
    assert list(tmp_path.iterdir()) == [stale]
    assert stale.read_text(encoding="utf-8") == "stale\n"
    assert not backups
    assert stream.getvalue() == ""


def test_write_dropin_prints_created_symbol(tmp_path: Path) -> None:
    stream = _capture()
    target = tmp_path / "99-lhm.conf"
    try:
        write_dropin(target, "Port 22345\n")
    finally:
        colors.set_output(None)
    assert stream.getvalue() == f"\033[32m+ {target}\033[0m\n"


def test_write_dropin_prints_modified_symbol(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("old\n", encoding="utf-8")
    stream = _capture()
    try:
        write_dropin(target, "new\n")
    finally:
        colors.set_output(None)
    assert stream.getvalue() == f"\033[33m~ {target}\033[0m\n"


def test_write_dropin_skipped_prints_nothing(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("same\n", encoding="utf-8")
    stream = _capture()
    try:
        write_dropin(target, "same\n")
    finally:
        colors.set_output(None)
    assert stream.getvalue() == ""


def test_write_dropin_verbose_shows_diff(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("keep\nold\n", encoding="utf-8")
    stream = _capture(verbose=True)
    try:
        write_dropin(target, "keep\nnew\n")
    finally:
        colors.set_output(None)
    out = stream.getvalue()
    assert "\033[31m-old\033[0m" in out
    assert "\033[32m+new\033[0m" in out


def test_append_marked_prints_modified(tmp_path: Path) -> None:
    target = tmp_path / "jail.local"
    target.write_text("[DEFAULT]\n", encoding="utf-8")
    stream = _capture()
    try:
        append_marked(target, "fail2ban", "enabled = true")
    finally:
        colors.set_output(None)
    assert stream.getvalue().startswith(f"\033[33m~ {target}\033[0m\n")


def test_append_marked_prints_created_for_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "new.conf"
    stream = _capture()
    try:
        append_marked(target, "x", "body")
    finally:
        colors.set_output(None)
    assert stream.getvalue().startswith(f"\033[32m+ {target}\033[0m\n")


def test_write_dropin_secret_hides_content_and_diff(tmp_path: Path) -> None:
    target = tmp_path / "secret.sh"
    target.write_text("TOKEN='old'\n", encoding="utf-8")
    stream = _capture(verbose=True)
    try:
        write_dropin(target, "TOKEN='new'\n", mode=0o700, secret=True)
    finally:
        colors.set_output(None)
    out = stream.getvalue()
    assert out.startswith(f"\033[33m~ {target}\033[0m\n")
    assert "(content hidden: contains a secret)" in out
    assert "old" not in out and "new" not in out


def test_write_dropin_secret_on_created_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.sh"
    stream = _capture(verbose=True)
    try:
        write_dropin(target, "TOKEN='x'\n", secret=True)
    finally:
        colors.set_output(None)
    out = stream.getvalue()
    assert "(content hidden: contains a secret)" in out
    assert "TOKEN" not in out
