import re
from pathlib import Path

import pytest

from lhm.core.files import (
    append_marked,
    render_shell_template,
    render_template,
    write_dropin,
)


def test_dropin_identical_content_is_skipped(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("Port 22345\n", encoding="utf-8")
    assert write_dropin(target, "Port 22345\n") == "skipped"
    assert not (tmp_path / "99-lhm.conf.bak").exists()


def test_dropin_changed_content_backs_up_and_writes(tmp_path: Path) -> None:
    target = tmp_path / "99-lhm.conf"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)
    assert write_dropin(target, "new\n") == "written"
    assert target.read_text(encoding="utf-8") == "new\n"
    assert (tmp_path / "99-lhm.conf.bak").read_text(encoding="utf-8") == "old\n"
    assert target.stat().st_mode & 0o777 == 0o600


def test_dropin_new_file_gets_default_mode(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "99-lhm.conf"
    assert write_dropin(target, "x\n") == "written"
    assert target.stat().st_mode & 0o777 == 0o644
    assert not list(target.parent.glob("*.bak*"))


def test_dropin_rejects_relative_path() -> None:
    with pytest.raises(ValueError):
        write_dropin("relative.conf", "x")


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
    assert append_marked(target, "fail2ban", "enabled = false") == "skipped"
    assert target.read_text(encoding="utf-8") == first
    assert not (tmp_path / "jail.local.bak.1").exists()


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
    assert "Unattended-Upgrade::Allowed-Origins" in rendered
    assert "APT::Periodic::Unattended-Upgrade \"1\";" in rendered
    # string.Template escape: "$${distro_id}" renders as "${distro_id}".
    assert '"${distro_id}:${distro_codename}-security"' in rendered


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
