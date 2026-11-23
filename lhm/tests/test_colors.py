import io
import sys

import pytest

from lhm.core import colors
from lhm.core.colors import Color


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class NoTty(io.StringIO):
    def isatty(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    colors.configure("auto", verbose=False)
    colors.set_output(None)


def test_auto_is_off_without_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(colors, "output", lambda: NoTty())
    assert colors.enabled() is False
    assert colors.paint("x", Color.RED) == "x"


def test_auto_is_on_with_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(colors, "output", lambda: Tty())
    assert colors.enabled() is True
    assert colors.paint("x", Color.RED) == f"{Color.RED}x{Color.RESET}"


def test_no_color_forces_auto_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(colors, "output", lambda: Tty())
    monkeypatch.setenv("NO_COLOR", "")
    assert colors.enabled() is False


def test_always_beats_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(colors, "output", lambda: NoTty())
    monkeypatch.setenv("NO_COLOR", "1")
    colors.configure("always")
    assert colors.enabled() is True
    assert colors.paint("x", Color.GREEN) == f"{Color.GREEN}x{Color.RESET}"


def test_never_disables_even_on_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(colors, "output", lambda: Tty())
    colors.configure("never")
    assert colors.enabled() is False


def test_invalid_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        colors.configure("sometimes")


def test_set_output_redirects_capture() -> None:
    stream = Tty()
    colors.configure("always")
    colors.set_output(stream)
    colors.paintln("hello", Color.CYAN)
    assert stream.getvalue() == f"{Color.CYAN}hello{Color.RESET}\n"


def test_file_change_symbols() -> None:
    stream = Tty()
    colors.configure("always")
    colors.set_output(stream)
    colors.file_change("created", "/etc/a.conf", new="a\n")
    colors.file_change("modified", "/etc/b.conf", old="x\n", new="y\n")
    colors.file_change("deleted", "/etc/c.conf", old="c\n")
    colors.file_change("symlink", "/etc/d.conf", link="/etc/d.conf.real")
    lines = stream.getvalue().splitlines()
    assert lines[0] == f"{Color.GREEN}+ /etc/a.conf{Color.RESET}"
    assert lines[1] == f"{Color.YELLOW}~ /etc/b.conf{Color.RESET}"
    assert lines[2] == f"{Color.RED}- /etc/c.conf{Color.RESET}"
    assert lines[3] == f"{Color.MAGENTA}@ /etc/d.conf{Color.RESET}"


def test_verbose_created_shows_full_content() -> None:
    stream = Tty()
    colors.configure("always", verbose=True)
    colors.set_output(stream)
    colors.file_change("created", "/etc/a.conf", new="one\ntwo\n")
    lines = stream.getvalue().splitlines()
    assert lines[0].endswith("+ /etc/a.conf" + Color.RESET)
    assert lines[1:] == ["one", "two"]


def test_verbose_modified_shows_unified_diff() -> None:
    stream = Tty()
    colors.configure("always", verbose=True)
    colors.set_output(stream)
    colors.file_change("modified", "/etc/a.conf", old="old\nsame\n", new="new\nsame\n")
    out = stream.getvalue()
    # Removed lines red, added lines green.
    assert f"{Color.RED}-old{Color.RESET}" in out
    assert f"{Color.GREEN}+new{Color.RESET}" in out
    assert " same" in out


def test_verbose_deleted_shows_old_content() -> None:
    stream = Tty()
    colors.configure("always", verbose=True)
    colors.set_output(stream)
    colors.file_change("deleted", "/etc/a.conf", old="gone\n")
    assert "gone" in stream.getvalue()


def test_not_verbose_hides_content() -> None:
    stream = Tty()
    colors.configure("always", verbose=False)
    colors.set_output(stream)
    colors.file_change("created", "/etc/a.conf", new="hidden\n")
    assert "hidden" not in stream.getvalue()


def test_command_echo() -> None:
    stream = Tty()
    colors.configure("always")
    colors.set_output(stream)
    colors.command(["ufw", "allow", "22345/tcp"])
    assert stream.getvalue() == f"{Color.CYAN}$ ufw allow 22345/tcp{Color.RESET}\n"


def test_output_defaults_to_sys_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = NoTty()
    monkeypatch.setattr(sys, "stdout", probe)
    colors.set_output(None)
    assert colors.output() is probe
