import io
import sys

import pytest

from lhm.core.confirm import BYPASS_ENV, bypass_requested, confirm_twice


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class NoTty(io.StringIO):
    def isatty(self) -> bool:
        return False


def test_refuses_non_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert confirm_twice(["plan"]) is False
    assert "not a TTY" in capsys.readouterr().err


def test_two_exact_yes_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", Tty("y\ny\n"))
    assert confirm_twice(["plan line"]) is True
    out = capsys.readouterr().out
    assert "plan line" in out


def test_second_answer_must_be_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = Tty("y\nn\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_twice(["plan"]) is False


def test_only_exact_y_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = Tty("Y\ny\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_twice(["plan"]) is False


def test_tty_check_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert confirm_twice(["plan"], tty_check=False) is True


def test_empty_answer_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", Tty("\n"))
    assert confirm_twice(["plan"]) is False


def test_bypass_skips_both_prompts_without_a_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """LHM_CONFIRM_BYPASS=1: no TTY needed, no input read, plan still printed."""
    monkeypatch.setenv(BYPASS_ENV, "1")
    monkeypatch.setattr(sys, "stdin", NoTty(""))
    assert confirm_twice(["plan line"]) is True
    captured = capsys.readouterr()
    assert "plan line" in captured.out
    assert "not a TTY" not in captured.err
    assert "skipped" in captured.err


def test_bypass_still_reads_nothing_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BYPASS_ENV, "1")
    stdin = Tty("n\nn\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_twice(["plan"]) is True
    assert stdin.tell() == 0


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "2"])
def test_bypass_requires_exact_one(
    monkeypatch: pytest.MonkeyPatch, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo must not silently disable the gate: still fails closed without a TTY."""
    monkeypatch.setenv(BYPASS_ENV, value)
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert bypass_requested() is False
    assert confirm_twice(["plan"]) is False
    assert "not a TTY" in capsys.readouterr().err


def test_bypass_unset_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    assert bypass_requested() is False
