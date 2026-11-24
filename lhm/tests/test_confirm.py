import io
import sys

import pytest

from lhm.core.confirm import BYPASS_ENV, bypass_requested, confirm_once


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
    assert confirm_once(["plan"]) is False
    assert "not a TTY" in capsys.readouterr().err


def test_one_exact_yes_prints_plan_and_leaves_the_next_answer_unread(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    stdin = Tty("y\nn\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_once(["plan line"]) is True
    out = capsys.readouterr().out
    assert out.startswith("plan line\n")
    assert out.count("Apply this plan?") == 1
    assert stdin.readline() == "n\n"


def test_only_exact_y_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = Tty("Y\ny\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_once(["plan"]) is False


def test_tty_check_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert confirm_once(["plan"], tty_check=False) is True


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ("\n", "nothing further was changed"),
        ("n\n", "nothing further was changed"),
        ("", "no input available"),
    ],
)
def test_empty_declined_or_eof_answer_aborts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    response: str,
    reason: str,
) -> None:
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    monkeypatch.setattr(sys, "stdin", Tty(response))
    assert confirm_once(["plan"]) is False
    assert reason in capsys.readouterr().err


def test_bypass_skips_prompt_without_a_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """LHM_CONFIRM_BYPASS=1: no TTY needed, no input read, plan still printed."""
    monkeypatch.setenv(BYPASS_ENV, "1")
    monkeypatch.setattr(sys, "stdin", NoTty(""))
    assert confirm_once(["plan line"]) is True
    captured = capsys.readouterr()
    assert "plan line" in captured.out
    assert "not a TTY" not in captured.err
    assert "skipped" in captured.err


def test_bypass_still_reads_nothing_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BYPASS_ENV, "1")
    stdin = Tty("n\nn\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert confirm_once(["plan"]) is True
    assert stdin.tell() == 0


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "2"])
def test_bypass_requires_exact_one(
    monkeypatch: pytest.MonkeyPatch, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo must not silently disable the gate: still fails closed without a TTY."""
    monkeypatch.setenv(BYPASS_ENV, value)
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert bypass_requested() is False
    assert confirm_once(["plan"]) is False
    assert "not a TTY" in capsys.readouterr().err


def test_bypass_unset_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BYPASS_ENV, raising=False)
    assert bypass_requested() is False


@pytest.mark.parametrize("value", [" 1 ", "1\n", "1 ", "\t1"])
def test_bypass_padding_is_not_accepted(
    monkeypatch: pytest.MonkeyPatch, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The documented value is exactly ``1``; padding must not bypass the gate."""
    monkeypatch.setenv(BYPASS_ENV, value)
    monkeypatch.setattr(sys, "stdin", NoTty("y\ny\n"))
    assert bypass_requested() is False
    assert confirm_once(["plan"]) is False
    assert "not a TTY" in capsys.readouterr().err
