import errno
import logging
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from lhm.core.runner import CommandError, Runner


def test_run_returns_typed_result(fake_exec: Any) -> None:
    fake_exec.responses.append(("echo hi", 0, "hi\n", ""))
    runner = Runner(exec_fn=fake_exec)
    result = runner.run(["echo", "hi"], timeout=5.0)
    assert result.ok
    assert result.stdout == "hi\n"
    assert result.cmd == ["echo", "hi"]


def test_run_passes_timeout(fake_exec: Any) -> None:
    runner = Runner(exec_fn=fake_exec)
    runner.run(["true"], timeout=7)
    assert fake_exec.timeouts == [7.0]


def test_run_check_raises_with_result(fake_exec: Any) -> None:
    fake_exec.responses.append(("false", 3, "", "boom"))
    runner = Runner(exec_fn=fake_exec)
    with pytest.raises(CommandError) as excinfo:
        runner.run(["false"])
    assert excinfo.value.result.returncode == 3
    assert "boom" in str(excinfo.value)


def test_run_check_false_does_not_raise(fake_exec: Any) -> None:
    fake_exec.responses.append(("false", 1, "", ""))
    runner = Runner(exec_fn=fake_exec)
    assert runner.run(["false"], check=False).returncode == 1


def test_dry_run_records_never_executes(fake_exec: Any) -> None:
    runner = Runner(dry_run=True, exec_fn=fake_exec)
    result = runner.run(["systemctl", "restart", "ssh"])
    assert result.was_dry_run
    assert result.returncode is None
    assert not result.ok
    assert runner.planned == [["systemctl", "restart", "ssh"]]
    assert fake_exec.calls == []
    assert runner.history == []


def test_dry_run_does_not_enforce_check(fake_exec: Any) -> None:
    result = Runner(dry_run=True, exec_fn=fake_exec).run(["systemctl", "daemon-reload"])
    assert result.was_dry_run
    assert not result.ok
    assert fake_exec.calls == []


@pytest.mark.parametrize("dry_run", [False, True])
def test_redacted_arguments_stay_out_of_diagnostics(
    dry_run: bool, fake_exec: Any, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    secret = "example-argument-to-hide"
    runner = Runner(dry_run=dry_run, verbose=True, exec_fn=fake_exec)
    with caplog.at_level(logging.INFO):
        result = runner.run(["example", secret], redact=frozenset({1}))
    assert result.cmd == ["example", "<hidden>"]
    assert secret not in caplog.text + capsys.readouterr().out
    assert fake_exec.calls == ([] if dry_run else [["example", secret]])
    assert runner.planned == ([["example", "<hidden>"]] if dry_run else [])


def test_live_returncode_passes_through() -> None:
    result = Runner().run([sys.executable, "-c", "raise SystemExit(7)"], check=False)
    assert result.returncode == 7
    assert not result.ok
    assert not result.was_dry_run


def test_native_newlines_can_be_preserved() -> None:
    script = r"import os; os.write(1, b'a\r\nb\rc\n'); os.write(2, b'd\re\r\nf\n')"
    argv = [sys.executable, "-c", script]
    runner = Runner()

    normalized = runner.run(argv)
    preserved = runner.run(argv, preserve_newlines=True)

    assert (normalized.stdout, normalized.stderr) == ("a\nb\nc\n", "d\ne\nf\n")
    assert (preserved.stdout, preserved.stderr) == ("a\r\nb\rc\n", "d\re\r\nf\n")


def test_fake_exec_accepts_newline_option_without_changing_contract(fake_exec: Any) -> None:
    fake_exec.responses.append(("example", 0, "out\r\n", "err\r"))
    runner = Runner(exec_fn=fake_exec)

    normalized = runner.run(["example"], timeout=5)
    preserved = runner.run(["example"], timeout=5, preserve_newlines=True)

    assert (normalized.stdout, normalized.stderr) == ("out\n", "err\n")
    assert (preserved.stdout, preserved.stderr) == ("out\r\n", "err\r")
    assert fake_exec.calls == [["example"], ["example"]]
    assert fake_exec.timeouts == [5, 5]


def test_missing_binary_is_127(tmp_path: Path) -> None:
    result = Runner().run([str(tmp_path / "does-not-exist")], check=False)
    assert result.returncode == 127
    assert "command not found" in result.stderr


def test_timeout_kills_same_session_children(tmp_path: Path) -> None:
    marker = tmp_path / "grandchild-ran"
    started = tmp_path / "grandchild-started"
    child = (
        "import pathlib, time; "
        f"pathlib.Path({str(started)!r}).touch(); time.sleep(1); "
        f"pathlib.Path({str(marker)!r}).write_text('ran')"
    )
    script = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "time.sleep(30)\n"
    )
    result = Runner().run([sys.executable, "-c", script], timeout=0.5, check=False)
    assert result.returncode == 124
    assert "timed out after 0.5s" in result.stderr
    assert started.exists()
    time.sleep(1)
    assert not marker.exists()


def test_escaped_child_cannot_wedge_timeout_cleanup() -> None:
    # The grandchild leaves the session (setsid) but keeps our pipe write ends:
    # the timeout path must return promptly instead of waiting for EOF.
    script = (
        "import subprocess, time\n"
        "subprocess.Popen(['sleep', '3'], start_new_session=True)\n"
        "time.sleep(30)\n"
    )
    start = time.monotonic()
    result = Runner().run([sys.executable, "-c", script], timeout=0.2, check=False)
    elapsed = time.monotonic() - start
    assert result.returncode == 124
    assert elapsed < 2.0


def test_capture_returns_stdout(fake_exec: Any) -> None:
    fake_exec.responses.append(("ss -tulpn", 0, "tcp LISTEN\n", ""))
    assert Runner(exec_fn=fake_exec).capture(["ss", "-tulpn"]) == "tcp LISTEN\n"


def test_commands_are_logged(fake_exec: Any, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="lhm.runner"):
        Runner(exec_fn=fake_exec).run(["true"])
    assert "cmd=true" in caplog.text
    assert "rc=0" in caplog.text
    assert "duration=" in caplog.text


def test_executed_command_is_echoed_in_color_mode(fake_exec: Any) -> None:
    import io

    from lhm.core import colors

    stream = io.StringIO()
    stream.isatty = lambda: True  # type: ignore[method-assign]
    colors.configure("always")
    colors.set_output(stream)
    try:
        Runner(exec_fn=fake_exec).run(["systemctl", "restart", "ssh"])
    finally:
        colors.set_output(None)
    assert "$ systemctl restart ssh" in stream.getvalue()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("output_errno", [errno.EPIPE, errno.ENOSPC])
def test_verbose_output_failure_preserves_command_failure(
    fake_exec: Any, monkeypatch: pytest.MonkeyPatch, check: bool, output_errno: int
) -> None:
    from lhm.core import colors

    echoes: list[list[str]] = []

    def fail_echo(argv: list[str]) -> None:
        echoes.append(argv)
        raise OSError(output_errno, "stdout write failed")

    colors.configure("never")
    monkeypatch.setattr(colors, "command", fail_echo)
    fake_exec.responses.append(("false", 3, "", "boom"))
    runner = Runner(verbose=True, exec_fn=fake_exec)

    if check:
        with pytest.raises(CommandError) as excinfo:
            runner.run(["false"])
        result = excinfo.value.result
    else:
        result = runner.run(["false"], check=False)

    assert echoes == fake_exec.calls == [["false"]]
    assert result.returncode == 3
    assert result.stderr == "boom"


def test_dry_run_echoes_no_command(fake_exec: Any) -> None:
    import io

    from lhm.core import colors

    stream = io.StringIO()
    colors.configure("always")
    colors.set_output(stream)
    try:
        Runner(dry_run=True, exec_fn=fake_exec).run(["systemctl", "restart", "ssh"])
    finally:
        colors.set_output(None)
    assert stream.getvalue() == ""
