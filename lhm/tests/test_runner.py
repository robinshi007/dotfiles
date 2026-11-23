import logging
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
    assert result.returncode == 0
    assert result.ok
    assert runner.planned == [["systemctl", "restart", "ssh"]]
    assert fake_exec.calls == []


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
