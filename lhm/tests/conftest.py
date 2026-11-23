"""Shared fakes: no test invokes a real system command."""

import subprocess
from collections.abc import Iterable

import pytest

from lhm.core.runner import Runner


class FakeExec:
    """Records calls and answers from a prefix->result table (first match wins)."""

    def __init__(self, responses: Iterable[tuple[str, int, str, str]] = ()) -> None:
        self.responses = list(responses)
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []

    def __call__(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        self.timeouts.append(timeout)
        joined = " ".join(cmd)
        for prefix, rc, out, err in self.responses:
            if joined.startswith(prefix):
                return subprocess.CompletedProcess(cmd, rc, out, err)
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def fake_exec() -> FakeExec:
    return FakeExec()


@pytest.fixture
def runner(fake_exec: FakeExec) -> Runner:
    return Runner(exec_fn=fake_exec)
