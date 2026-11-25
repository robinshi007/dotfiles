"""Opt in with LHM_TEST_CADDY=/absolute/path/to/an/extracted/caddy binary."""

import hashlib
import http.client
import json
import os
import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from typing import NamedTuple

import pytest

from lhm.core.runner import Runner
from lhm.modules import caddy

CAPTURE = Path(__file__).parent / "fixtures" / "caddy-2.6-loopback.json"
SITE = "app.example.test"


class Capture(NamedTuple):
    adapted: str
    runtime: str
    requests: list[dict[str, str | int | None]]


@pytest.fixture
def capture() -> Capture:
    data = json.loads(CAPTURE.read_text())
    return Capture(
        json.dumps(data["config"], separators=(",", ":")),
        json.dumps(data["runtime"], separators=(",", ":")),
        data["http"],
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('"status_code":308', '"status_code":307'),
        ("https://app.example.test{http.request.uri}", "https://other.example.test/"),
        ("127.0.0.1:19000", "127.0.0.1:19001"),
        ('"roll_keep":10', '"roll_keep":1'),
        ('"listen":["127.0.0.1:18443"]', '"listen":["127.0.0.1:19443"]'),
    ],
)
def test_runtime_comparator_rejects_drift_in_caddy_capture(
    monkeypatch: pytest.MonkeyPatch, capture: Capture, old: str, new: str
) -> None:
    def execute(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        inv = "1234567890abcdef" * 2
        info = f"LoadState=loaded\nActiveState=active\nMainPID=123\nInvocationID={inv}\n"
        value = info if cmd[0] == "systemctl" else capture.adapted
        return subprocess.CompletedProcess(cmd, 0, value, "")

    def read_active(pid: int) -> str:
        assert pid == 123
        return capture.runtime

    runner = Runner(exec_fn=execute)
    expected = caddy._expected(runner, Path("/tmp/lhm-caddy/Caddyfile"))
    assert capture.adapted != capture.runtime  # Caddy reorders object keys.
    monkeypatch.setattr(caddy, "_runtime_json", read_active)
    _, wire = caddy._verify_runtime(runner, expected)
    assert wire == hashlib.sha256(capture.runtime.encode()).hexdigest()
    altered = capture.runtime.replace(old, new, 1)
    assert altered != capture.runtime
    monkeypatch.setattr(caddy, "_runtime_json", lambda _: altered)
    with pytest.raises(caddy.CaddyError, match="running Caddy config differs"):
        caddy._verify_runtime(runner, expected)


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest.fixture
def disposable_caddy(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, int, int]]:
    location = os.environ.get("LHM_TEST_CADDY")
    if location is None:
        pytest.skip("set LHM_TEST_CADDY to run the disposable loopback test")
    binary = Path(location)
    assert binary.is_absolute() and binary.is_file()
    # A short path keeps the Unix address below Linux's 108-byte limit.
    with TemporaryDirectory(prefix="lhm-caddy-", dir="/tmp/opencode") as workspace:
        root = Path(workspace)
        config = root / "Caddyfile"
        monkeypatch.setattr(caddy, "ADMIN_SOCKET", root / "admin.sock")
        monkeypatch.setattr(caddy, "ACCESS_LOG", root / "access.log")
        plain, tls = _port(), _port()
        assert plain != tls
        rendered = caddy.desired_conf(site=SITE, upstream="127.0.0.1:19000")
        rendered = rendered.replace(
            "auto_https disable_redirects",
            f"auto_https disable_redirects\n\tskip_install_trust\n\tdefault_bind 127.0.0.1"
            f"\n\thttp_port {plain}\n\thttps_port {tls}",
        ).replace(f"\n{SITE} {{", f"\n{SITE} {{\n\ttls internal")
        config.write_text(rendered)
        env = {"HOME": workspace, "XDG_CONFIG_HOME": workspace, "XDG_DATA_HOME": workspace}
        adapted = subprocess.check_output(
            [binary, "adapt", "--config", config, "--adapter", "caddyfile"],
            env=env,
            text=True,
            timeout=5,
        )
        with (root / "caddy.log").open("wb") as log:
            proc = subprocess.Popen(
                [binary, "run", "--config", config, "--adapter", "caddyfile"],
                cwd=root,
                env=env,
                stdout=log,
                stderr=log,
            )
            try:
                deadline = monotonic() + 5
                while not caddy.ADMIN_SOCKET.is_socket():
                    assert proc.poll() is None and monotonic() < deadline
                    sleep(0.025)
                yield adapted, proc.pid, plain
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


def test_real_caddy_runtime_and_redirects_on_loopback(
    disposable_caddy: tuple[str, int, int],
    capture: Capture,
) -> None:
    adapted, pid, port = disposable_caddy
    runtime = caddy._runtime_json(pid)
    assert caddy._fingerprint(runtime) == caddy._fingerprint(adapted)
    with pytest.raises(caddy.CaddyError, match="not owned"):
        caddy._runtime_json(pid + 1)

    def local_redirect(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert cmd[0] == "curl" and "--ipv4" in cmd and cmd[-1].startswith("http://127.0.0.1/")
        url = cmd[-1].replace("http://127.0.0.1/", f"http://127.0.0.1:{port}/", 1)
        return subprocess.run([*cmd[:-1], url], text=True, capture_output=True, timeout=timeout)

    caddy._verify_route(Runner(exec_fn=local_redirect), SITE)
    for case in capture.requests:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request(
                str(case["method"]), str(case["path"]), headers={"Host": str(case["host"])}
            )
            response = conn.getresponse()
            assert response.status == case["status"]
            assert response.getheader("Location") == case["location"]
            assert response.getheader("Server") == case["server"]
        finally:
            conn.close()
