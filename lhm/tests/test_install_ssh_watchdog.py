import os
import pty
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-ssh-watchdog.sh"
IDENTITY = '{"build":"' + "a" * 64 + '","protocol":1,"schema":1}'


def _executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


@dataclass(frozen=True)
class Install:
    script: Path
    work: Path
    opt: Path
    state: Path
    env: dict[str, str]

    @property
    def dest(self) -> Path:
        return self.opt / "lhm-ssh-rollback"

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.script, *args],
            cwd=self.work,
            env=self.env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def confirm(self, answer: str = "y") -> tuple[int, str]:
        master, slave = pty.openpty()
        try:
            with subprocess.Popen(
                [self.script],
                cwd=self.work,
                env=self.env,
                stdin=slave,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            ) as proc:
                os.write(master, (answer + "\n").encode())
                try:
                    output, _ = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    raise
                return proc.returncode, output
        finally:
            os.close(slave)
            os.close(master)


@pytest.fixture
def install(tmp_path: Path) -> Install:
    if os.geteuid() == 0:
        pytest.skip("the installer requires an unprivileged caller")
    repo = tmp_path / "release checkout"
    project = repo / "lhm"
    scripts = project / "scripts"
    sources = project / "src/lhm"
    (sources / "modules").mkdir(parents=True)
    scripts.mkdir()
    script = Path(shutil.copy2(SCRIPT, scripts))
    (sources / "__init__.py").write_text("# committed\n")
    (sources / "modules/ssh_watchdog.py").write_text("# worker\n")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for args in (
        ("init", "-q"),
        ("add", "lhm/src"),
        ("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "release"),
    ):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, timeout=10)
    (sources / "__init__.py").write_text("# dirty\n")
    (sources / "untracked.py").touch()

    opt, run = tmp_path / "fake opt", tmp_path / "fake run"
    state = run / "lhm-ssh-rollback"
    work, tools, prefix = (tmp_path / name for name in ("other cwd", "bin", "Python image"))
    for directory in (opt, run, work, tools):
        directory.mkdir(mode=0o700)
    stdlib = prefix / "lib/python3.15/encodings"
    stdlib.mkdir(parents=True)
    (stdlib / "__init__.py").touch()
    (prefix / "bin").mkdir()
    (prefix / "bin/python3").symlink_to("python3.15")
    mode = work / "mode"
    _executable(
        prefix / "bin/python3.15",
        f"""#!/bin/bash
set -eu
[[ $1 == -I && $2 == -S && $3 == -B && $4 == -c ]]
scenario=$(cat {shlex.quote(str(mode))} 2>/dev/null || :)
if [[ $# == 7 ]]; then
    exec /usr/bin/python3 -I -S -B -c '
import ctypes
import errno
import sys
from pathlib import Path
from types import SimpleNamespace

scenario, inode_path, code = sys.argv[1:4]
del sys.argv[1:4]
if scenario == "publish-collision":
    dest = Path(sys.argv[2])
    dest.mkdir()
    Path(inode_path).write_text(str(dest.stat().st_ino))
elif scenario == "publish-unsupported":
    def unsupported(*args):
        ctypes.set_errno(errno.EOPNOTSUPP)
        return -1
    ctypes.CDLL = lambda *args, **kwargs: SimpleNamespace(renameat2=unsupported)
elif scenario == "publish-no-symbol":
    ctypes.CDLL = lambda *args, **kwargs: SimpleNamespace()
exec(code)
' "$scenario" {shlex.quote(str(work / "dest-inode"))} "${{@:5}}"
fi
[[ $# == 8 ]]
[[ $7 == probe && $8 == 00000000000000000000000000000000 ]]
[[ $(cat "$6/lhm/__init__.py") == '# committed' && ! -e "$6/lhm/untracked.py" ]]
[[ -f "$6/lhm/modules/ssh_watchdog.py" && ! -L "${{0%/*}}/python3" ]]
case $scenario in
    mismatch) printf '\\n' ;;
    late-pending) mkdir -m 700 -- {shlex.quote(str(state))}
        ln -s missing -- {shlex.quote(str(state / "pending.json"))} ;;
esac
printf '%s\\n' {shlex.quote(IDENTITY)}
""",
    )
    _executable(
        tools / "uv",
        f"""#!/bin/bash
set -eu
[[ $PWD == {shlex.quote(str(project))} ]]
[[ $* == 'run --locked --no-sync --no-python-downloads --managed-python python -I -B -c '* ]]
[[ ! -e {shlex.quote(str(work / "no-uv-environment"))} ]] || exit 1
printf '%s\\n' {shlex.quote(str(prefix))} {shlex.quote(IDENTITY)}
""",
    )
    # Run the privileged phase without sudo, replacing only host paths and UID
    # checks in the copied code. The tests never write to the actual /opt or /run.
    _executable(
        tools / "sudo",
        f"""#!/usr/bin/python3
import os
import sys
from pathlib import Path
from shlex import quote

args = sys.argv[1:]
assert args[:7] == ["--", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL=C", "/bin/bash", "-c"]
Path({str(work / "sudo-called")!r}).touch()
mode = Path({str(mode)!r})
scenario = mode.read_text() if mode.exists() else ""
code = args[7].replace("opt=/opt", "opt=" + quote({str(opt)!r}))
code = code.replace("run=/run", "run=" + quote({str(run)!r}))
code = code.replace("-uid 0", "-uid " + str(os.geteuid()))
code = code.replace("trusted_dir /\\n", "")
if scenario == "bad-archive":
    os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
args[7] = code
os.execv(args[1], args[1:])
""",
    )
    env["PATH"] = f"{tools}{os.pathsep}{env['PATH']}"
    return Install(script, work, opt, state, env)


def test_syntax_and_help() -> None:
    subprocess.run(["bash", "-n", SCRIPT], check=True, timeout=10)
    result = subprocess.run([SCRIPT, "--help"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert "--dry-run" in result.stdout


def test_rejects_bad_arguments_and_requires_confirmation(install: Install) -> None:
    assert install.run("--yes").returncode == 2
    dry_run = install.run("--dry-run")
    assert dry_run.returncode == 0, dry_run.stderr
    assert IDENTITY in dry_run.stdout
    assert install.run().returncode == 3
    assert install.confirm("y ")[0] == 3
    (install.work / "no-uv-environment").touch()
    incomplete = install.run("--dry-run")
    assert incomplete.returncode != 0
    assert "check uv sync" in incomplete.stderr
    assert not (install.work / "sudo-called").exists()
    assert list(install.opt.iterdir()) == []


def test_first_install_from_other_cwd_does_not_overwrite(install: Install) -> None:
    status, output = install.confirm()
    assert status == 0, output
    assert list(install.opt.iterdir()) == [install.dest]
    assert (install.dest / "src/lhm/__init__.py").read_text() == "# committed\n"
    assert not (install.dest / "src/lhm/untracked.py").exists()
    assert (install.dest / "python/lib/python3.15/encodings/__init__.py").is_file()
    inode = install.dest.stat().st_ino
    status, output = install.confirm()
    assert status != 0 and "destination already exists" in output
    assert install.dest.stat().st_ino == inode


def test_publish_conflict_does_not_replace_empty_directory(install: Install) -> None:
    (install.work / "mode").write_text("publish-collision")
    status, output = install.confirm()
    assert status != 0, output
    assert list(install.opt.iterdir()) == [install.dest]
    assert list(install.dest.iterdir()) == []
    assert install.dest.stat().st_ino == int((install.work / "dest-inode").read_text())


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("pending", "transaction is pending"),
        ("dangling-pending", "transaction is pending"),
        ("unknown-state", "untrusted directory"),
        ("late-pending", "transaction is pending"),
        ("dangling-target", "destination already exists"),
        ("publish-unsupported", "cannot atomically publish runtime"),
        ("publish-no-symbol", "atomic no-replace rename is unavailable"),
        ("bad-archive", "source archive digest mismatch"),
        ("mismatch", "protocol/schema or source fingerprint mismatch"),
    ],
)
def test_refuses_unsafe_install(install: Install, scenario: str, message: str) -> None:
    if scenario in {"pending", "dangling-pending"}:
        install.state.mkdir(mode=0o700)
        marker = install.state / "pending.json"
        if scenario == "pending":
            marker.touch()
        else:
            marker.symlink_to("missing")
    elif scenario == "unknown-state":
        install.state.touch()
    elif scenario == "dangling-target":
        install.dest.symlink_to("missing")
    else:
        (install.work / "mode").write_text(scenario)
    status, output = install.confirm()
    assert status != 0 and message in output, output
    if scenario == "dangling-target":
        assert install.dest.readlink() == Path("missing")
        assert list(install.opt.iterdir()) == [install.dest]
    else:
        assert list(install.opt.iterdir()) == []
