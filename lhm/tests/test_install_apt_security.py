import os
import pty
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from lhm.core import apt_runtime, apt_timer
from lhm.core.distro import DistroError
from lhm.core.runner import Runner

PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts/install-apt-security.sh"


def _executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


@dataclass(frozen=True)
class Install:
    script: Path
    repo: Path
    work: Path
    libexec: Path
    env: dict[str, str]

    @property
    def dest(self) -> Path:
        return self.libexec / "lhm-apt-security"

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, env=self.env, check=True, timeout=10)

    def commit(self) -> None:
        self.git("add", "lhm")
        self.git("-c", "user.name=Test", "-c", "user.email=t@example.com", "commit", "-qm", "test")

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

    def confirm(self, timeout: float = 10.0) -> tuple[int, str]:
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
                os.write(master, b"y\n")
                try:
                    output, _ = proc.communicate(timeout=timeout)
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
    for name in ("scripts", "src/lhm/core", "src/lhm/modules", "templates"):
        (project / name).mkdir(parents=True)
    script = Path(shutil.copy2(SCRIPT, project / "scripts"))
    sources = project / "src/lhm"
    (sources / "__init__.py").touch()
    shutil.copyfile(PROJECT / "src/lhm/core/apt_runtime.py", sources / "core/apt_runtime.py")
    (sources / "core/files.py").write_text(
        "from pathlib import Path\n"
        "TEMPLATES_DIR = Path(__file__).resolve().parents[3] / 'templates'\n"
        "def render_template(name, **kwargs):\n"
        "    assert (TEMPLATES_DIR / name).read_text() == '# committed\\n'\n"
    )
    (sources / "modules/updates.py").write_text(
        "def automatic_main():\n    print('committed automatic worker')\n    return 0\n"
    )
    for name in ("unattended-upgrades.conf.tmpl", "apt-security.sources.tmpl"):
        (project / "templates" / name).write_text("# committed\n")

    fake_root = tmp_path / "fake root"
    libexec = fake_root / "usr/local/libexec"
    for directory in (fake_root, fake_root / "usr", libexec.parent):
        directory.mkdir(mode=0o700)
    work, tools, prefix = (tmp_path / name for name in ("other cwd", "bin", "Python image"))
    work.mkdir()
    tools.mkdir()
    stdlib = prefix / "lib/python3.15/encodings"
    stdlib.mkdir(parents=True)
    (stdlib / "__init__.py").write_text("# private stdlib\n")
    (prefix / "bin").mkdir()
    (prefix / "bin/python3").symlink_to("python3.15")
    _executable(
        prefix / "bin/python3.15",
        """#!/bin/sh
set -eu
[ "$1 $2 $3" = "-I -S -B" ]
[ "$PWD" = "/" ]
[ "$HOME" = /root ]
[ "$(umask)" = 0022 ]
[ "${PYTHONPATH-unset}" = unset ]
shift 3
exec /usr/bin/python3 -I -S -B -c '
import hashlib
import os
import stat
import sys
from pathlib import Path

entry = Path(sys.argv[1])
prefix = str(entry.parent / "python")
stdlib = Path(prefix) / "lib/python3.15"
assert (stdlib / "encodings/__init__.py").read_text() == "# private stdlib\\n"
sys.prefix = sys.base_prefix = sys.exec_prefix = sys.base_exec_prefix = prefix
sys.path[:] = [str(stdlib)]
sys.version_info = (3, 15)
sys.argv = sys.argv[1:]
exec(compile(entry.read_bytes(), str(entry), "exec"), {"__file__": str(entry)})
' "$@"
""",
    )
    _executable(
        tools / "uv",
        f"""#!/bin/bash
set -eu
[[ $PWD == {shlex.quote(str(project))} ]]
[[ $* == 'run --locked --no-sync --no-python-downloads --managed-python python -I -S -B -c '* ]]
printf '%s\\n' {shlex.quote(str(prefix))}
""",
    )
    # Execute the real privileged phase after substituting only temporary host
    # paths and our UID. Never invoke sudo, the host timer, or APT.
    _executable(
        tools / "sudo",
        f"""#!/usr/bin/python3
import hashlib
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from shlex import quote

args = sys.argv[1:]
assert args[:7] == ["--", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL=C", "/bin/bash", "-c"]
work = Path({str(work)!r})
(work / "sudo-called").touch()
mode = work / "mode"
scenario = mode.read_text() if mode.exists() else ""
root = Path({str(fake_root)!r})
libexec = root / "usr/local/libexec"
code = args[7].replace("libexec=/usr/local/libexec", "libexec=" + quote(str(libexec)))
for relative in ("/", "/usr", "/usr/local"):
    code = code.replace(f"trusted_dir {{relative}}\\n",
                        f"trusted_dir {{quote(str(root / relative[1:]))}}\\n")
code = code.replace("-uid 0", "-uid " + str(os.geteuid()))
if scenario == "bad-artifact":
    os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
elif scenario == "linked-artifact":
    with tempfile.TemporaryFile() as stream:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            entry = tarfile.TarInfo("python")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "unexpected"
            archive.addfile(entry)
        stream.seek(0)
        args[9] = hashlib.sha256(stream.read()).hexdigest()
        stream.seek(0)
        os.dup2(stream.fileno(), 0)
elif scenario == "oversized-artifact":
    code = code.replace("max_bytes=$((256 * 1024 * 1024))", "max_bytes=512")
elif scenario == "late-conflict":
    code = code.replace('publishing=true', 'ln -s missing -- "$dest"\\npublishing=true')
elif scenario == "kill-after-publish":
    code = code.replace("printf 'Installed", 'kill -KILL "$$"\\n' + "printf 'Installed")
else:
    before_trust_check = {{
        "writable-tree": 'chmod g+w -- "$stage/python/lib/python3.15"',
        "linked-tree": 'ln -s missing -- "$stage/python/lib/extra"',
        "hardlinked-tree": 'ln -- "$stage/entry.py" "$stage/python/lib/extra"',
        "stale-probe": (
            'sed -i s/lhm-apt-security-v1/lhm-apt-security-v0/ '
            '"$stage/src/lhm/core/apt_runtime.py"'
        ),
        "changed-template": 'printf "# extra\\\\n" > "$stage/templates/extra.tmpl"',
    }}.get(scenario)
    if before_trust_check:
        anchor = 'bad=$(find -P "$stage"'
        assert anchor in code
        code = code.replace(anchor, before_trust_check + '\\n' + anchor)
args[7] = code
os.execv(args[1], args[1:])
""",
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["PATH"] = f"{tools}{os.pathsep}{env['PATH']}"
    env["PYTHONPATH"] = str(sources)
    result = Install(script, repo, work, libexec, env)
    result.git("init", "-q")
    result.commit()
    return result


def test_syntax_and_help() -> None:
    subprocess.run(["bash", "-n", SCRIPT], check=True, timeout=10)
    help_result = subprocess.run([SCRIPT, "--help"], capture_output=True, text=True, timeout=10)
    assert help_result.returncode == 0
    assert "--dry-run" in help_result.stdout


def test_dry_run_and_confirmation_do_not_call_sudo(install: Install) -> None:
    assert install.run("--yes").returncode == 2
    plan = install.run("--dry-run")
    assert plan.returncode == 0, plan.stderr
    assert "reviewed commit" in plan.stdout
    assert install.run().returncode == 3
    assert not (install.work / "sudo-called").exists()
    assert not install.libexec.exists()


def test_refuses_uncommitted_installer_and_committed_symlink(install: Install) -> None:
    original = install.script.read_text()
    install.script.write_text(original + "\n# dirty\n")
    dirty = install.run("--dry-run")
    assert dirty.returncode != 0 and "reviewed Git HEAD" in dirty.stderr
    install.script.write_text(original)
    (install.repo / "lhm/templates/extra.tmpl").symlink_to("missing")
    install.commit()
    linked = install.run("--dry-run")
    assert linked.returncode != 0 and "unexpected file" in linked.stderr
    assert not (install.work / "sudo-called").exists()


def test_install_and_run_without_checkout_then_refuse_reinstall(
    install: Install,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = install.repo / "lhm"
    (project / "src/lhm/modules/updates.py").write_text("raise RuntimeError('dirty checkout')\n")
    (project / "src/lhm/untracked.py").touch()
    (project / "templates/apt-security.sources.tmpl").write_text("# dirty\n")
    status, output = install.confirm()
    assert status == 0, output
    assert install.dest.is_file() and not install.dest.is_symlink()
    info = install.dest.stat()
    assert info.st_mode & 0o7777 == 0o755 and info.st_uid == os.geteuid()
    assert info.st_nlink == 1
    (runtime,) = install.libexec.glob(".lhm-apt-security.*")
    assert runtime.stat().st_mode & 0o7777 == 0o700
    assert not (runtime / "src/lhm/untracked.py").exists()
    assert not (runtime / "python/bin/python3").is_symlink()
    status, output = install.confirm()
    assert status != 0 and "destination already exists" in output
    assert install.dest.stat().st_ino == info.st_ino
    shutil.rmtree(install.repo)
    monkeypatch.setattr(apt_timer, "HELPER", install.dest)
    # The staged fixture uses this test user's UID and a temporary parent;
    # verify exactly the production launcher contents and invoke its real probe.
    monkeypatch.setattr(apt_timer, "_trusted_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(apt_runtime, "_ROOT_UID", os.geteuid())
    expected = apt_runtime.runtime_identity(runtime)
    assert expected.startswith("lhm-apt-security-v1 ")
    monkeypatch.setattr(
        apt_timer,
        "runtime_identity",
        lambda root=None: apt_runtime.runtime_identity(root or runtime),
    )
    apt_timer._verify_helper(Runner())
    result = subprocess.run(
        [install.dest],
        cwd=install.work,
        env=install.env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "committed automatic worker"


def test_publication_keeps_one_link_even_if_installer_is_killed(install: Install) -> None:
    (install.work / "mode").write_text("kill-after-publish")
    status, output = install.confirm()
    assert status != 0, output
    assert install.dest.stat().st_nlink == 1
    (runtime,) = install.libexec.glob(".lhm-apt-security.*")
    assert not (runtime / "launcher").exists()
    probe = subprocess.run(
        [install.dest, "--probe"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert probe.stdout == apt_runtime.runtime_identity(runtime) + "\n"


def test_offline_wheel_matches_archived_worker(install: Install, tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("offline wheel integration requires uv")
    base = Path(sys.base_prefix).resolve()
    python = base / "bin/python3.15"
    stdlib = base / "lib/python3.15"
    if not python.is_file() or not stdlib.is_dir():
        pytest.skip("worker integration requires a standalone CPython 3.15 image")

    project = install.repo / "lhm"
    for rel in ("src/lhm", "templates"):
        shutil.copytree(
            PROJECT / rel,
            project / rel,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    shutil.copyfile(PROJECT / "pyproject.toml", project / "pyproject.toml")
    install.commit()

    env = {**install.env, "TMPDIR": str(tmp_path), "UV_NO_PROGRESS": "1"}

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args, cwd=install.work, env=env, capture_output=True, text=True, timeout=60
        )

    wheels = tmp_path / "dist"
    offline_python = ("--offline", "--no-python-downloads", "--python", sys.executable)
    build = run(uv, "build", *offline_python, "--out-dir", str(wheels), str(project))
    if build.returncode and "was not found in the cache" in build.stderr:
        pytest.skip("offline build requirements are not cached")
    assert build.returncode == 0, build.stderr
    (wheel,) = wheels.glob("*.whl")
    venv = tmp_path / "wheel venv"
    created = run(uv, "venv", *offline_python, str(venv))
    assert created.returncode == 0, created.stderr
    installed_python = str(venv / "bin/python")
    installed = run(
        uv,
        "pip",
        "install",
        "--offline",
        "--no-index",
        "--no-deps",
        "--link-mode",
        "copy",
        "--python",
        installed_python,
        str(wheel),
    )
    assert installed.returncode == 0, installed.stderr

    # Use a genuine relocated interpreter without bundling unrelated uv data
    # (headers, manpages or site-packages) into this temporary fixture.
    image = tmp_path / "Python image"
    shutil.rmtree(image)
    (image / "bin").mkdir(parents=True)
    shutil.copy2(python, image / "bin/python3.15")
    shutil.copytree(
        stdlib,
        image / "lib/python3.15",
        ignore=shutil.ignore_patterns("__pycache__", "site-packages"),
    )
    for library in (base / "lib").glob("libpython*.so.*"):
        shutil.copy2(library, image / "lib")
    install.env["TMPDIR"] = str(tmp_path)
    status, output = install.confirm(timeout=60)
    assert status == 0, output
    shutil.rmtree(install.repo)
    shutil.rmtree(image)

    expected = run(
        installed_python,
        "-I",
        "-B",
        "-c",
        """
import sys
from pathlib import Path
from lhm.core.apt_runtime import runtime_identity
from lhm.core.files import TEMPLATES_DIR, render_template

assert TEMPLATES_DIR.is_relative_to(Path(sys.prefix))
assert "Unattended-Upgrade" in render_template("unattended-upgrades.conf.tmpl")
print(runtime_identity())
""",
    )
    observed = run(str(install.dest), "--probe")
    assert expected.returncode == 0, expected.stderr
    assert observed.returncode == 0, observed.stderr
    assert expected.stdout.startswith(f"{apt_runtime.PROTOCOL} ")
    assert observed.stdout == expected.stdout
    shutil.rmtree(install.libexec)


@pytest.mark.parametrize(
    "scenario", ["symlink", "hardlink", "writable", "owner", "bytecode", "entry"]
)
def test_runtime_verifier_rejects_nested_untrusted_paths(
    install: Install,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    status, output = install.confirm()
    assert status == 0, output
    (runtime,) = install.libexec.glob(".lhm-apt-security.*")
    monkeypatch.setattr(apt_runtime, "_ROOT_UID", os.geteuid())
    apt_runtime.verify_runtime_tree(runtime)
    stdlib = runtime / "python/lib/python3.15"
    if scenario == "symlink":
        (stdlib / "link").symlink_to("missing")
    elif scenario == "hardlink":
        (stdlib / "link").hardlink_to(runtime / "entry.py")
    elif scenario == "writable":
        (stdlib / "encodings").chmod(0o722)
    elif scenario == "owner":
        monkeypatch.setattr(apt_runtime, "_ROOT_UID", os.geteuid() + 1)
    elif scenario == "bytecode":
        (runtime / "src/lhm/worker.pyc").touch()
    else:
        (runtime / "entry.py").write_text("raise SystemExit(0)\n")
    with pytest.raises(DistroError, match="untrusted|entry point"):
        apt_runtime.verify_runtime_tree(runtime)


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("bad-artifact", "artifact digest mismatch"),
        ("linked-artifact", "unsafe artifact entry"),
        ("oversized-artifact", "artifact is too large"),
        ("bad-probe", "staged worker probe failed"),
        ("stale-probe", "staged worker protocol or build mismatch"),
        ("changed-template", "staged worker protocol or build mismatch"),
        ("writable-tree", "staged worker tree contains an untrusted path"),
        ("linked-tree", "staged worker tree contains an untrusted path"),
        ("hardlinked-tree", "staged worker tree contains an untrusted path"),
        ("dangling-target", "destination already exists"),
        ("late-conflict", "cannot publish launcher without replacing"),
        ("unsafe-parent", "untrusted directory"),
    ],
)
def test_refuses_unsafe_install(install: Install, scenario: str, message: str) -> None:
    if scenario == "bad-probe":
        (install.repo / "lhm/templates/apt-security.sources.tmpl").unlink()
        install.commit()
    elif scenario == "dangling-target":
        install.libexec.mkdir(mode=0o700)
        install.dest.symlink_to("missing")
    elif scenario == "unsafe-parent":
        install.libexec.mkdir()
        install.libexec.chmod(0o777)
    else:
        (install.work / "mode").write_text(scenario)
    status, output = install.confirm()
    assert status != 0 and message in output, output
    if scenario in {"dangling-target", "late-conflict"}:
        assert install.dest.readlink() == Path("missing")
        assert list(install.libexec.iterdir()) == [install.dest]
    else:
        assert list(install.libexec.iterdir()) == []
