"""Compatibility and trust contract for the independently installed APT worker."""

import hashlib
import os
import stat
from pathlib import Path

PROTOCOL = "lhm-apt-security-v1"
_ROOT_UID = 0
LAUNCHER = (
    "#!/bin/sh\nset -eu\numask 022\ncd /\n"
    'runtime="{runtime}"\n'
    "exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root \\\n"
    '    "$runtime/python/bin/python3.15" -I -S -B "$runtime/entry.py" "$@"\n'
)
ENTRYPOINT = """\
import sys
from pathlib import Path

root = Path(__file__).parent
prefix = str(root / "python")
if (
    sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 15)
    or (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix) != (prefix,) * 4
    or not all(path.startswith(prefix + "/") for path in sys.path)
):
    raise SystemExit("lhm apt-daily: invalid private interpreter prefix")
sys.path.append(str(root / "src"))
from lhm.core.apt_runtime import worker_main

raise SystemExit(worker_main(sys.argv[1:]))
"""


def runtime_identity(root: Path | None = None) -> str:
    """Fingerprint the same release paths in a wheel, checkout or archived worker."""
    if root is None:
        from lhm.core.files import TEMPLATES_DIR

        sources = Path(__file__).resolve().parents[1]
        templates = TEMPLATES_DIR
    else:
        sources = root / "src/lhm"
        templates = root / "templates"
    if not sources.is_dir() or not templates.is_dir():
        raise FileNotFoundError("cannot identify APT worker release: missing sources or templates")
    digest = hashlib.sha256()
    for directory, prefix, pattern in (
        (sources, "src/lhm", "*.py"),
        (templates, "templates", "*.tmpl"),
    ):
        for path in sorted(directory.rglob(pattern)):
            if path.is_file():
                rel = path.relative_to(directory).as_posix()
                digest.update(os.fsencode(f"{prefix}/{rel}") + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return f"{PROTOCOL} {digest.hexdigest()}"


def verify_runtime_tree(runtime: Path) -> None:
    """Refuse any untrusted path in the runtime before executing its interpreter.

    The caller must first verify the runtime path and all its ancestors.
    """
    from lhm.core.distro import DistroError

    pending = [runtime]
    while pending:
        path = pending.pop()
        info = path.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        regular = stat.S_ISREG(info.st_mode)
        parts = path.relative_to(runtime).parts
        top = parts[0] if parts else ""
        if (
            info.st_uid != _ROOT_UID
            or info.st_mode & 0o7022
            or not (directory or (regular and info.st_nlink == 1))
            or (not parts and not directory)
            or (parts and top not in {"python", "src", "templates", "entry.py"})
            or (top == "entry.py" and not regular)
            or (top == "src" and len(parts) > 1 and parts[1] != "lhm")
            or (top == "src" and not directory and path.suffix != ".py")
            or (top == "templates" and not directory and path.suffix != ".tmpl")
        ):
            raise DistroError(f"untrusted APT worker runtime path: {path}")
        if directory:
            pending.extend(path.iterdir())
    if (runtime / "entry.py").read_bytes() != ENTRYPOINT.encode("ascii"):
        raise DistroError("APT worker entry point does not match this release")


def worker_main(args: list[str]) -> int:
    """Probe imports/templates without APT, or enter the isolated scheduled path."""
    from lhm.core.files import render_template
    from lhm.modules.updates import automatic_main

    if args == ["--probe"]:
        render_template("unattended-upgrades.conf.tmpl")
        render_template(
            "apt-security.sources.tmpl",
            uri="uri",
            suite="suite",
            arch="arch",
            keyring="keyring",
            components="components",
        )
        if not callable(automatic_main):
            raise SystemExit("lhm apt-daily: missing automatic worker")
        print(runtime_identity())
        return 0
    if args:
        raise SystemExit("lhm apt-daily: unexpected arguments")
    return automatic_main()
