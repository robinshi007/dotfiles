"""An isolated APT view sharing only the host's package state and dpkg locks."""

import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from lhm.core.apt_security import AptSecurity, _canonical_uri, _site
from lhm.core.distro import APT_TIMEOUT, DistroError

RUN = Path("/run")
DPKG_STATUS = "/var/lib/dpkg/status"
DPKG_AUDIT = """\
import subprocess
import sys

audit = subprocess.run(["/usr/bin/dpkg", "--audit"], capture_output=True, timeout=30)
if audit.returncode or audit.stdout.strip() or audit.stderr.strip():
    sys.exit("incomplete dpkg state; repair it explicitly before running lhm")
"""
MISSING_ONLY_HOOK = (
    DPKG_AUDIT
    + """\
if sys.stdin.readline().rstrip("\\n") != "VERSION 2":
    sys.exit("cannot verify APT's locked dpkg plan: expected protocol version 2")
for line in sys.stdin:
    if line == "\\n":
        break
else:
    sys.exit("incomplete APT hook header")
for line in sys.stdin:
    fields = line.rstrip("\\n").split(" ", 4)
    if len(fields) != 5:
        sys.exit("unrecognized APT dpkg action")
    package, old, direction, new, action = fields
    if not (old == "-" and direction == "<" and new != "-" and
            (action == "**CONFIGURE**" or (action.startswith("/") and action.endswith(".deb")))):
        sys.exit("security-only bootstrap refuses to change existing package: " + package)
"""
)
SOURCE_FIELDS = """\
Types: deb
URIs: {uri}
Suites: {suite}
Components: {components}
Architectures: {architecture}
Signed-By: {keyring}
"""


def _assert_run() -> None:
    if os.geteuid() != 0:
        raise DistroError("APT operations require a root-owned runtime directory")
    for directory in (RUN, *RUN.parents):
        mode = directory.lstat()
        if mode.st_uid != 0 or not stat.S_ISDIR(mode.st_mode) or mode.st_mode & 0o022:
            raise DistroError("APT operations require a root-owned runtime directory")


@dataclass(frozen=True)
class AptView:
    apt: AptSecurity
    root: Path
    uris: set[str]
    include_base: bool
    settings: dict[str, str]
    patterns: tuple[str, ...]
    probe: bool
    missing_only: bool

    @property
    def env(self) -> list[str]:
        return [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "LC_ALL=C",
            "DEBIAN_FRONTEND=noninteractive",
            f"APT_CONFIG={self.root / 'view.conf'}",
        ]

    @property
    def apt_get(self) -> list[str]:
        return [*self.env, "/usr/bin/apt-get"]

    def config_dump(self) -> str:
        return self.apt.runner.capture([*self.env, "/usr/bin/apt-config", "dump"])

    def verify_config(self) -> str:
        dump = self.config_dump()
        lines = set(dump.splitlines())
        if not all(f'{key} "{value}";' in lines for key, value in self.settings.items()):
            raise DistroError("effective APT paths or trust settings are not isolated")
        if (
            self.missing_only
            and sum(line.startswith("DPkg::Pre-Install-Pkgs:: ") for line in dump.splitlines()) != 1
        ):
            raise DistroError("unexpected changes to the locked dpkg plan guard")
        return dump

    def refresh(self) -> None:
        if self.probe:
            raise DistroError("read-only APT view cannot refresh or download")
        self.verify_config()
        self.apt.refresh(self.apt_get)
        self.apt.verify(
            self.uris,
            command=self.apt_get,
            lists=self.root / "lists",
            include_base=self.include_base,
        )

    def install(self, missing: list[str]) -> None:
        if self.probe or not self.include_base or not missing:
            raise DistroError("missing authenticated APT bootstrap view or package selection")
        self.verify_config()
        assert_dpkg_clean(self.apt)
        self.apt.runner.run(
            [*self.apt_get, "install", "--no-remove", "--no-upgrade", "-y", "-q", "--", *missing],
            timeout=APT_TIMEOUT,
        )

    def security_upgrade(self) -> None:
        if self.probe or self.include_base:
            raise DistroError("security-only upgrade cannot use a base repository")
        self.verify_config()
        assert_dpkg_clean(self.apt)
        self.apt.runner.run(
            [*self.apt_get, "upgrade", "--with-new-pkgs", "--no-remove", "-y", "-q"],
            timeout=APT_TIMEOUT,
        )


def assert_dpkg_clean(apt: AptSecurity) -> None:
    apt.runner.run(["/usr/bin/python3", "-I", "-c", DPKG_AUDIT], timeout=40.0)


@contextmanager
def isolated_view(
    apt: AptSecurity,
    uris: set[str],
    *,
    include_base: bool = False,
    probe: bool = False,
    missing_only: bool = False,
) -> Iterator[AptView]:
    """Create disposable trusted config; apt/pkgcache may only see these sources."""
    if not probe:
        _assert_run()
    if missing_only and not include_base:
        raise DistroError("missing-only policy requires a bootstrap view")
    if not uris or not apt.components:
        raise DistroError("cannot isolate APT without known security sources and components")
    all_sources = set()
    for uri in uris:
        canonical = _canonical_uri(uri)
        if canonical is None:
            raise DistroError("invalid URI in isolated APT view")
        all_sources.add((canonical, apt.release.suite))
    if include_base:
        all_sources.add((apt.release.base_uri, apt.release.codename))
    directory = None if probe else RUN
    with TemporaryDirectory(prefix="lhm-apt-", dir=directory) as temp:
        root = Path(temp)
        if not re.fullmatch(r"[/a-zA-Z0-9._-]+", temp):
            raise DistroError("unsafe isolated APT runtime path")
        # The root-owned namespace is writable only by root, but APT's _apt
        # sandbox must traverse it to reach its private download subdirectories.
        if not probe:
            root.chmod(0o711)
        for name in (
            "apt.conf.d",
            "sources.list.d",
            "trusted.gpg.d",
            "preferences.d",
            "auth.conf.d",
        ):
            (root / name).mkdir(mode=0o700)
        # APT, running as root, creates _apt-owned partial directories inside
        # these. mkdir's requested mode alone loses traversal under umask 077.
        for name in ("lists", "archives"):
            target = root / name
            target.mkdir(mode=0o700)
            if not probe:
                target.chmod(0o755)
        (root / "apt.conf").touch(mode=0o600)
        (root / "lhm.sources").write_text(
            "\n".join(
                SOURCE_FIELDS.format(
                    uri=uri,
                    suite=suite,
                    components=" ".join(apt.components),
                    architecture=apt.release.arch,
                    keyring=apt.release.keyring,
                )
                for uri, suite in sorted(all_sources)
            ),
            encoding="utf-8",
        )
        settings = {
            "Dir::Etc::parts": str(root / "apt.conf.d"),
            "Dir::Etc::main": str(root / "apt.conf"),
            "Dir::Etc::sourcelist": str(root / "lhm.sources"),
            "Dir::Etc::sourceparts": str(root / "sources.list.d"),
            "Dir::Etc::preferences": str(root / "preferences"),
            "Dir::Etc::preferencesparts": str(root / "preferences.d"),
            "Dir::Etc::trusted": str(root / "trusted.gpg"),
            "Dir::Etc::trustedparts": str(root / "trusted.gpg.d"),
            "Dir::Etc::netrc": str(root / "auth.conf"),
            "Dir::Etc::netrcparts": str(root / "auth.conf.d"),
            "Dir::State::lists": str(root / "lists"),
            "Dir::State::status": DPKG_STATUS,
            "Dir::Cache::archives": str(root / "archives"),
            "Dir::Cache::pkgcache": str(root / "pkgcache.bin"),
            "Dir::Cache::srcpkgcache": str(root / "srcpkgcache.bin"),
            "Dir::Bin::dpkg": "/usr/bin/dpkg",
            "Debug::NoLocking": "false",
            "APT::Architecture": apt.release.arch,
            "APT::Sandbox::User": "_apt",
            "APT::Get::AllowUnauthenticated": "false",
            "APT::Get::Fix-Broken": "false",
            "Acquire::AllowInsecureRepositories": "false",
            "Acquire::AllowWeakRepositories": "false",
            "Acquire::AllowDowngradeToInsecureRepositories": "false",
            "Acquire::Check-Date": "true",
            "Acquire::Check-Valid-Until": "true",
            "APT::Update::Error-Mode": "any",
        }
        audit_path = root / "clean-dpkg.py"
        audit_path.write_text(DPKG_AUDIT, encoding="utf-8")
        settings["DPkg::Pre-Invoke::"] = f"/usr/bin/python3 -I {audit_path}"
        patterns = tuple(apt.release.pattern(site) for site in sorted({_site(uri) for uri in uris}))
        if missing_only:
            # This is APT's real action set under its frontend lock, not a
            # simulation whose result can change before the install.
            hook_path = root / "missing-only.py"
            hook_path.write_text("#!/usr/bin/python3 -I\n" + MISSING_ONLY_HOOK, encoding="utf-8")
            hook_path.chmod(0o700)
            hook = str(hook_path)
            settings["DPkg::Pre-Install-Pkgs::"] = hook
            settings[f"DPkg::Tools::options::{hook}::Version"] = "2"
        if not include_base:
            settings.update(
                {
                    "Unattended-Upgrade::Remove-Unused-Kernel-Packages": "false",
                    "Unattended-Upgrade::Remove-New-Unused-Dependencies": "false",
                    "Unattended-Upgrade::Remove-Unused-Dependencies": "false",
                }
            )
        config = "".join(f'{key} "{value}";\n' for key, value in settings.items())
        config += 'APT::Architectures { "' + apt.release.arch + '"; };\n'
        if not include_base:
            config += "".join(
                f'Unattended-Upgrade::Origins-Pattern:: "{pattern}";\n' for pattern in patterns
            )
        config_path = root / "view.conf"
        config_path.touch(mode=0o600)
        config_path.write_text(config, encoding="utf-8")
        yield AptView(apt, root, uris, include_base, settings, patterns, probe, missing_only)
