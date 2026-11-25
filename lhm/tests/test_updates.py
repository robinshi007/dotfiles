import hashlib
import os
import pwd
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

from lhm import cli
from lhm.core import apt_security, apt_view
from lhm.core.distro import DistroError
from lhm.core.report import Status
from lhm.core.runner import Runner
from lhm.modules import updates

DEBIAN_URI = "http://security.debian.org/debian-security/"
INDEX_CMD = (
    "env LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get"
    " -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= indextargets"
)
FILTERS = "Created-By: Packages Target-Of: deb"
TARGET_CMD = f"{INDEX_CMD} {FILTERS}"
CONFIGURED_CMD = f"{INDEX_CMD} --no-release-info {FILTERS}"
UPDATE_CMD = "env LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get update"
POLICY = "o=Debian,l=Debian-Security,n=bookworm-security,site=security.debian.org"
DEBIAN_RELEASE = "Origin: Debian\nLabel: Debian-Security\nCodename: bookworm-security\n"
INDEX_DATA = b"Package: contested\nVersion: 1.0\n\n"
FIXTURES = Path(__file__).parent / "fixtures" / "apt"


def signed_release(
    meta: str = DEBIAN_RELEASE,
    *,
    arch: str = "amd64",
    age: timedelta = timedelta(),
    components: str = "main",
    digest: str | None = None,
    size: int = len(INDEX_DATA),
) -> str:
    date = format_datetime(datetime.now(UTC) - age)
    digest = digest or hashlib.sha256(INDEX_DATA).hexdigest()
    return (
        f"{meta}Date: {date}\nComponents: {components}\n"
        f"SHA256:\n {digest} {size} main/binary-{arch}/Packages\n"
    )


class AptFixture:
    def __init__(self, root: Path, fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self.exec = fake_exec
        self.downloads: list[bytes] = []
        self.private_policy_override = ""
        self.private_error = ""
        self.bootstrap_actions: str | None = None
        self.views: dict[Path, str] = {}
        self.conf = root / "apt.conf.d" / "51-lhm"
        self.conf.parent.mkdir()
        self.parts = root / "sources.list.d"
        self.parts.mkdir()
        self.keyring = root / "debian-archive-keyring.gpg"
        self.keyring.touch()
        self.base = self.parts / "base.sources"
        self.base.write_text(
            f"Types: deb\nURIs: http://deb.debian.org/debian/\nSuites: bookworm\n"
            f"Components: main\nSigned-By: {self.keyring}\n",
            encoding="utf-8",
        )
        self.source = self.parts / "debian.sources"
        self.source.write_text(
            f"Types: deb\nURIs: {DEBIAN_URI}\nSuites: bookworm-security\n"
            f"Components: main\nSigned-By: {self.keyring}\n",
            encoding="utf-8",
        )
        self.os_release = root / "os-release"
        self.os_release.write_text('ID=debian\nVERSION_CODENAME="bookworm"\n', encoding="utf-8")
        monkeypatch.setattr(apt_security, "KEYRINGS", root)
        monkeypatch.setattr(apt_security, "OS_RELEASE", self.os_release)
        monkeypatch.setattr(apt_view, "RUN", root)
        monkeypatch.setattr(apt_view, "_assert_run", lambda: None)

        def require_keyring(apt: apt_security.AptSecurity) -> None:
            if not apt.release.keyring.is_file():
                raise DistroError("missing test archive trust anchor")

        monkeypatch.setattr(apt_security.AptSecurity, "require_keyring", require_keyring)
        monkeypatch.setattr(updates, "APT_CONF", self.conf)
        monkeypatch.setattr(updates, "confirm_once", lambda plan: True)
        monkeypatch.setattr(updates, "configure_timer", lambda runner: False)
        monkeypatch.setattr(updates, "preflight_timer", lambda runner: None)
        monkeypatch.setattr(updates, "verify_timer", lambda runner: None)
        fake_exec.responses.extend(
            [
                ("apt-get --version", 0, "apt 2.6.1 (amd64)\n", ""),
                ("dpkg --print-architecture", 0, "amd64\n", ""),
                (
                    "apt-config shell PREF ",
                    0,
                    f"PREF='{root / 'preferences'}'\nPREFS='{root / 'preferences.d'}'\n",
                    "",
                ),
                ("apt-config shell", 0, f"PARTS='{self.parts}/'\n", ""),
                (CONFIGURED_CMD, 0, self.base_target() + "\n" + self.target(), ""),
                (TARGET_CMD, 0, self.index(), ""),
                ("gpgv --keyring", 0, signed_release(), ""),
                ("apt-config dump", 0, self.policy(), ""),
                ("dpkg-query", 0, "installed", ""),
                ("systemctl is-active unattended-upgrades", 0, "active\n", ""),
                ("systemctl is-enabled unattended-upgrades", 0, "enabled\n", ""),
            ]
        )

    def respond(self, cmd: str, out: str = "", rc: int = 0, err: str = "") -> None:
        if cmd == CONFIGURED_CMD:
            out = self.base_target() + "\n" + out
        self.exec.responses.insert(0, (cmd, rc, out, err))

    def base_target(self) -> str:
        return self.target("http://deb.debian.org/debian/", "bookworm", entry=f"{self.base}:1")

    def target(
        self,
        uri: str = DEBIAN_URI,
        suite: str = "bookworm-security",
        arch: str = "amd64",
        entry: str | None = None,
        component: str = "main",
    ) -> str:
        return (
            f"Repo-URI: {uri}\nRelease: {suite}\nArchitecture: {arch}\n"
            f"Sourcesentry: {entry or f'{self.source}:1'}\nComponent: {component}\n"
        )

    def index(
        self,
        target: str | None = None,
        release: str = DEBIAN_RELEASE,
        arch: str = "amd64",
        *,
        repo: str = "repo",
        data: bytes = INDEX_DATA,
    ) -> str:
        prefix = self.root / f"{repo}_dists_security_"
        filename = Path(f"{prefix}main_binary-{arch}_Packages")
        filename.write_bytes(data)
        Path(f"{prefix}InRelease").touch()
        return (
            f"{target or self.target()}{release}Trusted: yes\nFilename: {filename}\n"
            f"MetaKey: main/binary-{arch}/Packages\n"
        )

    def policy(self, pattern: str = POLICY) -> str:
        return f'Unattended-Upgrade::Origins-Pattern:: "{pattern}";\n'

    def _offline_indexes(self, root: Path) -> str:
        view_sources = root / "lhm.sources"
        records = apt_security._deb822(view_sources.read_text(encoding="utf-8"))
        targets = []
        for number, source in enumerate(records, 1):
            suite, arch = source["suites"], source["architectures"]
            security = suite.endswith("-security")
            if self.keyring.name.startswith("debian") and suite.startswith("bookworm"):
                label = "Debian-Security" if security else "Debian"
                meta = f"Origin: Debian\nLabel: {label}\nCodename: {suite}\n"
            else:
                meta = f"Origin: Ubuntu\nLabel: Ubuntu\nCodename: noble\nSuite: {suite}\n"
            artifact = FIXTURES / "security.payload"
            checksums = []
            for component in source["components"].split():
                key = f"{component}/binary-{arch}/Packages"
                prefix = root / "lists" / f"{number}_dists_{suite}_"
                filename = Path(f"{prefix}{key.replace('/', '_')}")
                data = (
                    INDEX_DATA.rstrip()
                    + f"\nFilename: {artifact.name}\n".encode()
                    + f"SHA256: {hashlib.sha256(artifact.read_bytes()).hexdigest()}\n".encode()
                )
                filename.write_bytes(data)
                checksums.append(f" {hashlib.sha256(data).hexdigest()} {len(data)} {key}\n")
                target = self.target(
                    source["uris"], suite, arch, f"{view_sources}:{number}", component
                )
                targets.append(
                    f"{target}{meta}Trusted: yes\nFilename: {filename}\nMetaKey: {key}\n"
                )
            date = format_datetime(datetime.now(UTC) - timedelta(days=0 if security else 180))
            Path(f"{prefix}InRelease").write_text(
                f"{meta}Date: {date}\nComponents: {source['components']}\n"
                "SHA256:\n" + "".join(checksums),
                encoding="utf-8",
            )
        return "\n".join(targets)

    def _execute(self, cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        config = next(
            (arg.removeprefix("APT_CONFIG=") for arg in cmd if arg.startswith("APT_CONFIG=")), None
        )
        if config is not None:
            self.exec.calls.append(cmd)
            root = Path(config).parent
            self.views[root] = (root / "lhm.sources").read_text(encoding="utf-8")
            if "/usr/bin/apt-config" in cmd:
                out = Path(config).read_text(encoding="utf-8") + self.private_policy_override
                return subprocess.CompletedProcess(cmd, 0, out, "")
            if "update" in cmd and self.private_error:
                return subprocess.CompletedProcess(cmd, 1, "", self.private_error)
            if "indextargets" in cmd:
                return subprocess.CompletedProcess(cmd, 0, self._offline_indexes(root), "")
            if "install" in cmd and self.bootstrap_actions is not None:
                script = (root / "missing-only.py").read_text(encoding="utf-8")
                return subprocess.run(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-c",
                        script.replace(apt_view.DPKG_AUDIT, "import sys\n"),
                    ],
                    input=self.bootstrap_actions,
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                )
            if "upgrade" in cmd:
                for index in (root / "lists").glob("*_Packages"):
                    fields = apt_security._deb822(index.read_text(encoding="utf-8"))[0]
                    artifact = (FIXTURES / fields["filename"]).read_bytes()
                    assert hashlib.sha256(artifact).hexdigest() == fields["sha256"]
                    self.downloads.append(artifact)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "/usr/bin/gpgv":
            if "lhm-apt-" in cmd[-1]:
                self.exec.calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, Path(cmd[-1]).read_text(), "")
            return self.exec(["gpgv", *cmd[1:]], timeout)
        return self.exec(cmd, timeout)

    def runner(self) -> Runner:
        return Runner(exec_fn=self._execute)

    def apply(self, *, security_only: bool = False) -> dict[str, Status]:
        return {
            r.name: r.status
            for r in updates.UpdatesModule().apply(self.runner(), security_only=security_only)
        }

    def commands(self) -> list[str]:
        return [" ".join(cmd) for cmd in self.exec.calls]


@pytest.fixture
def apt(tmp_path: Path, fake_exec: Any, monkeypatch: pytest.MonkeyPatch) -> AptFixture:
    return AptFixture(tmp_path, fake_exec, monkeypatch)


def test_dry_run_plans_without_commands(apt: AptFixture) -> None:
    runner = Runner(dry_run=True, exec_fn=apt.exec)
    results = updates.UpdatesModule().apply(runner, security_only=True)
    assert apt.exec.calls == []
    assert all(r.status is Status.PLANNED for r in results)
    assert any("isolated apt-get security upgrade" in r.name for r in results)
    assert not apt.conf.exists()


def test_normal_upgrade_remains_full_and_missing_tools_are_bootstrapped(apt: AptFixture) -> None:
    apt.conf.write_text(updates.desired_conf((POLICY,)), encoding="utf-8")
    for pkg in ("curl", "tmux", updates.PACKAGE, updates.HTTPS_PACKAGE):
        apt.respond(f"dpkg-query -W -f=${{db:Status-Status}} {pkg}", rc=1)
    results = apt.apply()
    assert results["apt update"] is Status.CHANGED
    assert results["verify security index"] is Status.OK
    assert results["apt upgrade"] is Status.CHANGED
    assert results["install missing packages"] is Status.CHANGED
    assert results["verify"] is Status.OK
    assert apt.conf.read_text(encoding="utf-8") == updates.desired_conf((POLICY,))
    assert not (apt.parts / apt_security.MANAGED_SOURCE).exists()
    executed = "\n".join(apt.commands())
    assert executed.index("apt-get update") < executed.index("gpgv --keyring")
    assert executed.index("gpgv --keyring") < executed.index("apt-get upgrade")
    assert executed.index("apt-get upgrade") < executed.index("/usr/bin/apt-get install")
    install = next(cmd for cmd in apt.exec.calls if "install" in cmd)
    assert "--no-remove" in install
    assert install[-3:] == ["unattended-upgrades", "curl", "tmux"]
    boot_config = next(arg for arg in install if arg.startswith("APT_CONFIG="))
    boot_root = Path(boot_config.removeprefix("APT_CONFIG=")).parent
    assert "Suites: bookworm\n" in apt.views[boot_root]
    assert "Suites: bookworm-security\n" in apt.views[boot_root]
    assert not boot_root.exists()


def test_security_only_bootstraps_in_separate_view_but_leaves_local_policy(apt: AptFixture) -> None:
    old = 'Unattended-Upgrade::Origins-Pattern:: "o=Local";\n'
    apt.conf.write_text(old, encoding="utf-8")
    apt.respond("dpkg-query -W -f=${db:Status-Status} unattended-upgrades", rc=1)
    apt.respond("apt-config dump", old)
    results = apt.apply(security_only=True)
    assert results["security upgrade"] is Status.CHANGED
    assert results["verify"] is Status.FAIL
    configs = [
        next(arg for arg in cmd if arg.startswith("APT_CONFIG="))
        for cmd in apt.exec.calls
        if "install" in cmd or "upgrade" in cmd
    ]
    assert len(set(configs)) == 2
    assert not any(
        cmd[:2] == ["env", "DEBIAN_FRONTEND=noninteractive"] and "upgrade" in cmd
        for cmd in apt.exec.calls
    )
    assert apt.conf.read_text(encoding="utf-8") == old
    assert not list(apt.conf.parent.glob("51-lhm.bak*"))


@pytest.mark.parametrize(
    "effective",
    [
        "",
        'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm";\n',
        'Unattended-Upgrade::Origins-Pattern:: "o=Debian";\n',
        'Unattended-Upgrade::Origins-Pattern::override "o=Debian";\n',
    ],
)
def test_normal_apply_and_query_refuse_missing_or_broadened_effective_policy(
    apt: AptFixture, effective: str
) -> None:
    desired = updates.desired_conf((POLICY,))
    apt.conf.write_text(desired, encoding="utf-8")
    local = apt.conf.with_name("99-local")
    local.write_text(effective, encoding="utf-8")
    apt.respond("apt-config dump", apt.policy() + effective if effective else "")
    result = apt.apply()
    assert result["apt upgrade"] is Status.CHANGED
    assert result["verify"] is Status.FAIL
    view = updates.inspect(apt.runner())
    assert view["apt_conf_current"] is False
    assert view["apt_policy_security_only"] is False
    assert "apt_policy_error" in view
    assert apt.conf.read_text(encoding="utf-8") == desired
    assert local.read_text(encoding="utf-8") == effective
    assert not any("noninteractive unattended-upgrade" in cmd for cmd in apt.commands())
    assert not any("apt-get install" in cmd for cmd in apt.commands())


def test_second_run_does_not_rewrite_current_config_or_install(apt: AptFixture) -> None:
    apt.conf.write_text(updates.desired_conf((POLICY,)), encoding="utf-8")
    results = apt.apply()
    assert results["verify"] is Status.OK
    assert not list(apt.conf.parent.glob("51-lhm.bak*"))
    assert not any("apt-get install" in cmd for cmd in apt.commands())


def test_refusal_makes_no_changes(apt: AptFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "confirm_once", lambda plan: False)
    assert apt.apply() == {"updates": Status.ABORTED}
    assert not apt.conf.exists()
    assert apt.commands() == []


def test_query_reports_private_runtime_as_unknown(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(runner: Runner) -> None:
        raise PermissionError("cannot traverse private runtime")

    monkeypatch.setattr(updates, "verify_timer", denied)
    state = updates.inspect(apt.runner())
    assert state["apt_conf_current"] is None
    assert state["apt_policy_security_only"] is None
    assert state["apt_downloads_isolated"] is None
    assert "unverified" in str(state["apt_policy_error"])
    _, rows, _, _ = cli._query_updates(apt.runner())
    assert ["effective security policy verified", "unknown"] in rows


@pytest.mark.parametrize(
    "policy",
    [
        'Unattended-Upgrade::Package-Blacklist:: "^example$";',
        'Unattended-Upgrade::Package-Whitelist:: "allowed";',
        'Unattended-Upgrade::Package-Whitelist-Strict "true";',
        "pins",
    ],
)
def test_admin_exclusions_stop_apply_and_timer_before_any_changes(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
) -> None:
    if policy == "pins":
        pins = apt.root / "preferences.d"
        pins.mkdir()
        (pins / "admin.pref").write_text(
            "Package: example\nPin: release *\nPin-Priority: -1\n", encoding="utf-8"
        )
    else:
        apt.respond("apt-config dump", apt.policy() + policy + "\n")
    monkeypatch.setattr(updates, "Runner", apt.runner)
    assert apt.apply() == {"updates": Status.FAIL}
    assert apt.apply(security_only=True) == {"updates": Status.FAIL}
    assert updates.automatic_main() == 1
    assert not any(
        "update" in cmd or "install" in cmd or "upgrade" in cmd for cmd in apt.exec.calls
    )
    assert not apt.conf.exists()


def test_verify_fails_when_timer_setup_fails(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def disabled(runner: Runner) -> bool:
        raise DistroError("apt-daily-upgrade.timer is disabled")

    monkeypatch.setattr(updates, "configure_timer", disabled)
    assert apt.apply()["verify"] is Status.FAIL


def test_inventory_is_read_only_and_legacy_https_still_reported_when_missing(
    apt: AptFixture,
) -> None:
    apt.respond("apt-get --version", "apt 1.4.11 (amd64)\n")
    apt.respond("dpkg-query -W -f=${db:Status-Status} apt-transport-https", rc=1)
    apt.respond("dpkg-query -W -f=${db:Status-Status} debian-archive-keyring", rc=1)
    inventory = updates.inspect(apt.runner())
    assert inventory["installed"] is True
    assert inventory["apt_transport_https_required"] is True
    assert inventory["packages"] == {
        package: package not in {"apt-transport-https", "debian-archive-keyring"}
        for package in (updates.PACKAGE, *updates.TOOLS, updates.HTTPS_PACKAGE, apt.keyring.stem)
    }
    assert not any("apt-get install" in c or "apt-get update" in c for c in apt.commands())
    assert apt.apply()["install missing packages"] is Status.CHANGED
    assert any(cmd.endswith("debian-archive-keyring apt-transport-https") for cmd in apt.commands())


def test_contested_version_downloads_only_authenticated_security_payload(
    apt: AptFixture,
) -> None:
    # Both repositories offer contested=1.0; origin filtering alone does not
    # constrain which repository APT will use for the candidate's download.
    alternate = apt.target("https://other.example/other/", "stable")
    third_party = apt.index(
        alternate,
        "Origin: Third Party\n",
        repo="other",
        data=INDEX_DATA.rstrip() + b"\nFilename: third-party.payload\n",
    )
    apt.respond(TARGET_CMD, apt.index() + "\n" + third_party)
    apt.conf.write_text(updates.desired_conf((POLICY,)), encoding="utf-8")
    assert updates.inspect(apt.runner())["apt_policy_security_only"] is True
    apt.exec.calls.clear()
    result = apt.apply(security_only=True)
    assert result["security upgrade"] is Status.CHANGED
    assert apt.downloads == [(FIXTURES / "security.payload").read_bytes()]
    assert apt.downloads[0] != (FIXTURES / "third-party.payload").read_bytes()
    assert all("other.example" not in sources for sources in apt.views.values())
    assert not any(
        cmd[:2] == ["env", "DEBIAN_FRONTEND=noninteractive"] and "upgrade" in cmd
        for cmd in apt.exec.calls
    )


def test_real_apt_parses_only_private_sources_without_fetching(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("apt-get") is None:
        pytest.skip("APT binaries are unavailable")
    monkeypatch.setenv("APT_CONFIG", str(apt.root / "not-the-private-config"))
    discovery = apt_security.AptSecurity(apt.runner())
    discovery.sources()
    discovery.runner = Runner()
    with apt_view.isolated_view(
        discovery, {DEBIAN_URI}, include_base=True, probe=True, missing_only=True
    ) as view:
        dump = view.verify_config()
        assert f'Dir::State::status "{apt_view.DPKG_STATUS}";' in dump
        assert not list((view.root / "archives").iterdir())
        assert not list((view.root / "sources.list.d").iterdir())
        assert not discovery._targets(command=view.apt_get)
        configured = discovery._targets(configured=True, command=view.apt_get)
        assert {(row["repo-uri"], row["release"]) for row in configured} == {
            (DEBIAN_URI, "bookworm-security"),
            ("http://deb.debian.org/debian/", "bookworm"),
        }
        assert {Path(row["sourcesentry"].rsplit(":", 1)[0]) for row in configured} == {
            view.root / "lhm.sources",
        }


def test_apt_download_paths_are_searchable_under_private_umask(apt: AptFixture) -> None:
    discovery = apt_security.AptSecurity(apt.runner())
    discovery.sources()
    with TemporaryDirectory(prefix="lhm-apt-access-") as tmp:
        outer = Path(tmp)
        outer.chmod(0o711)
        # Fake execution still uses the real filesystem permissions.
        original = apt_view.RUN
        old_umask = os.umask(0o077)
        try:
            apt_view.RUN = outer
            with apt_view.isolated_view(discovery, {DEBIAN_URI}) as view:
                assert stat.S_IMODE(view.root.stat().st_mode) == 0o711
                for name in ("lists", "archives"):
                    assert stat.S_IMODE((view.root / name).stat().st_mode) == 0o755
                assert stat.S_IMODE((view.root / "apt.conf.d").stat().st_mode) == 0o700
                if os.geteuid() != 0 or shutil.which("setpriv") is None:
                    return  # UID-switching probe is available in a root test container.
                sandbox = pwd.getpwnam("_apt")
                subprocess.run(
                    [
                        "/usr/bin/setpriv",
                        "--reuid",
                        str(sandbox.pw_uid),
                        "--regid",
                        str(sandbox.pw_gid),
                        "--clear-groups",
                        "/usr/bin/python3",
                        "-I",
                        "-c",
                        "import os, sys; assert all(os.access(p, os.X_OK) for p in sys.argv[1:3]); "
                        "assert not os.access(sys.argv[3], os.X_OK)",
                        str(view.root / "lists"),
                        str(view.root / "archives"),
                        str(view.root / "apt.conf.d"),
                    ],
                    check=True,
                    timeout=10,
                )
        finally:
            os.umask(old_umask)
            apt_view.RUN = original


def test_real_apt_prints_only_the_security_uri_and_hash_for_a_contested_version(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("apt-get") is None:
        pytest.skip("APT binaries are unavailable")
    discovery = apt_security.AptSecurity(apt.runner())
    discovery.sources()
    discovery.runner = Runner()
    pkg = "lhm-offline-contested"
    third_party = "https://third-party.invalid/debian/"
    with (
        apt_view.isolated_view(discovery, {third_party}, probe=True) as outside,
        apt_view.isolated_view(discovery, {DEBIAN_URI}, probe=True) as scoped,
    ):
        for view, payload in ((outside, "third-party.payload"), (scoped, "security.payload")):
            index = next(
                row
                for row in discovery._targets(configured=True, command=view.apt_get)
                if row["architecture"] == "amd64"
            )
            data = (FIXTURES / payload).read_bytes()
            Path(index["filename"]).write_text(
                f"Package: {pkg}\nVersion: 1.0\nArchitecture: amd64\n"
                f"Filename: pool/{payload}\nSize: {len(data)}\n"
                f"SHA256: {hashlib.sha256(data).hexdigest()}\nDescription: Offline fixture\n",
                encoding="utf-8",
            )
        monkeypatch.setenv("APT_CONFIG", str(outside.root / "view.conf"))
        args = ["--print-uris", "download", f"{pkg}=1.0"]
        outside_result = discovery.runner.capture([*outside.apt_get, *args])
        assert f"{third_party}pool/third-party.payload" in outside_result
        scoped_result = discovery.runner.capture([*scoped.apt_get, *args])
        assert f"{DEBIAN_URI}pool/security.payload" in scoped_result
        assert hashlib.sha256((FIXTURES / "security.payload").read_bytes()).hexdigest() in (
            scoped_result
        )
        assert "third-party" not in scoped_result


@pytest.mark.parametrize("failure", ["refresh", "policy"])
def test_private_view_failure_never_falls_back(apt: AptFixture, failure: str) -> None:
    if failure == "refresh":
        apt.private_error = "signed security refresh failed"
    else:
        apt.private_policy_override = 'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm";'
    result = apt.apply(security_only=True)
    assert result["updates"] is Status.FAIL
    assert not any("apt-get upgrade" in cmd for cmd in apt.commands())
    assert not apt.downloads


@pytest.mark.parametrize("installed_dependency", [False, True])
def test_security_bootstrap_checks_live_locked_dpkg_plan(
    apt: AptFixture,
    installed_dependency: bool,
) -> None:
    apt.respond("dpkg-query -W -f=${db:Status-Status} unattended-upgrades", rc=1)
    old = "1.0" if installed_dependency else "-"
    apt.bootstrap_actions = (
        "VERSION 2\nDir::State::status=/var/lib/dpkg/status\n\n"
        f"dependency {old} < 2.0 /archives/dependency_2.0_amd64.deb\n"
        "unattended-upgrades - < 3.0 /archives/unattended-upgrades_3.0_all.deb\n"
        "unattended-upgrades - < 3.0 **CONFIGURE**\n"
    )
    results = apt.apply(security_only=True)
    if installed_dependency:
        assert results["updates"] is Status.FAIL
        assert not apt.downloads
    else:
        assert results["install missing packages"] is Status.CHANGED
        assert results["security upgrade"] is Status.CHANGED


@pytest.mark.parametrize("installed_dependency", [False, True])
def test_real_offline_apt_bootstrap_hook_blocks_existing_dependency_upgrade(
    apt: AptFixture,
    installed_dependency: bool,
) -> None:
    tools = tuple(shutil.which(tool) for tool in ("apt-get", "dpkg-deb", "dpkg-scanpackages"))
    if not all(tools):
        pytest.skip("offline APT fixture utilities are unavailable")
    discovery = apt_security.AptSecurity(apt.runner())
    discovery.sources()
    discovery.runner = Runner()
    with apt_view.isolated_view(
        discovery, {DEBIAN_URI}, include_base=True, missing_only=True, probe=True
    ) as view:
        root = view.root
        status = root / "status"
        repo = root / "fixture-repo"
        repo.mkdir()
        logs = root / "logs"
        logs.mkdir()
        dep, package = "lhm-fixture-dependency", "lhm-fixture-tool"

        def control(name: str, version: str) -> str:
            return (
                f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
                "Maintainer: LHM <fixture@example.invalid>\nDescription: offline fixture\n"
            )

        status.write_text(
            control(dep, "1.0") + "Status: install ok installed\n" if installed_dependency else "",
            encoding="utf-8",
        )
        for name, requirement in ((dep, ""), (package, f"Depends: {dep} (>= 2.0)\n")):
            build = root / name
            (build / "DEBIAN").mkdir(parents=True)
            (build / "DEBIAN/control").write_text(control(name, "2.0") + requirement)
            discovery.runner.run(
                ["/usr/bin/dpkg-deb", "--build", str(build), str(repo / f"{name}.deb")]
            )
        scan = subprocess.run(
            ["/usr/bin/dpkg-scanpackages", "."],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
            timeout=20,
        )
        (repo / "Packages").write_text(scan.stdout, encoding="utf-8")
        (root / "lhm.sources").write_text(
            f"Types: deb\nURIs: file:{repo}/\nSuites: ./\nTrusted: yes\n", encoding="utf-8"
        )
        fake_dpkg = root / "dpkg"
        dpkg_log = logs / "dpkg.log"
        dpkg_log.touch()
        fake_dpkg.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {dpkg_log}\n', encoding="utf-8")
        fake_dpkg.chmod(0o700)
        # Never attempt host dpkg maintenance, locks, logging, writes, or network.
        (root / "clean-dpkg.py").write_text("", encoding="utf-8")
        hook = root / "missing-only.py"
        hook.write_text(hook.read_text().replace(apt_view.DPKG_AUDIT, "import sys\n"))
        with (root / "view.conf").open("a", encoding="utf-8") as config:
            config.write(
                f'\nDir::State "{root}";\nDir::State::status "{status}";'
                f'\nDir::State::extended_states "{root}/extended";'
                f'\nDir::Bin::dpkg "{fake_dpkg}";\nDir::Log "{logs}";\n'
                'Acquire::Languages "none";\n'
            )
        discovery.runner.run([*view.apt_get, "update"])
        result = discovery.runner.run(
            [*view.apt_get, "install", "--no-upgrade", "--no-remove", "-y", package],
            check=False,
        )
        if installed_dependency:
            assert not result.ok
            assert f"security-only bootstrap refuses to change existing package: {dep}" in (
                result.stderr
            )
            assert "--unpack" not in dpkg_log.read_text()
        else:
            assert result.ok, result.stderr
            assert "--unpack" in dpkg_log.read_text()


def test_helper_and_interrupted_dpkg_checks_precede_any_apt_mutation(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def untrusted(runner: Runner) -> None:
        raise DistroError("bad helper provenance")

    with monkeypatch.context() as patch:
        patch.setattr(updates, "preflight_timer", untrusted)
        assert apt.apply() == {"updates": Status.FAIL}
        assert not apt.commands()
    apt.respond("/usr/bin/python3 -I -c", rc=1, err="incomplete dpkg")
    assert apt.apply() == {"updates": Status.FAIL}
    assert not any("apt-get update" in cmd or "apt-get upgrade" in cmd for cmd in apt.commands())


@pytest.mark.parametrize("signed_empty", [False, True])
def test_missing_index_is_allowed_only_for_cryptographically_proven_empty(
    apt: AptFixture,
    signed_empty: bool,
) -> None:
    filename = apt.root / "repo_dists_security_main_binary-amd64_Packages"
    filename.unlink()
    apt.respond(
        CONFIGURED_CMD,
        apt.target() + f"Filename: {filename}\nMetaKey: main/binary-amd64/Packages\n",
    )
    apt.respond(TARGET_CMD, "")
    if signed_empty:
        apt.respond("gpgv", signed_release(digest=hashlib.sha256(b"").hexdigest(), size=0))
        assert apt.apply()["verify security index"] is Status.OK
    else:
        assert apt.apply() == {"apt update": Status.CHANGED, "updates": Status.FAIL}


@pytest.mark.parametrize(
    "failure",
    ["stale", "missing", "untrusted", "wrong-signer", "wrong-meta", "expired", "hash", "size"],
)
def test_invalid_refresh_or_index_stops_before_upgrades(apt: AptFixture, failure: str) -> None:
    if failure == "stale":
        apt.respond(UPDATE_CMD, err="W: Some index files failed to download")
    elif failure == "missing":
        apt.respond(TARGET_CMD, "")
    elif failure == "untrusted":
        apt.respond(TARGET_CMD, apt.index().replace("Trusted: yes", "Trusted: no"))
    elif failure == "wrong-signer":
        apt.respond("gpgv", rc=2, err="No public key")
    elif failure == "expired":
        apt.respond("gpgv", signed_release(age=timedelta(days=8)))
    elif failure == "hash":
        (apt.root / "repo_dists_security_main_binary-amd64_Packages").write_bytes(
            INDEX_DATA.replace(b"1.0", b"2.0")
        )
    elif failure == "size":
        apt.respond("gpgv", signed_release(size=len(INDEX_DATA) + 1))
    else:
        apt.respond("gpgv", signed_release(DEBIAN_RELEASE.replace("Debian-Security", "Other")))
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get upgrade" in cmd or "apt-get install" in cmd for cmd in apt.commands())
    assert not apt.conf.exists()


@pytest.mark.parametrize(
    "option",
    ["Trusted: yes", "Check-Valid-Until: no", "Signed-By: /etc/apt/keyrings/third-party.gpg"],
)
def test_conflicting_source_stops_before_refresh(apt: AptFixture, option: str) -> None:
    contents = apt.source.read_text(encoding="utf-8")
    if option.startswith("Signed-By:"):
        contents = contents.removesuffix(f"Signed-By: {apt.keyring}\n")
    apt.source.write_text(contents + option + "\n", encoding="utf-8")
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get update" in cmd for cmd in apt.commands())


@pytest.mark.parametrize("suite", ["stable-security", "bullseye-security"])
def test_mismatched_official_security_suite_stops(apt: AptFixture, suite: str) -> None:
    apt.respond(CONFIGURED_CMD, apt.target(suite=suite))
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get update" in cmd for cmd in apt.commands())


def test_second_source_cannot_shadow_the_security_site_policy(apt: AptFixture) -> None:
    alternate = apt.target("https://security.debian.org:8443/other/", "stable")
    apt.respond(TARGET_CMD, apt.index() + "\n" + apt.index(alternate))
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get upgrade" in cmd for cmd in apt.commands())


@pytest.mark.parametrize(("scheme", "port"), [("https", 443), ("http", 80)])
def test_default_port_accepts_exact_scoped_uri_without_broadening_site(
    apt: AptFixture, scheme: str, port: int
) -> None:
    uri = f"{scheme}://security.debian.org:{port}/debian-security/"
    apt.respond(CONFIGURED_CMD, apt.target(uri))
    apt.respond(TARGET_CMD, apt.index(apt.target(uri.replace(f":{port}/", "/"))))
    apt.conf.write_text(updates.desired_conf((POLICY,)), encoding="utf-8")
    assert apt.apply()["verify"] is Status.OK


@pytest.mark.parametrize(
    "authority",
    [
        "security.debian.org:80",
        "security.debian.org:0443",
        "security.debian.org:8443",
        "user@security.debian.org:443",
        "security.debian.org.evil.invalid:443",
    ],
)
def test_noncanonical_or_unscoped_security_authority_is_not_trusted(
    apt: AptFixture, authority: str
) -> None:
    if authority.endswith(".invalid:443"):
        apt.source.write_text(
            apt.source.read_text(encoding="utf-8").removesuffix(f"Signed-By: {apt.keyring}\n"),
            encoding="utf-8",
        )
    apt.respond(CONFIGURED_CMD, apt.target(f"https://{authority}/debian-security/"))
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get update" in cmd for cmd in apt.commands())


def test_official_uri_also_requires_persistent_signed_by(apt: AptFixture) -> None:
    apt.source.write_text(
        apt.source.read_text(encoding="utf-8").removesuffix(f"Signed-By: {apt.keyring}\n"),
        encoding="utf-8",
    )
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get update" in cmd for cmd in apt.commands())


@pytest.mark.parametrize("scoped", [False, True])
def test_mirror_requires_distro_keyring_scope(apt: AptFixture, scoped: bool) -> None:
    mirror = "https://mirror.example/debian-security/"
    apt.source = apt.root / "sources.list"
    options = f"[arch=amd64 signed-by={apt.keyring}] " if scoped else ""
    apt.source.write_text(
        f"# mirror\n deb {options}{mirror} bookworm-security main\n", encoding="utf-8"
    )
    apt.respond(CONFIGURED_CMD, apt.target(mirror, entry=f"{apt.source}:2"))
    apt.respond(TARGET_CMD, apt.index(apt.target(mirror, entry=f"{apt.source}:2")))
    results = apt.apply()
    if scoped:
        assert results["verify security index"] is Status.OK
        assert not apt.conf.exists()
    else:
        assert results["updates"] is Status.FAIL
        assert not any("apt-get update" in cmd for cmd in apt.commands())


@pytest.mark.parametrize("expired", [False, True])
def test_ubuntu_ports_managed_source_matches_base_and_checks_date_without_valid_until(
    apt: AptFixture,
    monkeypatch: pytest.MonkeyPatch,
    expired: bool,
) -> None:
    apt.os_release.write_text("ID=ubuntu\nVERSION_CODENAME=noble\n", encoding="utf-8")
    keyring = apt.root / "ubuntu-archive-keyring.gpg"
    keyring.touch()
    apt.respond("dpkg --print-architecture", "arm64\n")
    apt.respond("dpkg-query -W -f=${db:Status-Status} ubuntu-keyring", rc=1)
    managed = apt.parts / apt_security.MANAGED_SOURCE
    uri = "http://ports.ubuntu.com/ubuntu-ports/"
    apt.base.write_text(
        f"Types: deb\nURIs: {uri}\nSuites: noble\nComponents: main universe\n"
        f"Signed-By: {keyring}\n",
        encoding="utf-8",
    )
    base = "\n".join(
        apt.target(uri, "noble", "arm64", f"{apt.base}:1", component)
        for component in ("main", "universe")
    )
    target = apt.target(uri, "noble-security", "arm64", f"{managed}:1")
    release = "Origin: Ubuntu\nLabel: Ubuntu\nCodename: noble\nSuite: noble-security\n"
    apt.respond(TARGET_CMD, apt.index(target, release, "arm64"))
    # Universe is enabled in base but not advertised by this signed Release.
    apt.respond(
        "gpgv", signed_release(release, arch="arm64", age=timedelta(days=8 if expired else 0))
    )
    capture = Runner.capture
    existing = apt.source.read_bytes()

    def fake_capture(self: Runner, cmd: list[str], timeout: float = 30.0) -> str:
        if "--no-release-info" in cmd:
            return base + "\n" + (target if managed.exists() else apt.target(arch="amd64"))
        return capture(self, cmd, timeout)

    monkeypatch.setattr(Runner, "capture", fake_capture)
    results = apt.apply()
    assert results[f"write {managed}"] is Status.CHANGED
    text = managed.read_text(encoding="utf-8")
    assert f"URIs: {uri}\nSuites: noble-security\n" in text
    assert f"Architectures: arm64\nSigned-By: {keyring}\n" in text
    assert "Components: main universe\n" in text
    assert apt.source.read_bytes() == existing
    assert not apt.conf.exists()
    if expired:
        assert results["updates"] is Status.FAIL
        assert not any("apt-get upgrade" in cmd for cmd in apt.commands())
    else:
        assert results["verify security index"] is Status.OK
        assert results["install missing packages"] is Status.CHANGED
        assert any(
            "URIs: http://ports.ubuntu.com/ubuntu-ports/\nSuites: noble\n" in src
            for src in apt.views.values()
        )


def test_security_index_must_cover_enabled_and_supported_components(apt: AptFixture) -> None:
    base_extra = apt.target(
        "http://deb.debian.org/debian/", "bookworm", entry=f"{apt.base}:1", component="contrib"
    )
    apt.respond(CONFIGURED_CMD, apt.target() + "\n" + base_extra)
    apt.respond("gpgv", signed_release(components="updates/main updates/contrib"))
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get upgrade" in cmd for cmd in apt.commands())


def test_missing_trust_anchor_does_not_bootstrap_from_unverified_sources(apt: AptFixture) -> None:
    apt.keyring.unlink()
    assert apt.apply()["updates"] is Status.FAIL
    assert not any("apt-get update" in cmd or "apt-get install" in cmd for cmd in apt.commands())


def test_detached_release_is_verified_with_distro_keyring(apt: AptFixture) -> None:
    (apt.root / "repo_dists_security_InRelease").unlink()
    detached = apt.root / "repo_dists_security_Release"
    detached.write_text(signed_release(), encoding="utf-8")
    signature = detached.with_suffix(".gpg")
    signature.touch()
    assert apt.apply()["verify security index"] is Status.OK
    assert f"gpgv --keyring {apt.keyring} {signature} {detached}" in apt.commands()
