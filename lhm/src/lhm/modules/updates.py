"""Refresh and verify the APT security pocket before applying updates."""

import re
import shlex
from pathlib import Path

from lhm.core.apt_security import AptSecurity, Release
from lhm.core.apt_timer import configure_timer, preflight_timer, verify_timer
from lhm.core.apt_view import assert_dpkg_clean, isolated_view
from lhm.core.confirm import confirm_once
from lhm.core.distro import AptBackend, DistroError
from lhm.core.files import render_template, write_dropin
from lhm.core.mutations import mutations_allowed
from lhm.core.report import Status, StepResult
from lhm.core.runner import CommandError, Runner

PACKAGE = "unattended-upgrades"
TOOLS = ("ca-certificates", "curl", "gnupg", "git", "tmux", "vim")
HTTPS_PACKAGE = "apt-transport-https"
TEMPLATE = "unattended-upgrades.conf.tmpl"
SOURCE_TEMPLATE = "apt-security.sources.tmpl"
APT_CONF = Path("/etc/apt/apt.conf.d/51-lhm")


def _read_conf() -> str | None:
    try:
        return APT_CONF.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def desired_conf(patterns: tuple[str, ...]) -> str:
    return render_template(TEMPLATE) + "".join(
        f'Unattended-Upgrade::Origins-Pattern:: "{pattern}";\n' for pattern in patterns
    )


def _inventory(apt: AptSecurity) -> dict[str, bool]:
    installed = {}
    for package in (PACKAGE, *TOOLS, apt.release.keyring_package, HTTPS_PACKAGE):
        result = apt.runner.run(
            ["dpkg-query", "-W", "-f=${db:Status-Status}", package], timeout=60.0, check=False
        )
        if result.returncode not in {0, 1}:
            raise CommandError(result)
        installed[package] = result.ok and result.stdout.strip() == "installed"
    return installed


def inspect(runner: Runner, *, probe_package: bool = True) -> dict[str, object]:
    """Read-only state used by ``query updates`` and ``check``."""
    state: dict[str, object] = {
        "package": PACKAGE,
        "installed": None,
        "packages": {},
        "apt_conf": str(APT_CONF),
        "apt_conf_current": None,
        "apt_legacy_conf_current": False,
        "apt_policy_security_only": None,
        "apt_legacy_policy_security_only": None,
        "apt_downloads_isolated": None,
    }
    if not probe_package or runner.dry_run or not mutations_allowed():
        return state
    try:
        apt = AptSecurity(runner)
        packages = _inventory(apt)
    except (CommandError, OSError, ValueError) as exc:
        raise DistroError(str(exc)) from exc
    state.update(
        installed=packages[PACKAGE],
        packages=packages,
        apt_transport_https_required=apt.legacy_https,
    )
    try:
        apt.require_keyring()
        uris = apt.sources()
        state["security_sources"] = sorted(uris)
        if uris:
            try:
                sites = apt.verify(uris)
                state["security_index_verified"] = True
                patterns = tuple(apt.release.pattern(site) for site in sites)
            except (CommandError, DistroError, OSError, ValueError) as exc:
                state["security_source_error"] = str(exc)
                state["security_index_verified"] = False
                patterns = ()
            legacy = _read_conf()
            if legacy is not None:
                try:
                    _verify_policy(runner.capture(["apt-config", "dump"]), patterns)
                    state["apt_legacy_policy_security_only"] = True
                    state["apt_legacy_conf_current"] = legacy == desired_conf(patterns)
                except (CommandError, DistroError, OSError, ValueError) as exc:
                    state["apt_legacy_policy_security_only"] = False
                    state["apt_legacy_policy_error"] = str(exc)
            try:
                _verify_automatic(apt, uris)
                state["apt_downloads_isolated"] = True
                if state["apt_legacy_policy_security_only"] is False:
                    raise DistroError(str(state["apt_legacy_policy_error"]))
                state["apt_policy_security_only"] = True
                state["apt_conf_current"] = True
            except PermissionError:
                state["apt_policy_error"] = "private apt-daily runtime unverified; retry as root"
            except (CommandError, DistroError, OSError, ValueError) as exc:
                state["apt_conf_current"] = False
                state["apt_policy_security_only"] = False
                if state["apt_downloads_isolated"] is None:
                    state["apt_downloads_isolated"] = False
                state["apt_policy_error"] = str(exc)
    except (CommandError, DistroError, OSError, ValueError) as exc:
        state["security_source_error"] = str(exc)
    return state


def _write_source(path: Path, release: Release, components: tuple[str, ...]) -> None:
    if path.exists() or path.is_symlink():
        raise DistroError(f"managed APT security source already exists but is ineffective: {path}")
    write_dropin(
        path,
        render_template(
            SOURCE_TEMPLATE,
            uri=release.uri,
            suite=release.suite,
            arch=release.arch,
            keyring=str(release.keyring),
            components=" ".join(components),
        ),
    )


def _verify_policy(dump: str, patterns: tuple[str, ...]) -> None:
    effective = []
    for line in dump.splitlines():
        if not line.lower().startswith(
            ("unattended-upgrade::allowed-origins", "unattended-upgrade::origins-pattern")
        ):
            continue
        match = re.fullmatch(
            r'Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)(::)? "([^"]*)";',
            line,
            re.IGNORECASE,
        )
        if match is None:
            raise DistroError("cannot verify effective unattended-upgrades origin policy")
        name, child, value = match.groups()
        if name.lower() == "origins-pattern" and child:
            effective.append(value)
        elif value:
            raise DistroError("effective unattended-upgrades origin policy is not security-only")
    if not patterns or sorted(effective) != sorted(patterns):
        raise DistroError("effective unattended-upgrades origin policy is not security-only")


def _reject_admin_exclusions(runner: Runner) -> None:
    for line in runner.capture(["apt-config", "dump"]).splitlines():
        if not re.match(r"unattended-upgrade::package-(blacklist|whitelist)", line, re.I):
            continue
        if re.fullmatch(r'Unattended-Upgrade::Package-(?:Blacklist|Whitelist) "";', line, re.I):
            continue
        if re.fullmatch(
            r'Unattended-Upgrade::Package-Whitelist-Strict "(?:false|no|0|)";', line, re.I
        ):
            continue
        raise DistroError("local unattended package exclusions are unsupported by isolated APT")
    output = runner.capture(
        [
            "apt-config",
            "shell",
            "PREF",
            "Dir::Etc::preferences/f",
            "PREFS",
            "Dir::Etc::preferencesparts/d",
        ]
    )
    words = shlex.split(output)
    paths = dict(word.split("=", 1) for word in words if "=" in word)
    if (
        len(words) != 2
        or set(paths) != {"PREF", "PREFS"}
        or not all(Path(p).is_absolute() for p in paths.values())
    ):
        raise DistroError("cannot verify the host's APT pinning policy")
    candidates = [Path(paths["PREF"])]
    try:
        candidates.extend(
            path
            for path in Path(paths["PREFS"]).iterdir()
            if path.suffix in {"", ".pref"} and re.fullmatch(r"[a-zA-Z0-9_.-]+", path.name)
        )
    except FileNotFoundError:
        pass
    for path in candidates:
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError, IsADirectoryError:
            continue
        if any(line.strip() and not line.lstrip().startswith("#") for line in lines):
            raise DistroError(f"local APT pinning is unsupported by isolated APT: {path}")


def _verify_automatic(apt: AptSecurity, uris: set[str]) -> None:
    verify_timer(apt.runner)
    _reject_admin_exclusions(apt.runner)
    with isolated_view(apt, uris, probe=True) as view:
        _verify_policy(view.verify_config(), view.patterns)


def _security_upgrade(apt: AptSecurity, uris: set[str]) -> None:
    with isolated_view(apt, uris) as view:
        view.refresh()
        _verify_policy(view.verify_config(), view.patterns)
        _reject_admin_exclusions(apt.runner)
        view.security_upgrade()


def automatic_main() -> int:
    """Entry point for the independently installed root-owned apt-daily worker."""
    try:
        apt = AptSecurity(Runner())
        _reject_admin_exclusions(apt.runner)
        uris = apt.sources()
        apt.require_keyring()
        if not uris:
            raise DistroError("no persistently scoped security source for apt-daily")
        _security_upgrade(apt, uris)
    except (CommandError, DistroError, OSError, ValueError) as exc:
        print(f"lhm apt-daily: {exc}", flush=True)
        return 1
    return 0


class UpdatesModule:
    name = "updates"
    description = "upgrade APT, bootstrap missing tools, and scope automatic security upgrades"
    implemented = True

    def apply(self, runner: Runner, *, security_only: bool = False) -> list[StepResult]:
        actions = ["ensure apt security source (create dedicated source only if missing)"]
        if not security_only:
            actions.extend(["apt update", "verify authenticated security index", "apt upgrade"])
        actions.append("install missing tools from an isolated distro base and security view")
        if security_only:
            actions.extend(["verify security-only policy", "isolated apt-get security upgrade"])
        actions.append("verify and configure apt-daily with a trusted isolated helper")
        plan = ["Plan (updates):", *(f"  - {action}" for action in actions)]
        if runner.dry_run or not mutations_allowed():
            for line in plan:
                print(line)
            return [StepResult(action, Status.PLANNED) for action in actions]
        if not confirm_once(plan):
            return [StepResult("updates", Status.ABORTED, "aborted; no changes made")]

        backend = AptBackend(runner)
        results: list[StepResult] = []
        try:
            preflight_timer(runner)
            _reject_admin_exclusions(runner)
            apt = AptSecurity(runner)
            assert_dpkg_clean(apt)
            uris = apt.sources()
            apt.require_keyring()
            if not uris:
                path = apt.managed_source()
                _write_source(path, apt.release, apt.components)
                results.append(StepResult(f"write {path}", Status.CHANGED))
                uris = apt.sources()
                if not uris or uris != {apt.release.uri}:
                    raise DistroError("managed APT security source is not effective")
            if not security_only:
                apt.refresh()
                results.append(StepResult("apt update", Status.CHANGED, "package lists refreshed"))
                sites = apt.verify(uris)
                results.append(StepResult("verify security index", Status.OK, ", ".join(sites)))
                backend.upgrade()
                results.append(StepResult("apt upgrade", Status.CHANGED))
            inventory = _inventory(apt)
            missing = [
                pkg
                for pkg, installed in inventory.items()
                if not installed and (pkg != HTTPS_PACKAGE or apt.legacy_https)
            ]
            if missing:
                with isolated_view(
                    apt, uris, include_base=True, missing_only=security_only
                ) as view:
                    view.refresh()
                    view.install(missing)
                results.append(
                    StepResult("install missing packages", Status.CHANGED, ", ".join(missing))
                )
            if security_only:
                _security_upgrade(apt, uris)
                results.append(StepResult("security upgrade", Status.CHANGED, "isolated APT view"))
            self._configure_automatic(apt, uris, results)
        except (CommandError, DistroError, OSError, ValueError) as exc:
            results.append(StepResult("updates", Status.FAIL, str(exc)))
        return results

    def _configure_automatic(
        self,
        apt: AptSecurity,
        uris: set[str],
        results: list[StepResult],
    ) -> None:
        try:
            _reject_admin_exclusions(apt.runner)
            with isolated_view(apt, uris, probe=True) as view:
                _verify_policy(view.verify_config(), view.patterns)
                if _read_conf() is not None:
                    # Keep legacy/local host policy intact and report a conflict.
                    _verify_policy(apt.runner.capture(["apt-config", "dump"]), view.patterns)
            changed = configure_timer(apt.runner)
        except (CommandError, DistroError, OSError, ValueError) as exc:
            results.append(StepResult("verify", Status.FAIL, str(exc)))
        else:
            results.append(
                StepResult(
                    "verify",
                    Status.CHANGED if changed else Status.OK,
                    "apt-daily ExecStart and effective isolated security policy verified",
                )
            )
