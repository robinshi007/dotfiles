"""Distribution backend seam. Phase 1 ships an apt implementation only."""

from typing import Protocol

from lhm.core.runner import Runner

APT_GET = "apt-get"
APT_TIMEOUT = 1800.0


class DistroError(RuntimeError):
    """Raised when the expected package backend is unavailable."""


class DistroBackend(Protocol):
    def pkg_installed(self, name: str) -> bool: ...

    def install(self, pkgs: list[str]) -> None: ...

    def update(self) -> None: ...

    def upgrade(self, security_only: bool = False) -> None: ...


class AptBackend:
    """Debian/Ubuntu backend driven entirely through the injected Runner."""

    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self._available: bool | None = None

    def _require_apt(self) -> None:
        if self._available is None:
            probe = self.runner.run([APT_GET, "--version"], timeout=15.0, check=False)
            if probe.was_dry_run:
                return  # plan without asserting that apt is available
            self._available = probe.ok
        if not self._available:
            raise DistroError("apt-get not found: lhm supports Debian/Ubuntu with apt only")

    def pkg_installed(self, name: str) -> bool:
        self._require_apt()
        result = self.runner.run(
            ["dpkg-query", "-W", "-f=${Status}", name], timeout=60.0, check=False
        )
        return result.ok and "install ok installed" in result.stdout

    def install(self, pkgs: list[str]) -> None:
        if not pkgs:
            return
        self._require_apt()
        env = ["env", "DEBIAN_FRONTEND=noninteractive"]
        self.runner.run([*env, APT_GET, "install", "-y", "-q", *pkgs], timeout=APT_TIMEOUT)

    def update(self) -> None:
        self._require_apt()
        env = ["env", "DEBIAN_FRONTEND=noninteractive"]
        self.runner.run([*env, APT_GET, "update", "-q"], timeout=APT_TIMEOUT)

    def upgrade(self, security_only: bool = False) -> None:
        self._require_apt()
        env = ["env", "DEBIAN_FRONTEND=noninteractive"]
        if security_only:
            # unattended-upgrade honours Allowed-Origins (security only).
            self.runner.run([*env, "unattended-upgrade"], timeout=APT_TIMEOUT)
        else:
            self.runner.run([*env, APT_GET, "upgrade", "-y", "-q"], timeout=APT_TIMEOUT)
