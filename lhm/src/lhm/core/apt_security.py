"""APT security-pocket discovery, refresh and authentication for updates."""

import hashlib
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from lhm.core.distro import APT_TIMEOUT, DistroError
from lhm.core.runner import Runner

OS_RELEASE = Path("/etc/os-release")
KEYRINGS = Path("/usr/share/keyrings")
MANAGED_SOURCE = "lhm-security.sources"
APT = ["env", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "apt-get"]
INDEX_FILTERS = ["Created-By: Packages", "Target-Of: deb"]
DEBIAN_MOVING_SECURITY = {"stable-security", "oldstable-security", "oldoldstable-security"}
DEFAULT_PORTS = {"http": "80", "https": "443"}
DNS_NAME = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
COMPRESSIONS = (".lz4", ".zst", ".xz", ".gz", ".bz2", ".lzma")
MAX_AGE_WITHOUT_VALID_UNTIL = timedelta(days=7)
_HASH_COMPRESSED = """\
import hashlib
import subprocess
import sys

digest = hashlib.sha256()
size = 0
with subprocess.Popen(
    ["/usr/lib/apt/apt-helper", "cat-file", sys.argv[1]], stdout=subprocess.PIPE
) as apt:
    for chunk in iter(lambda: apt.stdout.read(1 << 20), b""):
        size += len(chunk)
        digest.update(chunk)
    if apt.wait() != 0:
        sys.exit(1)
print(digest.hexdigest(), size)
"""


def _deb822(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    record: dict[str, str] = {}
    key = ""
    for line in [*text.splitlines(), ""]:
        if line.startswith("#"):
            continue
        if not line.strip():
            if record:
                records.append(record)
            record, key = {}, ""
        elif line[0].isspace() and key:
            record[key] += " " + line.strip()
        else:
            name, sep, value = line.partition(":")
            if not sep or not name or name.lower() in record:
                raise DistroError("malformed APT deb822 metadata")
            key = name.lower()
            record[key] = value.strip()
    return records


@dataclass(frozen=True)
class Release:
    distro: str
    codename: str
    arch: str

    @property
    def suite(self) -> str:
        return f"{self.codename}-security"

    @property
    def keyring_package(self) -> str:
        return "debian-archive-keyring" if self.distro == "debian" else "ubuntu-keyring"

    @property
    def keyring(self) -> Path:
        return KEYRINGS / f"{self.distro}-archive-keyring.gpg"

    @property
    def supported_components(self) -> set[str]:
        if self.distro == "debian":
            return {"main", "contrib", "non-free", "non-free-firmware"}
        return {"main", "restricted", "universe", "multiverse"}

    @property
    def uri(self) -> str:
        # APT authenticates HTTP with Signed-By; HTTPS might need bootstrapping.
        if self.distro == "debian":
            return "http://security.debian.org/debian-security/"
        if self.arch not in {"amd64", "i386"}:
            return "http://ports.ubuntu.com/ubuntu-ports/"
        return "http://security.ubuntu.com/ubuntu/"

    @property
    def base_uri(self) -> str:
        if self.distro == "debian":
            return "http://deb.debian.org/debian/"
        if self.arch not in {"amd64", "i386"}:
            return "http://ports.ubuntu.com/ubuntu-ports/"
        return "http://archive.ubuntu.com/ubuntu/"

    def official_uri(self, uri: str) -> bool:
        canonical = _canonical_uri(uri)
        if canonical is None:
            return False
        parsed = urlsplit(canonical)
        path = parsed.path.removesuffix("/")
        host = parsed.hostname
        if self.distro == "debian":
            return path == "/debian-security" and host in {"security.debian.org", "deb.debian.org"}
        if host == "ports.ubuntu.com":
            return path == "/ubuntu-ports"
        return path == "/ubuntu" and bool(
            host in {"security.ubuntu.com", "archive.ubuntu.com"}
            or (host or "").endswith(".archive.ubuntu.com")
        )

    def matches(self, fields: dict[str, str], *, security: bool = True) -> bool:
        if self.distro == "debian":
            return (
                fields.get("origin") == "Debian"
                and fields.get("label") == ("Debian-Security" if security else "Debian")
                and fields.get("codename") == (self.suite if security else self.codename)
            )
        return (
            fields.get("origin") == "Ubuntu"
            and fields.get("label") == "Ubuntu"
            and fields.get("codename") == self.codename
            and fields.get("suite") == (self.suite if security else self.codename)
        )

    def pattern(self, site: str) -> str:
        if self.distro == "debian":
            return f"o=Debian,l=Debian-Security,n={self.suite},site={site}"
        return f"o=Ubuntu,l=Ubuntu,n={self.codename},a={self.suite},site={site}"


def _canonical_uri(uri: str) -> str | None:
    # Only explicit, scheme-appropriate default ports are equivalent. Keep the
    # path as APT reported it; never normalize encoded paths or an authority.
    if not uri.isascii() or re.search(r"[\x00-\x20\x7f\\?#]", uri):
        return None
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname or ""
        port = DEFAULT_PORTS.get(parsed.scheme)
        if (
            port
            and uri.startswith(f"{parsed.scheme}://")
            and parsed.netloc in {host, f"{host}:{port}"}
            and re.fullmatch(DNS_NAME, host)
        ):
            return parsed._replace(netloc=host).geturl()
    except ValueError:
        pass
    return None


def _site(uri: str) -> str:
    """APT's site match uses the hostname, even for a disallowed scheme or port."""
    try:
        return urlsplit(uri if "://" in uri else "//" + uri).hostname or ""
    except ValueError:
        return ""


def _source_options(entry: str) -> dict[str, str]:
    filename, sep, number = entry.rpartition(":")
    if not sep or not number.isascii() or not number.isdecimal() or int(number) < 1:
        raise DistroError("cannot identify the active APT security source")
    path = Path(filename)
    text = path.read_text(encoding="utf-8")
    index = int(number) - 1
    if path.suffix == ".sources":
        records = _deb822(text)
        if index < len(records):
            return records[index]
    elif index < len(lines := text.splitlines()):
        match = re.match(r"\s*deb\s+(?:\[([^]]*)\]\s+)?", lines[index])
        if match is not None:
            return {
                key.lower(): value
                for option in (match[1] or "").split()
                for key, _, value in [option.partition("=")]
            }
    raise DistroError(f"cannot read active APT security source options: {entry}")


def _check_source(release: Release, target: dict[str, str]) -> None:
    uri, entry = target.get("repo-uri", ""), target.get("sourcesentry", "")
    options = _source_options(entry)
    signed_by = options.get("signed-by")
    if (
        _canonical_uri(uri) is None
        or signed_by != str(release.keyring)
        or "trusted" in options
        or any(
            options.get(key, "no").casefold() not in {"no", "false", "0"}
            for key in ("allow-insecure", "allow-weak", "allow-downgrade-to-insecure")
        )
        or any(
            options.get(key, "yes").casefold() not in {"yes", "true", "1"}
            for key in ("check-date", "check-valid-until")
        )
        or any(key in options for key in ("valid-until-min", "date-max-future", "inrelease-path"))
    ):
        raise DistroError(f"conflicting or unscoped APT security source: {entry}")


class AptSecurity:
    """Use APT's effective binary targets, not a guess from source filenames."""

    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        version = runner.run(["apt-get", "--version"], timeout=15.0, check=False)
        if not version.ok:
            raise DistroError("apt-get not found: lhm supports Debian/Ubuntu with apt only")
        match = re.match(r"apt (\d+)\.(\d+)", version.stdout)
        if not match:
            raise DistroError("cannot determine APT version")
        self.legacy_https = tuple(map(int, match.groups())) < (1, 5)
        arch = runner.capture(["dpkg", "--print-architecture"]).strip()
        values: dict[str, str] = {}
        for line in OS_RELEASE.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key in {"ID", "VERSION_CODENAME"}:
                values[key] = value.strip("'\"")
        distro, codename = values.get("ID", ""), values.get("VERSION_CODENAME", "")
        if distro not in {"debian", "ubuntu"} or not all(
            re.fullmatch(r"[a-z][a-z0-9-]*", token) for token in (codename, arch)
        ):
            raise DistroError("cannot determine supported Debian/Ubuntu codename and architecture")
        self.release = Release(distro, codename, arch)
        self.components: tuple[str, ...] = ()

    def managed_source(self) -> Path:
        out = self.runner.capture(["apt-config", "shell", "PARTS", "Dir::Etc::sourceparts/d"])
        words = shlex.split(out)
        if len(words) != 1 or not words[0].startswith("PARTS=/"):
            raise DistroError("cannot determine the active APT source directory")
        return Path(words[0].removeprefix("PARTS=")) / MANAGED_SOURCE

    def _targets(
        self,
        *,
        configured: bool = False,
        command: Sequence[str] = APT,
    ) -> list[dict[str, str]]:
        cmd = [
            *command,
            "-o",
            "Dir::Cache::pkgcache=",
            "-o",
            "Dir::Cache::srcpkgcache=",
            "indextargets",
        ]
        if configured:
            cmd.append("--no-release-info")
        return _deb822(self.runner.capture([*cmd, *INDEX_FILTERS], timeout=60.0))

    def sources(self) -> set[str]:
        """Find configured native binary sources; stop on unsafe competitors."""
        uris = set()
        components = set()
        for target in self._targets(configured=True):
            if target.get("architecture") != self.release.arch:
                continue
            suite = target.get("release", "")
            uri = target.get("repo-uri", "")
            component = target.get("component", "")
            if (
                suite == self.release.codename
                and component in self.release.supported_components
                and _canonical_uri(uri) is not None
                and _source_options(target.get("sourcesentry", "")).get("signed-by")
                == str(self.release.keyring)
            ):
                _check_source(self.release, target)
                components.add(component)
            elif suite == self.release.suite:
                _check_source(self.release, target)
                uris.add(uri)
            elif suite.endswith("-security") and (
                self.release.official_uri(uri)
                or (self.release.distro == "debian" and suite in DEBIAN_MOVING_SECURITY)
            ):
                raise DistroError(
                    f"conflicting official security suite {suite}; expected {self.release.suite}"
                )
        if not components:
            raise DistroError(
                "cannot determine security components from a distro-scoped base source"
            )
        self.components = tuple(sorted(components))
        return uris

    def require_keyring(self) -> None:
        if not self.release.keyring.is_file():
            raise DistroError(
                f"missing archive trust anchor: restore {self.release.keyring_package}"
            )
        keyring = self.release.keyring.resolve(strict=True)
        for path in (keyring, *keyring.parents):
            st = path.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise DistroError(f"unsafe archive trust anchor or parent: {path}")

    def refresh(self, command: Sequence[str] = APT) -> None:
        result = self.runner.run(
            [
                *command,
                "update",
                "-q",
                "-o",
                "APT::Update::Error-Mode=any",
                "-o",
                "Acquire::AllowInsecureRepositories=false",
                "-o",
                "Acquire::AllowWeakRepositories=false",
                "-o",
                "Acquire::AllowDowngradeToInsecureRepositories=false",
                "-o",
                "Acquire::Check-Date=true",
                "-o",
                "Acquire::Check-Valid-Until=true",
            ],
            timeout=APT_TIMEOUT,
        )
        # Older APT may exit zero despite a failed fetch and use stale lists.
        if re.search(
            r"^(?:[WE]: (?:Failed to fetch|Some index files failed|GPG error)|Err:)",
            result.stderr + "\n" + result.stdout,
            re.MULTILINE,
        ):
            raise DistroError("APT did not refresh all package lists; refusing stale indexes")

    def _verify_release(
        self,
        prefix: str,
        *,
        security: bool,
    ) -> tuple[set[str], dict[str, tuple[str, int]]]:
        inline = Path(prefix + "InRelease")
        release = Path(prefix + "Release")
        sig = Path(prefix + "Release.gpg")
        gpgv = ["/usr/bin/gpgv", "--keyring", str(self.release.keyring)]
        sqv = ["/usr/bin/sqv", "--keyring", str(self.release.keyring)]
        if inline.is_file():
            result = self.runner.run([*gpgv, "--output", "-", str(inline)], check=False)
            if result.returncode == 127:  # newer Debian APT depends on sqv instead of gpgv
                with TemporaryDirectory(prefix="lhm-apt-") as tmp:
                    payload = Path(tmp) / "release"
                    self.runner.run([*sqv, "--cleartext", "--output", str(payload), str(inline)])
                    text = payload.read_text(encoding="utf-8")
            elif result.ok:
                text = result.stdout
            else:
                raise DistroError("APT security InRelease is not signed by the distro archive")
        elif release.is_file() and sig.is_file():
            result = self.runner.run([*gpgv, str(sig), str(release)], check=False)
            if result.returncode == 127:
                self.runner.run([*sqv, "--signature-file", str(sig), str(release)])
            elif not result.ok:
                raise DistroError("APT security Release is not signed by the distro archive")
            text = release.read_text(encoding="utf-8")
        else:
            raise DistroError("no signed APT security Release metadata after refresh")
        records = _deb822(text)
        if len(records) != 1 or not self.release.matches(records[0], security=security):
            raise DistroError("signed APT Release metadata does not match the OS and pocket")
        fields = records[0]
        try:
            signed_date = parsedate_to_datetime(fields["date"])
            expires = None
            if "valid-until" in fields:
                expires = parsedate_to_datetime(fields["valid-until"])
            elif security:
                expires = signed_date + MAX_AGE_WITHOUT_VALID_UNTIL
        except (KeyError, OverflowError, ValueError) as exc:
            raise DistroError("invalid signed APT security Release dates") from exc
        now = datetime.now(UTC)
        if (
            signed_date.tzinfo is None
            or signed_date > now + timedelta(seconds=10)
            or (
                expires is not None and (expires.tzinfo is None or expires <= max(now, signed_date))
            )
        ):
            raise DistroError("expired or future-dated signed APT security Release")
        checksums: dict[str, tuple[str, int]] = {}
        tokens = fields.get("sha256", "").split()
        if len(tokens) % 3:
            raise DistroError("malformed signed APT security Release checksums")
        for digest, size, key in zip(tokens[::3], tokens[1::3], tokens[2::3], strict=True):
            if (
                key in checksums
                or not re.fullmatch(r"[0-9a-fA-F]{64}", digest)
                or not re.fullmatch(r"[0-9]{1,20}", size)
            ):
                raise DistroError("malformed signed APT security Release checksums")
            checksums[key] = digest.lower(), int(size)
        advertised = fields.get("components", "").split()
        components = {name.removeprefix("updates/") for name in advertised}
        return components, checksums

    def _measure_index(self, filename: Path, compression: str) -> tuple[str, int]:
        if compression:
            text = self.runner.capture(
                ["/usr/bin/python3", "-I", "-c", _HASH_COMPRESSED, str(filename)],
                timeout=APT_TIMEOUT,
            )
            match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,20})\n?", text)
            if match is None:
                raise DistroError("could not measure APT security Packages index")
            return match[1], int(match[2])
        with filename.open("rb") as data:
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: data.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
            return digest.hexdigest(), size

    def verify(
        self,
        uris: set[str],
        *,
        command: Sequence[str] = APT,
        lists: Path | None = None,
        include_base: bool = False,
    ) -> tuple[str, ...]:
        """Require authenticated, refreshed native indexes for each selected repository."""
        sites = {_site(uri) for uri in uris}
        canonical_uris = {_canonical_uri(uri) for uri in uris}
        if not canonical_uris or None in canonical_uris:
            raise DistroError("invalid APT security source URI")
        expected_sources = {(uri, self.release.suite) for uri in canonical_uris}
        if include_base:
            expected_sources.add((self.release.base_uri, self.release.codename))
        verified: set[tuple[str | None, str]] = set()
        releases: dict[tuple[str, bool], tuple[set[str], dict[str, tuple[str, int]]]] = {}
        coverage: dict[str, set[str]] = {}
        advertised: dict[str, set[str]] = {}

        def target_id(target: dict[str, str]) -> tuple[str | None, str, str, str]:
            return (
                _canonical_uri(target.get("repo-uri", "")),
                target.get("release", ""),
                target.get("architecture", ""),
                target.get("metakey", ""),
            )

        loaded = self._targets(command=command)
        loaded_ids = {target_id(target) for target in loaded}
        configured = self._targets(configured=True, command=command)
        targets = [(target, True) for target in loaded]
        targets.extend(
            (target, False)
            for target in configured
            if target_id(target) not in loaded_ids
            and target.get("metakey")
            and target_id(target)[:2] in expected_sources
        )
        for target, is_loaded in targets:
            uri = target.get("repo-uri", "")
            suite = target.get("release", "")
            identity = (_canonical_uri(uri), suite)
            if identity not in expected_sources:
                if lists is not None or (
                    self.release.matches(target)
                    and ({_site(uri), _site(target.get("site", ""))} & sites)
                ):
                    raise DistroError("another APT index matches the security-only origin policy")
                continue
            security = suite == self.release.suite
            _check_source(self.release, target)
            filename = Path(target.get("filename", ""))
            if lists is not None and (filename.parent != lists or filename.is_symlink()):
                raise DistroError("APT Packages index is outside the isolated lists directory")
            key = target.get("metakey", "")
            metakey = key.replace("/", "_")
            stem = str(filename)
            compression = next((suffix for suffix in COMPRESSIONS if stem.endswith(suffix)), "")
            stem = stem.removesuffix(compression)
            if is_loaded and (
                not self.release.matches(target, security=security)
                or target.get("trusted") != "yes"
            ):
                raise DistroError("APT security index is not trusted or has unexpected metadata")
            if not filename.is_absolute() or not metakey or not stem.endswith("_" + metakey):
                raise DistroError("APT security index is not trusted or has unexpected metadata")
            prefix = stem.removesuffix(metakey)
            release_key = (prefix, security)
            if release_key not in releases:
                releases[release_key] = self._verify_release(prefix, security=security)
            components, checksums = releases[release_key]
            expected = checksums.get(key)
            if not is_loaded or (not filename.exists() and not filename.is_symlink()):
                # APT can omit an empty authenticated index from its lists.
                if expected == (hashlib.sha256(b"").hexdigest(), 0):
                    measured = expected
                elif target.get("optional") == "yes" and expected is None:
                    continue
                else:
                    raise DistroError("APT Packages index is missing without a signed empty hash")
            elif filename.is_file():
                measured = self._measure_index(filename, compression)
            else:
                raise DistroError("APT Packages index is not a regular file")
            if expected is None or measured != expected:
                raise DistroError("APT Packages index does not match the signed Release checksums")
            if target.get("architecture") == self.release.arch:
                verified.add(identity)
                coverage.setdefault(suite, set()).add(key.partition("/")[0])
                advertised.setdefault(suite, set()).update(components)
        if verified != expected_sources:
            raise DistroError(f"missing verified APT package index for {self.release.arch}")
        for suite in {suite for _, suite in expected_sources}:
            required = advertised[suite].intersection(self.components)
            if not required or not required <= coverage[suite]:
                raise DistroError("verified APT indexes do not cover enabled distro components")
        return tuple(sorted(sites))
