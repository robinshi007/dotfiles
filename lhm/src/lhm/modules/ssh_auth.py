"""Check effective OpenSSH public-key settings for one administrator context."""

import re
from collections.abc import Mapping
from ipaddress import ip_address
from pathlib import PurePosixPath

from lhm.core.runner import Runner
from lhm.core.userkeys import Account

_RAW_OPTIONS = {
    "authenticationmethods": "AuthenticationMethods",
    "authorizedkeysfile": "AuthorizedKeysFile",
    "gssapiauthentication": "GSSAPIAuthentication",
    "hostbasedauthentication": "HostbasedAuthentication",
    "kbdinteractiveauthentication": "KbdInteractiveAuthentication",
    "passwordauthentication": "PasswordAuthentication",
    "permitemptypasswords": "PermitEmptyPasswords",
    "pubkeyauthentication": "PubkeyAuthentication",
    "usepam": "UsePAM",
}
_METHOD_OPTIONS = {
    "gssapi-with-mic": ("gssapiauthentication",),
    "hostbased": ("hostbasedauthentication",),
    # On Debian/Ubuntu, PAM is the keyboard-interactive device.
    "keyboard-interactive": ("kbdinteractiveauthentication", "usepam"),
    "keyboard-interactive:pam": ("kbdinteractiveauthentication", "usepam"),
    "none": ("permitemptypasswords", "passwordauthentication"),
    "password": ("passwordauthentication",),
    "publickey": (),  # PubkeyAuthentication is checked separately.
}
# BSD auth is valid OpenSSH syntax but not available on Debian/Ubuntu.
_AUTH_METHODS = _METHOD_OPTIONS.keys() | {"keyboard-interactive:bsdauth"}


class AdminSshConfigError(ValueError):
    """The effective administrator config could not be probed reliably."""


def _matches_managed_path(value: str, account: Account) -> bool:
    replacements = {"h": str(account.home), "u": account.name, "U": str(account.uid), "%": "%"}
    try:
        # re.sub matches the original tokens, not their expansions.
        expanded = re.sub(r"%(.?)", lambda match: replacements[match[1]], value)
    except KeyError:
        return False
    path = PurePosixPath(expanded)
    if expanded != str(path):
        return False
    path = account.home / path  # An absolute expansion overrides the home.
    return ".." not in path.parts and path == account.home / ".ssh" / "authorized_keys"


def _permits_publickey(config: Mapping[str, str]) -> bool:
    value = config.get("authenticationmethods", "")
    if value == "any":
        return True
    # Split horizontal separators only; do not strip raw CR or other controls.
    alternatives = [alternative.split(",") for alternative in re.split(r"[ \t]+", value)]
    return all(method in _AUTH_METHODS for sequence in alternatives for method in sequence) and any(
        "publickey" in sequence
        and all(
            method in _METHOD_OPTIONS
            and all(config.get(option) == "yes" for option in _METHOD_OPTIONS[method])
            for method in sequence
        )
        for sequence in alternatives
    )


def admin_key_problems(config: Mapping[str, str], account: Account) -> list[str]:
    """Check raw effective key settings; neither inspect key files nor test a login."""
    problems: list[str] = []
    if config.get("pubkeyauthentication") != "yes":
        problems.append("effective PubkeyAuthentication must be yes for the administrator")
    if not _permits_publickey(config):
        problems.append(
            "effective AuthenticationMethods must permit publickey in a valid chain "
            "of enabled methods for the administrator"
        )

    value = config.get("authorizedkeysfile", "")
    # sshd prints a list and a single whitespace-containing path identically.
    if (
        not value
        or value.lower() == "none"
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        problems.append(
            "effective AuthorizedKeysFile must be a single unambiguous path "
            "without whitespace; configure only the managed key file"
        )
    elif not _matches_managed_path(value, account):
        problems.append("effective AuthorizedKeysFile must point exactly to the managed key file")
    return problems


def parse_ssh_connection(connection: str | None) -> tuple[str, int, str, int] | None:
    """Parse the exact OpenSSH field format and normalize addresses for comparison."""
    fields = connection.split(" ") if connection else []
    if len(fields) != 4:
        return None
    addr, client_port, laddr, server_port = fields
    if not all(
        re.fullmatch(r"[0-9]{1,5}", value) and 1 <= int(value) <= 65535
        for value in (client_port, server_port)
    ):
        return None
    if "%" in addr or "%" in laddr:  # Scoped addresses aren't plain IP literals.
        return None
    try:
        source = str(ip_address(addr))
        target = str(ip_address(laddr))
    except ValueError:
        return None
    return source, int(client_port), target, int(server_port)


def admin_connection_spec(
    account: Account, port: int, ssh_connection: str | None
) -> tuple[str, str]:
    """Return one sshd -C argument and a note describing the limits of that context."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise AdminSshConfigError("invalid target SSH port")
    connection = parse_ssh_connection(ssh_connection)
    if connection is None:
        addr = laddr = "127.0.0.1"
        scope = (
            "loopback (localhost) probe for Match User/Group; "
            "remote Match Address/Host/LocalAddress not verified; not a login test"
        )
    else:
        addr, _, laddr, _ = connection
        scope = (
            "probe using SSH_CONNECTION addresses and target port "
            "(numeric host assumes UseDNS=no); not a login test"
        )
    return f"user={account.name},host={addr},addr={addr},laddr={laddr},lport={port}", scope


def admin_effective_config(
    runner: Runner, account: Account, port: int, ssh_connection: str | None
) -> tuple[dict[str, str], str]:
    """Return account-specific sshd -T config with raw auth settings, and its scope note.

    Use admin_key_problems on the result. Probe errors raise AdminSshConfigError.
    """
    spec, scope = admin_connection_spec(account, port, ssh_connection)
    try:
        result = runner.run(["sshd", "-T", "-C", spec], check=False, preserve_newlines=True)
    except OSError, ValueError:
        raise AdminSshConfigError(
            "effective administrator SSH config probe could not execute"
        ) from None
    if not result.ok:
        raise AdminSshConfigError(
            f"effective administrator SSH config probe failed (rc={result.returncode})"
        )
    if not result.stdout.strip():
        raise AdminSshConfigError("effective administrator SSH config probe returned empty output")
    if not result.stdout.endswith("\n"):
        raise AdminSshConfigError("incomplete effective administrator SSH config output")

    config: dict[str, str] = {}
    # OpenSSH emits LF. A CR before it can be literal data from a quoted path.
    for line in result.stdout.split("\n"):
        if not line:
            continue
        keyword, separator, value = line.partition(" ")
        if not separator or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]*", keyword):
            raise AdminSshConfigError("malformed effective administrator SSH config output")
        option = keyword.lower()
        if option in _RAW_OPTIONS:
            if option in config:
                raise AdminSshConfigError(f"duplicate effective {_RAW_OPTIONS[option]} setting")
            config[option] = value
        elif option == "allowusers" and option in config:
            config[option] = f"{config[option]} {value.strip()}"
        else:
            config[option] = value.strip()
    return config, scope
