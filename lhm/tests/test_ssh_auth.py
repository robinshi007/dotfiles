from pathlib import Path

import pytest
from conftest import FakeExec

from lhm.core.runner import CommandResult, Runner
from lhm.core.userkeys import Account
from lhm.modules.ssh_auth import (
    AdminSshConfigError,
    admin_connection_spec,
    admin_effective_config,
    admin_key_problems,
)

ADMIN = Account("deploy", 1001, 100, Path("/srv/deploy"))
PORT = 22345
KEY_FILE = ".ssh/authorized_keys"
PAM_ENABLED = "kbdinteractiveauthentication yes\nusepam yes\n"


@pytest.mark.parametrize(
    ("home", "value"),
    [
        ("/srv/deploy", KEY_FILE),
        ("/srv/deploy", "/srv/deploy/.ssh/authorized_keys"),
        ("/srv/deploy", "%h/.ssh/authorized_keys"),
        ("/srv/deploy", "/srv/%u/.ssh/authorized_keys"),
        ("/srv/1001", "/srv/%U/.ssh/authorized_keys"),
        ("/srv/%h", "/srv/%%h/.ssh/authorized_keys"),
        ("/srv/%u", "%h/.ssh/authorized_keys"),
        ("/srv/deploy space", "%h/.ssh/authorized_keys"),
        ("/srv/deploy space", KEY_FILE),
    ],
)
def test_exact_managed_key_file_preserves_mfa(home: str, value: str) -> None:
    account = Account(ADMIN.name, ADMIN.uid, ADMIN.gid, Path(home))
    config = {
        "pubkeyauthentication": "yes",
        "authorizedkeysfile": value,
        "authenticationmethods": "publickey,keyboard-interactive:pam",
        "kbdinteractiveauthentication": "yes",
        "usepam": "yes",
    }
    assert admin_key_problems(config, account) == []


@pytest.mark.parametrize(
    "value",
    [
        "",
        "none",
        "NONE",
        f".ssh/authorized_keys2 {KEY_FILE}",
        f"{KEY_FILE}\x00",
        f"{KEY_FILE}\x7f",
        f"./{KEY_FILE}",
        f"other/../{KEY_FILE}",
        f"/srv/other/../deploy/{KEY_FILE}",
        f"/srv/deploy//{KEY_FILE}",
        f"{KEY_FILE}/",
        f"{KEY_FILE}.old",
        f"/srv/other/{KEY_FILE}",
        f"%x/{KEY_FILE}",
        f"{KEY_FILE}%",
        f'"{KEY_FILE}"',
    ],
)
def test_invalid_key_path_fails_without_echoing_the_value(value: str) -> None:
    problems = admin_key_problems(
        {
            "pubkeyauthentication": "yes",
            "authorizedkeysfile": value,
            "authenticationmethods": "any",
        },
        ADMIN,
    )
    assert len(problems) == 1
    assert "AuthorizedKeysFile" in problems[0]
    if value:
        assert value not in problems[0]


def test_missing_settings_and_traversing_home_fail_closed() -> None:
    assert len(admin_key_problems({}, ADMIN)) == 3
    account = Account("deploy", 1001, 100, Path("/srv/other/../deploy"))
    problems = admin_key_problems(
        {
            "pubkeyauthentication": "yes",
            "authorizedkeysfile": KEY_FILE,
            "authenticationmethods": "any",
        },
        account,
    )
    assert len(problems) == 1 and "AuthorizedKeysFile" in problems[0]


def test_any_still_requires_pubkey_authentication() -> None:
    config = {
        "pubkeyauthentication": "no",
        "authorizedkeysfile": KEY_FILE,
        "authenticationmethods": "any",
    }
    problems = admin_key_problems(config, ADMIN)
    assert len(problems) == 1 and "PubkeyAuthentication" in problems[0]


@pytest.mark.parametrize(
    ("connection", "addr", "laddr"),
    [
        ("192.0.2.15 59361 198.51.100.9 22", "192.0.2.15", "198.51.100.9"),
        ("2001:db8::AB 59361 2001:db8:1::9 22", "2001:db8::ab", "2001:db8:1::9"),
        (
            "::ffff:192.0.2.15 59361 ::ffff:198.51.100.9 22",
            "::ffff:192.0.2.15",
            "::ffff:198.51.100.9",
        ),
    ],
)
def test_connection_spec_uses_validated_session_addresses_and_target_port(
    connection: str, addr: str, laddr: str
) -> None:
    spec, scope = admin_connection_spec(ADMIN, PORT, connection)
    assert spec == f"user=deploy,host={addr},addr={addr},laddr={laddr},lport=22345"
    assert "SSH_CONNECTION" in scope and "UseDNS=no" in scope and "not a login test" in scope


@pytest.mark.parametrize(
    "connection",
    [
        None,
        "",
        "host 59361 198.51.100.9 22",
        "192.0.2.15 59361 host 22",
        "192.0.2.15 0 198.51.100.9 22",
        "192.0.2.15 59361 198.51.100.9 65536",
        "192.0.2.15 +59361 198.51.100.9 22",
        "192.0.2.15 59361 198.51.100.9 ２２",
        "192.0.2.15 59361 198.51.100.9",
        "192.0.2.15,host=spoof 59361 198.51.100.9 22",
        "192.0.2.15 59361 198.51.100.9 22,rdomain=spoof",
        "192.0.2.15 59361 198.51.100.9 22\n",
        "192.0.2.15\t59361 198.51.100.9 22",
        "192.0.2.15  59361 198.51.100.9 22",
        "fe80::1%spoof,addr=x 59361 2001:db8::9 22",
    ],
)
def test_invalid_or_absent_connection_only_probes_loopback(connection: str | None) -> None:
    spec, scope = admin_connection_spec(ADMIN, PORT, connection)
    assert spec == "user=deploy,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=22345"
    assert "loopback" in scope and "User/Group" in scope
    assert "Address/Host/LocalAddress not verified" in scope and "not a login test" in scope
    assert "spoof" not in scope


@pytest.mark.parametrize("port", [0, -1, 65536, True])
def test_invalid_target_port_is_an_error(port: int) -> None:
    with pytest.raises(AdminSshConfigError, match="port"):
        admin_connection_spec(ADMIN, port, None)


@pytest.mark.parametrize("pubkey", ["yes", "no"])
def test_probe_uses_account_match_and_preserves_mfa(
    runner: Runner, fake_exec: FakeExec, monkeypatch: pytest.MonkeyPatch, pubkey: str
) -> None:
    fake_exec.responses = [
        (
            "sshd -T -C user=deploy,",
            0,
            f"pubkeyauthentication {pubkey}\nauthorizedkeysfile {KEY_FILE}\n"
            "authenticationmethods publickey,keyboard-interactive:pam\n"
            f"{PAM_ENABLED}"
            "listenaddress 0.0.0.0:22345\nlistenaddress [::]:22345\n",
            "",
        )
    ]
    run = runner.run

    def checked_run(argv: list[str], *, check: bool, preserve_newlines: bool) -> CommandResult:
        assert not check and preserve_newlines
        return run(argv, check=check, preserve_newlines=preserve_newlines)

    monkeypatch.setattr(runner, "run", checked_run)
    config, scope = admin_effective_config(runner, ADMIN, PORT, "192.0.2.15 57901 198.51.100.9 22")
    assert fake_exec.calls == [
        [
            "sshd",
            "-T",
            "-C",
            "user=deploy,host=192.0.2.15,addr=192.0.2.15,laddr=198.51.100.9,lport=22345",
        ]
    ]
    assert "SSH_CONNECTION" in scope
    assert config["authenticationmethods"] == "publickey,keyboard-interactive:pam"
    problems = admin_key_problems(config, ADMIN)
    if pubkey == "yes":
        assert problems == []
    else:
        assert len(problems) == 1 and "PubkeyAuthentication" in problems[0]


def test_admin_effective_config_accumulates_allowusers(runner: Runner, fake_exec: FakeExec) -> None:
    fake_exec.responses = [("sshd", 0, "allowusers robin\nAllowUsers deploy\n", "")]
    config, _ = admin_effective_config(runner, ADMIN, PORT, None)
    assert config["allowusers"] == "robin deploy"


@pytest.mark.parametrize(
    ("methods", "permits_publickey"),
    [
        ("any", True),
        ("publickey", True),
        ("keyboard-interactive publickey,keyboard-interactive:pam", True),
        ("keyboard-interactive \t publickey", True),
        ("keyboard-interactive:pam,publickey", True),
        ("publickey,publickey", True),
        ("keyboard-interactive", False),
        ("keyboard-interactive:pam hostbased", False),
        ("notpublickey", False),
        ("publickey:not-for-display", False),
        ("publickey,keyboard-interactive:not-for-display", False),
        ("publickey not-for-display", False),
        ("publickey,,keyboard-interactive", False),
        ("publickey,", False),
        ("any publickey", False),
        ("any ", False),
        ("publickey\r", False),
        ("keyboard-interactive\u2028publickey", False),
        ("", False),
        (None, False),
    ],
)
def test_probe_requires_a_valid_publickey_alternative(
    runner: Runner, fake_exec: FakeExec, methods: str | None, permits_publickey: bool
) -> None:
    stdout = f"pubkeyauthentication yes\nauthorizedkeysfile {KEY_FILE}\n{PAM_ENABLED}"
    if methods is not None:
        stdout += f"authenticationmethods {methods}\n"
    fake_exec.responses = [("sshd", 0, stdout, "")]
    config, _ = admin_effective_config(runner, ADMIN, PORT, None)
    assert config.get("authenticationmethods") == methods
    problems = admin_key_problems(config, ADMIN)
    if permits_publickey:
        assert problems == []
    else:
        assert len(problems) == 1 and "AuthenticationMethods" in problems[0]
        assert "not-for-display" not in problems[0]


@pytest.mark.parametrize(
    ("methods", "settings", "permits_publickey"),
    [
        (
            "hostbased publickey,password",
            "hostbasedauthentication yes\npasswordauthentication no\n",
            False,
        ),
        ("password,publickey", "passwordauthentication no\n", False),
        ("publickey,hostbased", "hostbasedauthentication no\n", False),
        ("publickey,gssapi-with-mic", "gssapiauthentication no\n", False),
        (
            "publickey,password publickey,hostbased",
            "passwordauthentication no\nhostbasedauthentication yes\n",
            True,
        ),
        ("publickey,password publickey", "", True),
        ("publickey,password", "passwordauthentication yes\n", True),
        ("publickey,gssapi-with-mic", "gssapiauthentication yes\n", True),
        ("none,publickey", "permitemptypasswords no\npasswordauthentication yes\n", False),
        ("none,publickey", "permitemptypasswords yes\npasswordauthentication no\n", False),
        ("none,publickey", "permitemptypasswords yes\npasswordauthentication yes\n", True),
        ("publickey,password", "", False),
        ("publickey,password", "passwordauthentication \n", False),
        ("publickey,password", "passwordauthentication yes\r\n", False),
        ("publickey,password", "passwordauthentication yes \n", False),
        ("publickey,password", "passwordauthentication  yes\n", False),
        ("publickey,keyboard-interactive", PAM_ENABLED, True),
        ("publickey,keyboard-interactive", "kbdinteractiveauthentication yes\nusepam no\n", False),
        ("publickey,keyboard-interactive:pam", PAM_ENABLED, True),
        (
            "publickey,keyboard-interactive:pam",
            "kbdinteractiveauthentication no\nusepam yes\n",
            False,
        ),
        ("publickey,keyboard-interactive:pam", "kbdinteractiveauthentication yes\n", False),
        ("publickey,keyboard-interactive:bsdauth", PAM_ENABLED, False),
        ("publickey,keyboard-interactive:bsdauth publickey", PAM_ENABLED, True),
    ],
)
def test_probe_requires_all_methods_in_a_publickey_chain_to_be_enabled(
    runner: Runner, fake_exec: FakeExec, methods: str, settings: str, permits_publickey: bool
) -> None:
    stdout = (
        f"pubkeyauthentication yes\nauthorizedkeysfile {KEY_FILE}\n"
        f"authenticationmethods {methods}\n{settings}"
    )
    fake_exec.responses = [("sshd", 0, stdout, "")]
    config, _ = admin_effective_config(runner, ADMIN, PORT, None)
    problems = admin_key_problems(config, ADMIN)
    if permits_publickey:
        assert problems == []
    else:
        assert len(problems) == 1 and "AuthenticationMethods" in problems[0]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(f"{KEY_FILE} .ssh/authorized_keys2", id="printed-multiple-paths"),
        pytest.param(f"{KEY_FILE} .ssh/authorized_keys2", id="printed-quoted-single-path"),
        f" {KEY_FILE}",
        f"{KEY_FILE} ",
        f"{KEY_FILE}\t",
        f"{KEY_FILE}\u2028",
        f"\r{KEY_FILE}",
        f"{KEY_FILE}\r",
        ".ssh/\rauthorized_keys",
    ],
)
def test_probe_preserves_raw_values_and_rejects_ambiguity(
    runner: Runner, fake_exec: FakeExec, value: str
) -> None:
    fake_exec.responses = [
        (
            "sshd",
            0,
            f"pubkeyauthentication yes\nauthorizedkeysfile {value}\nauthenticationmethods any\n",
            "",
        )
    ]
    config, _ = admin_effective_config(runner, ADMIN, PORT, None)
    assert config["authorizedkeysfile"] == value
    problems = admin_key_problems(config, ADMIN)
    assert len(problems) == 1 and "AuthorizedKeysFile" in problems[0]


@pytest.mark.parametrize(
    ("rc", "stdout", "match"),
    [
        (1, f"pubkeyauthentication yes\nauthorizedkeysfile {KEY_FILE}\n", "failed"),
        (0, "", "empty"),
        (0, " \t\n", "empty"),
        (0, f"pubkeyauthentication yes\nauthorizedkeysfile {KEY_FILE}", "incomplete"),
        (0, f"authorizedkeysfile {KEY_FILE}\nAuthorizedKeysFile not-for-display\n", "duplicate"),
        (0, "pubkeyauthentication no\npubkeyauthentication yes\n", "duplicate"),
        (0, "authenticationmethods any\nAuthenticationMethods not-for-display\n", "duplicate"),
        (0, "passwordauthentication no\nPasswordAuthentication yes\n", "duplicate"),
        (0, "usepam yes\nUsePAM no\n", "duplicate"),
        (0, f"authorizedkeysfile\t{KEY_FILE}\n", "malformed"),
        (0, f" authorizedkeysfile {KEY_FILE}\n", "malformed"),
    ],
)
def test_undecidable_probe_is_an_explicit_error(
    runner: Runner, fake_exec: FakeExec, rc: int, stdout: str, match: str
) -> None:
    fake_exec.responses = [("sshd", rc, stdout, "not-for-display")]
    with pytest.raises(AdminSshConfigError, match=match) as failure:
        admin_effective_config(runner, ADMIN, PORT, None)
    assert "not-for-display" not in str(failure.value)
