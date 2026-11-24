import os
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lhm.core.runner import Runner
from lhm.core.userkeys import (
    Account,
    KeyState,
    UserKeysError,
    ensure_key,
    lookup_account,
    probe_keys,
    read_public_key_source,
)

KEY = r"ssh-ed25519 example comment '\t ; $(not-a-command)"
OTHER_KEY = "ssh-ed25519 different"
SECRET = "do not show key-file content"
EXAMPLE = Account("alice", 1001, 100, Path("/srv/users/alice space"))
PREFIX = "LHM_USERKEYS_V1 "


def stub_runner(rc: int, stdout: str = "", stderr: str = "") -> tuple[Runner, list[list[str]]]:
    calls: list[list[str]] = []

    def execute(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert timeout > 0
        calls.append(argv)
        return subprocess.CompletedProcess(argv, rc, stdout, stderr)

    return Runner(exec_fn=execute), calls


def test_exact_passwd_identity_and_numeric_primary_group() -> None:
    runner, calls = stub_runner(0, "alice:x:1001:100:Alice:/srv/users/alice space:/bin/sh\n")
    assert lookup_account(runner, "alice") == EXAMPLE
    assert calls == [["/usr/bin/getent", "passwd", "alice"]]


def test_only_getent_status_two_is_absent() -> None:
    assert lookup_account(stub_runner(2)[0], "alice") is None
    for rc in (1, 3, 124, 127):
        with pytest.raises(UserKeysError, match=f"rc={rc}") as failure:
            lookup_account(stub_runner(rc, SECRET, SECRET)[0], "alice")
        assert SECRET not in str(failure.value)
    with pytest.raises(UserKeysError, match="rc=None"):
        lookup_account(Runner(dry_run=True), "alice")


@pytest.mark.parametrize(
    "record",
    [
        "",
        "alice:x:1001:100:Alice:/home/alice",
        "bob:x:1001:100:Alice:/home/alice:/bin/sh",
        "alice:x:0:100:Alice:/home/alice:/bin/sh",
        "alice:x:1001:0:Alice:/home/alice:/bin/sh",
        "alice:x:+1001:100:Alice:/home/alice:/bin/sh",
        "alice:x:1001:4294967295:Alice:/home/alice:/bin/sh",
        "alice:x:1001:100:Alice:relative:/bin/sh",
        "alice:x:1001:100:Alice:/home/alice:/bin/sh\nanother record",
        "alice:x:1001:100:Alice:/home/alice:/bin/sh\r",
        "alice:x:1001:100:Alice:/home/\0alice:/bin/sh",
    ],
)
def test_passwd_record_rejected(record: str) -> None:
    with pytest.raises(UserKeysError):
        lookup_account(stub_runner(0, record + "\n")[0], "alice")


def test_passwd_record_with_bare_cr_rejected() -> None:
    runner, _ = stub_runner(0, "alice:x:1001:100:Alice:/home/alice:/bin/sh\r")
    with pytest.raises(UserKeysError, match="invalid passwd record"):
        lookup_account(runner, "alice")


def test_account_names_cannot_be_options_or_numeric_keys() -> None:
    runner, calls = stub_runner(2)
    for name in ("-s", "1001", "alice:other", "alice\n"):
        with pytest.raises(UserKeysError, match="invalid account name"):
            lookup_account(runner, name)
    assert calls == []


def test_helper_argv_and_exact_output_protocol() -> None:
    probe, probe_calls = stub_runner(0, PREFIX + "STATE 0 0644 YQ0K\n")
    ensure, ensure_calls = stub_runner(0, PREFIX + "CHANGED 1\n")
    assert probe_keys(probe, EXAMPLE) == KeyState("a\r\n", False, 0o644)
    assert ensure_key(ensure, EXAMPLE, KEY)
    (probe_argv,) = probe_calls
    (ensure_argv,) = ensure_calls
    assert probe_argv[:14] == [
        "/usr/bin/setpriv",
        "--reuid",
        "1001",
        "--regid",
        "100",
        "--clear-groups",
        "--no-new-privs",
        "--",
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "/bin/sh",
        "-c",
    ]
    assert probe_argv[:16] == ensure_argv[:16]
    assert KEY not in ensure_argv[14]
    assert str(EXAMPLE.home) not in probe_argv[14]
    assert ensure_argv[16:] == ["ensure", "1001", "100", str(EXAMPLE.home), KEY, "1048576"]
    assert probe_argv[16:] == ["probe", "1001", "100", str(EXAMPLE.home), "", "1048576"]


@pytest.mark.parametrize(
    ("rc", "stdout"),
    [
        (1, PREFIX + "STATE 0 -\n"),
        (0, "STATE 0 -\n"),
        (0, PREFIX + "STATE 0 -"),
        (0, PREFIX + "STATE 0 -\r\n"),
        (0, PREFIX + "STATE 0 -\r"),
        (0, PREFIX + "STATE 0 -\n\n"),
        (0, PREFIX + "STATE 0 0688 \n"),
        (0, PREFIX + "STATE 0 0600 a\n"),
        (0, PREFIX + "STATE 0 0600 YR==\n"),
        (0, PREFIX + "STATE 0 0600 /w==\n"),
        (0, PREFIX + f"STATE 0 0600 {SECRET}\n"),
        (124, PREFIX + f"ERROR {SECRET}\n"),
    ],
)
def test_invalid_probe_frames_fail_without_exposing_output(rc: int, stdout: str) -> None:
    with pytest.raises(UserKeysError) as failure:
        probe_keys(stub_runner(rc, stdout, SECRET)[0], EXAMPLE)
    assert SECRET not in str(failure.value)


def test_helper_error_allowlist_and_dry_run() -> None:
    runner, _ = stub_runner(1, PREFIX + "ERROR backup\n", SECRET)
    with pytest.raises(UserKeysError, match="publish private authorized_keys backup"):
        ensure_key(runner, EXAMPLE, KEY)
    with pytest.raises(UserKeysError, match="rc=None"):
        probe_keys(Runner(dry_run=True), EXAMPLE)


@pytest.mark.parametrize("key", ["", " leading", "two\nkeys", "bad\0data", "\udc80", "x" * 16385])
def test_invalid_line_does_not_invoke_helper(key: str) -> None:
    runner, calls = stub_runner(0, PREFIX + "CHANGED 0\n")
    with pytest.raises(UserKeysError):
        ensure_key(runner, EXAMPLE, key)
    assert calls == []


@pytest.fixture
def local_home(tmp_path: Path) -> Account:
    if os.getuid() == 0 or os.getgid() == 0 or os.geteuid() == 0 or os.getegid() == 0:
        pytest.skip("shell integration tests must run unprivileged")
    home = tmp_path / "home ' $(not-a-command)"
    home.mkdir(mode=0o700)
    return Account("testuser", os.geteuid(), os.getegid(), home)


def local_runner() -> Runner:
    # Use the exact helper and clean environment without any privilege/account operations.
    def execute(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert argv[0] == "/usr/bin/setpriv"
        return subprocess.run(
            argv[8:],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    return Runner(exec_fn=execute)


def test_shell_probe_create_and_skip(local_home: Account) -> None:
    runner = local_runner()
    ssh = local_home.home / ".ssh"
    keys = ssh / "authorized_keys"
    assert probe_keys(runner, local_home) == KeyState(None, False, None)
    assert not ssh.exists()
    assert ensure_key(runner, local_home, KEY)
    assert ssh.stat().st_mode & 0o7777 == 0o700
    assert probe_keys(runner, local_home) == KeyState(KEY + "\n", True, 0o600)
    original_inode = keys.stat().st_ino
    original_dir_mtime = ssh.stat().st_mtime_ns
    assert not ensure_key(runner, local_home, KEY)
    assert keys.stat().st_ino == original_inode
    assert ssh.stat().st_mtime_ns == original_dir_mtime
    assert list(ssh.iterdir()) == [keys]


def test_shell_rejects_group_or_world_writable_home(local_home: Account) -> None:
    local_home.home.chmod(0o777)
    runner = local_runner()
    with pytest.raises(UserKeysError, match="home owner or permissions"):
        probe_keys(runner, local_home)
    with pytest.raises(UserKeysError, match="home owner or permissions"):
        ensure_key(runner, local_home, KEY)
    assert not (local_home.home / ".ssh").exists()


def test_shell_does_not_treat_form_feed_as_ssh_indentation(local_home: Account) -> None:
    ssh = local_home.home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    bad = "\f" + KEY + "\n"
    keys.write_text(bad, encoding="utf-8")
    keys.chmod(0o600)
    assert ensure_key(local_runner(), local_home, KEY)
    assert keys.read_text(encoding="utf-8") == bad + KEY + "\n"


def test_shell_accepts_non_ascii_whitespace_in_key_comment(local_home: Account) -> None:
    line = KEY + "\u00a0"
    runner = local_runner()
    assert ensure_key(runner, local_home, line)
    assert not ensure_key(runner, local_home, line)


@pytest.mark.parametrize("existing", [b"", b"# old comment", b"# old comment\r\n\r\n"])
def test_shell_append_preserves_bytes_and_exclusively_backs_up(
    local_home: Account, existing: bytes
) -> None:
    runner = local_runner()
    ssh = local_home.home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    keys.write_bytes(existing)
    keys.chmod(0o640)
    first = ssh / "authorized_keys.bak.1"
    first.write_text("untouched", encoding="utf-8")
    second = ssh / "authorized_keys.bak.2"
    second.symlink_to(local_home.home / "absent")
    assert ensure_key(runner, local_home, KEY)
    separator = b"\n" if existing and not existing.endswith(b"\n") else b""
    assert keys.read_bytes() == existing + separator + KEY.encode() + b"\n"
    assert keys.stat().st_mode & 0o7777 == 0o600
    assert first.read_text(encoding="utf-8") == "untouched"
    assert second.is_symlink()
    third = ssh / "authorized_keys.bak.3"
    assert third.read_bytes() == existing
    assert third.stat().st_mode & 0o7777 == 0o600
    assert {entry.name for entry in ssh.iterdir()} == {
        keys.name,
        first.name,
        second.name,
        third.name,
    }


def test_shell_backup_failure_leaves_existing_keys_untouched(local_home: Account) -> None:
    ssh = local_home.home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    keys.write_text(OTHER_KEY + "\n", encoding="utf-8")
    keys.chmod(0o640)
    for index in range(1, 1001):
        (ssh / f"authorized_keys.bak.{index}").touch()
    with pytest.raises(UserKeysError, match="publish private authorized_keys backup"):
        ensure_key(local_runner(), local_home, KEY)
    assert keys.read_text(encoding="utf-8") == OTHER_KEY + "\n"
    assert keys.stat().st_mode & 0o7777 == 0o640
    assert not list(ssh.glob(".authorized_keys.*"))


def test_shell_tightens_modes_without_changing_content_or_creating_backup(
    local_home: Account,
) -> None:
    runner = local_runner()
    ssh = local_home.home / ".ssh"
    ssh.mkdir()
    ssh.chmod(0o2755)
    keys = ssh / "authorized_keys"
    existing = f" \t{KEY} \t\r\n"
    keys.write_bytes(existing.encode())
    keys.chmod(0o764)
    assert probe_keys(runner, local_home) == KeyState(existing, False, 0o764)
    assert ensure_key(runner, local_home, KEY)
    assert probe_keys(runner, local_home) == KeyState(existing, True, 0o600)
    assert not ensure_key(runner, local_home, KEY)
    assert list(ssh.iterdir()) == [keys]


@pytest.mark.parametrize(("dir_mode", "key_mode"), [(0o500, 0o600), (0o700, 0o400)])
def test_shell_does_not_widen_permissions(
    local_home: Account, dir_mode: int, key_mode: int
) -> None:
    ssh = local_home.home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    keys.write_text(KEY, encoding="utf-8")
    keys.chmod(key_mode)
    ssh.chmod(dir_mode)
    try:
        with pytest.raises(UserKeysError, match="refusing to widen"):
            ensure_key(local_runner(), local_home, KEY)
        assert ssh.stat().st_mode & 0o7777 == dir_mode
        assert keys.stat().st_mode & 0o7777 == key_mode
        assert keys.read_text(encoding="utf-8") == KEY
    finally:
        ssh.chmod(0o700)


@pytest.mark.parametrize("unsafe", ["ssh_link", "ssh_file", "keys_link", "keys_fifo", "keys_dir"])
def test_shell_rejects_unsafe_paths(local_home: Account, unsafe: str) -> None:
    ssh = local_home.home / ".ssh"
    elsewhere = local_home.home / "elsewhere"
    elsewhere.mkdir()
    sentinel = elsewhere / "authorized_keys"
    sentinel.write_text(SECRET, encoding="utf-8")
    if unsafe == "ssh_link":
        ssh.symlink_to(elsewhere, target_is_directory=True)
    elif unsafe == "ssh_file":
        ssh.touch()
    else:
        ssh.mkdir(mode=0o700)
        keys = ssh / "authorized_keys"
        if unsafe == "keys_link":
            keys.symlink_to(sentinel)
        elif unsafe == "keys_fifo":
            os.mkfifo(keys)
        else:
            keys.mkdir()
    runner = local_runner()
    with pytest.raises(UserKeysError):
        probe_keys(runner, local_home)
    with pytest.raises(UserKeysError):
        ensure_key(runner, local_home, KEY)
    assert sentinel.read_text(encoding="utf-8") == SECRET


def test_shell_source_requires_a_bounded_nonsymlink_regular_file(local_home: Account) -> None:
    runner = local_runner()
    source = local_home.home / "-key ' source"
    source.write_bytes(b"a\r\nb\nc\r")
    assert read_public_key_source(runner, local_home, source) == "a\r\nb\nc\r"
    symlink = local_home.home / "link"
    symlink.symlink_to(source)
    with pytest.raises(UserKeysError, match="regular file"):
        read_public_key_source(runner, local_home, symlink)
    source.chmod(0)
    with pytest.raises(UserKeysError, match="cannot read"):
        read_public_key_source(runner, local_home, source)
    source.chmod(0o600)
    source.write_bytes(b"a" * 1048577)
    with pytest.raises(UserKeysError, match="size limit"):
        read_public_key_source(runner, local_home, source)


def test_shell_does_not_publish_if_append_would_exceed_limit(local_home: Account) -> None:
    ssh = local_home.home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    contents = b"#" * 1048576
    keys.write_bytes(contents)
    keys.chmod(0o600)
    runner = local_runner()
    assert probe_keys(runner, local_home).content == contents.decode()
    with pytest.raises(UserKeysError, match="size limit"):
        ensure_key(runner, local_home, KEY)
    assert keys.read_bytes() == contents
    assert list(ssh.iterdir()) == [keys]


def test_shell_cooperating_updates_do_not_lose_keys(local_home: Account) -> None:
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(ensure_key, local_runner(), local_home, KEY)
        second = pool.submit(ensure_key, local_runner(), local_home, OTHER_KEY)
        assert first.result() and second.result()
    ssh = local_home.home / ".ssh"
    state = probe_keys(local_runner(), local_home)
    assert state.ssh_ready and state.keys_mode == 0o600 and state.content is not None
    assert set(state.content.splitlines()) == {KEY, OTHER_KEY}
    backup = ssh / "authorized_keys.bak.1"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert backup.read_text(encoding="utf-8") in {KEY + "\n", OTHER_KEY + "\n"}
