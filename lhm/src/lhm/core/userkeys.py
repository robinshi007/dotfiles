"""Read and update SSH user files without giving their paths root authority."""

import base64
import re
from dataclasses import dataclass
from pathlib import Path

from lhm.core.runner import CommandResult, Runner

_MAX_BYTES = 1024 * 1024
_MAX_KEY_BYTES = 16 * 1024
_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.-]*\$?")
_ID = re.compile(r"[0-9]{1,10}")
_PREFIX = "LHM_USERKEYS_V1 "


class UserKeysError(RuntimeError):
    """The account or its key files could not be safely handled."""


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    gid: int
    home: Path

    def __post_init__(self) -> None:
        if not (
            _NAME.fullmatch(self.name)
            and type(self.uid) is int
            and 0 < self.uid < 2**32 - 1
            and type(self.gid) is int
            and 0 < self.gid < 2**32 - 1
            and self.home.is_absolute()
            and not any(char in str(self.home) for char in "\0\r\n")
        ):
            raise UserKeysError("invalid non-root account identity or home")


@dataclass(frozen=True)
class KeyState:
    """Raw UTF-8 text (None if absent), exact .ssh readiness, and permission bits.

    An owned .ssh directory is ready only at 0700. A present authorized_keys
    has its full permission bits, including special bits; None means absent.
    Unsafe/unreadable files or directories raise UserKeysError, not absence.
    """

    content: str | None
    ssh_ready: bool
    keys_mode: int | None


def _run(
    runner: Runner, argv: list[str], operation: str, *, redact: frozenset[int] = frozenset()
) -> CommandResult:
    # Do not leak potentially account-controlled command output on errors.
    try:
        return runner.run(argv, check=False, redact=redact, preserve_newlines=True)
    except (
        OSError,
        ValueError,
    ):
        raise UserKeysError(f"{operation} could not execute") from None


def lookup_account(runner: Runner, name: str) -> Account | None:
    """Resolve one exact getent passwd name; only exit status 2 means absent."""
    if not _NAME.fullmatch(name):
        raise UserKeysError("invalid account name")
    result = _run(runner, ["/usr/bin/getent", "passwd", name], "account lookup")
    if result.returncode == 2:
        return None
    if not result.ok:
        raise UserKeysError(f"account lookup failed (rc={result.returncode})")
    record = result.stdout.removesuffix("\n")
    fields = record.split(":")
    if (
        len(fields) != 7
        or any(char in record for char in "\0\r\n")
        or fields[0] != name
        or not _ID.fullmatch(fields[2])
        or not _ID.fullmatch(fields[3])
    ):
        raise UserKeysError("invalid passwd record or account identity mismatch")
    # The primary group may be named users, the login name, or another alias.
    # Its numeric ID is authoritative; do not resolve it from the login name.
    return Account(name, int(fields[2]), int(fields[3]), Path(fields[5]))


# Linux/GNU tools. Hold the .ssh directory open and lock that inode, not a
# user-supplied lockfile. This only serializes cooperating invocations, not
# the account itself. Even a raced path is handled with the target's rights.
_HELPER = r"""
set -uf
umask 077
exec 2>/dev/null

reply() { printf 'LHM_USERKEYS_V1 %s\n' "$*"; }
fail() { reply "ERROR $1"; exit 1; }

op=$1 uid=$2 gid=$3 home=$4 arg=$5 limit=$6
[ "$uid" != 0 ] && [ "$gid" != 0 ] &&
    [ "$(id -u)" = "$uid" ] && [ "$(id -g)" = "$gid" ] || fail identity

inspect() {
    if meta=$(stat -c '%f %u %d:%i %s %y %z' -- "$1" 2>&1); then
        # stat's format here contains no file name.
        set -- $meta
        type_bits=$((0x$1 & 0170000))
        mode=$((0x$1 & 07777))
        owner=$2 inode=$3 size=$4
    else
        case "$meta" in
            *': No such file or directory') meta= type_bits=0 ;;
            *) fail inspect ;;
        esac
    fi
}

read_leaf() {
    # Read at most one byte past the limit to distinguish a full file from
    # truncation. A final symlink is never opened; a raced FIFO cannot block.
    dd if="$1" iflag=nofollow,nonblock,count_bytes bs=65536 \
        count="$((limit + 1))" status=none
}

encode_leaf() {
    # Preserve dd's status separately from base64's (dash has no pipefail).
    payload=$(
        exec 4>&1
        status=$(
            exec 3>&1
            { read_leaf "$1"; printf '%s' "$?" >&3; } | base64 -w0 >&4
        ) || exit 1
        [ "$status" = 0 ]
    ) || fail read
    bytes=$((${#payload} / 4 * 3))
    case "$payload" in
        *==) bytes=$((bytes - 2)) ;;
        *=) bytes=$((bytes - 1)) ;;
    esac
    [ "$bytes" -le "$limit" ] || fail size
}

decode_leaf() { printf '%s' "$payload" | base64 -d; }

if [ "$op" = source ]; then
    inspect "$arg"
    [ "$type_bits" -eq "$((0100000))" ] || fail leaf
    [ "$size" -le "$limit" ] || fail size
    original=$meta
    encode_leaf "$arg"
    inspect "$arg"
    [ "$meta" = "$original" ] || fail raced
    reply "SOURCE $payload"
    exit 0
fi

cd -P -- "$home" || fail home
inspect .
[ "$type_bits" -eq "$((0040000))" ] &&
    { [ "$owner" = 0 ] || [ "$owner" = "$uid" ]; } &&
    [ "$((mode & 0022))" -eq 0 ] || fail home_mode
changed=0
inspect .ssh
if [ "$type_bits" -eq 0 ]; then
    if [ "$op" = probe ]; then
        reply 'STATE 0 -'
        exit 0
    fi
    if mkdir -m 700 -- .ssh; then changed=1; fi
    inspect .ssh
fi
[ "$type_bits" -eq "$((0040000))" ] && [ "$owner" = "$uid" ] || fail directory
dir_inode=$inode
cd -P -- .ssh || fail directory
check_directory() {
    inspect "$home/.ssh"
    [ "$type_bits" -eq "$((0040000))" ] && [ "$owner" = "$uid" ] &&
        [ "$inode" = "$dir_inode" ] || fail raced
}
inspect .
[ "$inode" = "$dir_inode" ] || fail raced
exec 9<.
case "$op" in
    probe) flock -s -w 5 9 || fail lock ;;
    ensure) flock -x -w 5 9 || fail lock ;;
    *) fail operation ;;
esac

check_directory
ready=0
if [ "$mode" -eq "$((0700))" ]; then
    ready=1
elif [ "$op" = ensure ]; then
    [ "$((mode & 0700))" -eq "$((0700))" ] || fail narrow
    chmod 00700 -- . || fail mode
    check_directory
    [ "$mode" -eq "$((0700))" ] || fail mode
    ready=1 changed=1
fi

leaf=authorized_keys
inspect "$leaf"
original=$meta
if [ "$type_bits" -ne 0 ]; then
    [ "$type_bits" -eq "$((0100000))" ] && [ "$owner" = "$uid" ] || fail leaf
    [ "$size" -le "$limit" ] || fail size
    old_mode=$mode
fi

if [ "$op" = probe ]; then
    if [ -z "$original" ]; then
        reply "STATE $ready -"
    else
        encode_leaf "$leaf"
        inspect "$leaf"
        [ "$meta" = "$original" ] || fail raced
        reply "STATE $ready $(printf '%04o' "$old_mode") $payload"
    fi
    exit 0
fi

append=1
if [ -n "$original" ]; then
    [ "$((old_mode & 0600))" -eq "$((0600))" ] || fail narrow
    encode_leaf "$leaf"
    inspect "$leaf"
    [ "$meta" = "$original" ] || fail raced
    decode_leaf | iconv -f UTF-8 -t UTF-8 >/dev/null || fail read
    # ENVIRON avoids awk -v's backslash-escape interpretation.
    append=$(decode_leaf | KEY_LINE="$arg" awk '
        { sub(/^[ \t]+/, ""); sub(/\r$/, ""); sub(/[ \t]+$/, "") }
        $0 == ENVIRON["KEY_LINE"] { found=1 }
        END { print found ? 0 : 1 }
    ') || fail read
    if [ "$append" = 0 ] && [ "$old_mode" -eq "$((0600))" ]; then
        check_directory
        [ "$mode" -eq "$((0700))" ] || fail verify
        reply "CHANGED $changed"
        exit 0
    fi
fi

old= stage=
cleanup() {
    [ -z "$old" ] || rm -f -- "$old"
    [ -z "$stage" ] || rm -f -- "$stage"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

stage=$(mktemp -- .authorized_keys.new.XXXXXXXX) || fail stage
if [ -n "$original" ]; then decode_leaf > "$stage" || fail stage; fi
if [ "$append" = 1 ]; then
    if [ -n "$original" ] && [ "$bytes" -ne 0 ]; then
        last=$(od -An -tu1 -j "$((bytes - 1))" -N1 -- "$stage") || fail stage
        if [ "$last" -ne 10 ]; then printf '\n' >> "$stage" || fail stage; fi
    fi
    printf '%s\n' "$arg" >> "$stage" || fail stage
fi
inspect "$stage"
[ "$type_bits" -eq "$((0100000))" ] && [ "$mode" -eq "$((0600))" ] &&
    [ "$owner" = "$uid" ] || fail stage
[ "$size" -le "$limit" ] || fail size
stage_inode=$inode
sync -- "$stage" || fail stage

if [ -n "$original" ] && [ "$append" = 1 ]; then
    old=$(mktemp -- .authorized_keys.old.XXXXXXXX) || fail backup
    decode_leaf > "$old" || fail backup
    inspect "$old"
    [ "$type_bits" -eq "$((0100000))" ] && [ "$mode" -eq "$((0600))" ] &&
        [ "$owner" = "$uid" ] || fail backup
    sync -- "$old" || fail backup
    index=1
    while :; do
        backup=$leaf.bak.$index
        if ln -T -- "$old" "$backup"; then break; fi
        inspect "$backup"
        [ "$type_bits" -ne 0 ] && [ "$index" -lt 1000 ] || fail backup
        index=$((index + 1))
    done
    sync -- . || fail backup
fi

inspect "$leaf"
[ "$meta" = "$original" ] || fail raced
mv -fT -- "$stage" "$leaf" || fail publish
stage=
sync -- . || fail publish
inspect "$leaf"
[ "$inode" = "$stage_inode" ] && [ "$mode" -eq "$((0600))" ] || fail verify
check_directory
[ "$mode" -eq "$((0700))" ] || fail verify
reply 'CHANGED 1'
"""

_ERRORS = {
    "identity": "privilege drop did not yield the requested UID/GID",
    "home": "account home is not accessible",
    "home_mode": "account home owner or permissions are unsafe for SSH",
    "inspect": "cannot inspect the key path",
    "directory": ".ssh is not an accessible, account-owned directory",
    "leaf": "key path is not an acceptable regular file",
    "lock": "cannot lock the .ssh directory",
    "narrow": "refusing to widen existing SSH permissions",
    "mode": "cannot tighten .ssh permissions",
    "size": "key file exceeds the size limit",
    "read": "cannot read UTF-8 key file",
    "raced": "key path changed during the operation",
    "stage": "cannot stage private authorized_keys",
    "backup": "cannot publish private authorized_keys backup",
    "publish": "cannot publish authorized_keys",
    "verify": "could not verify published authorized_keys",
}


def _as_account(runner: Runner, account: Account, operation: str, arg: str = "") -> str:
    result = _run(
        runner,
        [
            "/usr/bin/setpriv",
            "--reuid",
            str(account.uid),
            "--regid",
            str(account.gid),
            "--clear-groups",
            "--no-new-privs",
            "--",
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LC_ALL=C",
            "/bin/sh",
            "-c",
            _HELPER,
            "lhm-userkeys",
            operation,
            str(account.uid),
            str(account.gid),
            str(account.home),
            arg,
            str(_MAX_BYTES),
        ],
        operation,
        redact=frozenset({14, 20}),  # helper body and public-key line/source path
    )
    frame = result.stdout.removesuffix("\n") if result.stdout.endswith("\n") else ""
    if not result.ok:
        reason = frame.removeprefix(_PREFIX + "ERROR ")
        if frame.startswith(_PREFIX + "ERROR ") and reason in _ERRORS:
            raise UserKeysError(_ERRORS[reason])
        raise UserKeysError(f"{operation} helper failed (rc={result.returncode})")
    if not frame.startswith(_PREFIX) or "\n" in frame or "\r" in frame:
        raise UserKeysError(f"invalid {operation} helper response")
    return frame.removeprefix(_PREFIX)


def _decode(payload: str) -> str:
    if len(payload) > 4 * ((_MAX_BYTES + 2) // 3):
        raise UserKeysError("key file exceeds the size limit")
    try:
        data = base64.b64decode(payload, validate=True)
        if len(data) > _MAX_BYTES:
            raise UserKeysError("key file exceeds the size limit")
        if base64.b64encode(data).decode("ascii") != payload:
            raise ValueError("noncanonical base64")
        return data.decode("utf-8")
    except ValueError:
        raise UserKeysError("invalid UTF-8 key file or encoded helper response") from None


def probe_keys(runner: Runner, account: Account) -> KeyState:
    """Read-only probe as account; cannot run with a dry-run Runner."""
    frame = _as_account(runner, account, "probe")
    absent = re.fullmatch(r"STATE ([01]) -", frame)
    if absent:
        return KeyState(None, absent[1] == "1", None)
    present = re.fullmatch(r"STATE ([01]) ([0-7]{4}) ([A-Za-z0-9+/=]*)", frame)
    if not present:
        raise UserKeysError("invalid probe helper response")
    return KeyState(_decode(present[3]), present[1] == "1", int(present[2], 8))


def ensure_key(runner: Runner, account: Account, key_line: str) -> bool:
    """Install one caller-validated public key line; return whether anything changed.

    Accepts an already validated line without surrounding spaces or tabs.
    Existing lines match after stripping SSH-file whitespace. Modes tighten to 0700/0600
    only; a mode missing any needed owner bit is refused, not widened.
    """
    if (
        not key_line
        or key_line != key_line.strip(" \t")
        or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in key_line)
    ):
        raise UserKeysError("expected one validated public key line")
    try:
        size = len(key_line.encode("utf-8"))
    except UnicodeError:
        raise UserKeysError("expected one UTF-8 public key line") from None
    if size > _MAX_KEY_BYTES:
        raise UserKeysError("public key line exceeds the size limit")
    frame = _as_account(runner, account, "ensure", key_line)
    if frame not in {"CHANGED 0", "CHANGED 1"}:
        raise UserKeysError("invalid ensure helper response")
    return frame == "CHANGED 1"


def read_public_key_source(runner: Runner, account: Account, path: str | Path) -> str:
    """Read a nonsymlink regular source as account, preserving raw UTF-8 text.

    The caller must resolve and validate the invoking identity (e.g. SUDO_UID)
    and parse the returned text as a public key before using it.
    """
    try:
        source = Path(path).absolute()
    except OSError:
        raise UserKeysError("cannot resolve public key source path") from None
    frame = _as_account(runner, account, "source", str(source))
    if not frame.startswith("SOURCE "):
        raise UserKeysError("invalid source helper response")
    return _decode(frame.removeprefix("SOURCE "))
