#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s [--help | --dry-run]\n' "${0##*/}"
    printf '%s\n' 'Install the independent SSH rollback runtime (first install only).' \
        'Run unprivileged after uv sync. --dry-run shows the plan without sudo.'
}

die() { printf 'install-ssh-watchdog: %s\n' "$*" >&2; exit 1; }

dry_run=false
case "$#:${1-}" in
    0:) ;;
    1:--help) usage; exit 0 ;;
    1:--dry-run) dry_run=true ;;
    *) usage >&2; exit 2 ;;
esac
(( EUID != 0 )) || die 'run as an unprivileged user, not with sudo'

project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repo=$(cd -- "$project/.." && pwd -P)
commit=$(git -C "$repo" rev-parse --verify 'HEAD^{commit}')
discovery=$(cd -- "$project" && uv run --locked --no-sync --no-python-downloads \
    --managed-python python -I -B -c '
import sys
from pathlib import Path
from lhm.modules.ssh_watchdog import _runtime_identity

if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 15):
    raise SystemExit("run uv sync with managed CPython 3.15 first")
if sys.prefix == sys.base_prefix:
    raise SystemExit("run uv sync in the lhm project first")
print(Path(sys.base_prefix).resolve(strict=True))
print(_runtime_identity())
') || die 'cannot discover the lhm CLI runtime; check uv sync'
python_prefix=${discovery%%$'\n'*}
identity=${discovery#*$'\n'}
[[ $discovery == *$'\n'* && $identity != *$'\n'* && -n $identity ]] \
    || die 'invalid CLI runtime discovery output'
case "$python_prefix" in
    ''|/|/usr|/usr/local|/opt|[!/]*) die 'expected a standalone CPython installation prefix' ;;
esac
[[ -x "$python_prefix/bin/python3.15" &&
    -f "$python_prefix/lib/python3.15/encodings/__init__.py" ]] \
    || die 'CPython prefix is missing the interpreter or its standard library'

# Git archives preserve symlinks. Refuse them (and anything but Python sources)
# before sending any archive to the privileged process.
git -C "$repo" ls-tree -rz --full-tree "$commit" -- lhm/src/lhm |
    while IFS= read -r -d '' entry; do
        case "${entry%%$'\t'*}" in
            '100644 blob '*|'100755 blob '*) ;;
            *) die 'committed lhm package contains a non-regular file' ;;
        esac
        [[ ${entry#*$'\t'} == *.py ]] || die 'committed lhm package contains non-Python files'
    done

printf 'First install at /opt/lhm-ssh-rollback (no SSH or service changes).\n'
printf '  Copy full CPython image: %q\n  Archive lhm sources from commit: %s\n' \
    "$python_prefix" "$commit"
printf '  Probe for exact CLI identity: %s\n' "$identity"
printf '%s\n' 'The administrator must trust the release, CPython image, and all its symlink targets.' \
    'Do not proceed with an active SSH transaction or concurrent changes to these inputs.'
if "$dry_run"; then
    exit 0
fi

printf 'Proceed with sudo? Type y: '
if [[ ! -t 0 ]] || ! IFS= read -r answer || [[ $answer != y ]]; then
    printf '\nAborted.\n' >&2
    exit 3
fi

archive=$(mktemp)
trap 'rm -f -- "$archive"' EXIT
trap 'exit 1' HUP INT TERM
git -C "$repo" archive --format=tar "$commit:lhm/src" lhm > "$archive"
digest=$(sha256sum < "$archive")
digest=${digest%% *}

# Keep the archive on stdin and the script in fixed code; root never opens an
# archive by a path in the user checkout or temp directory.
root_script=$(cat <<'ROOT'
set -euo pipefail
umask 077
cd /
python_prefix=$1
identity=$2
digest=$3
opt=/opt
run=/run
dest=$opt/lhm-ssh-rollback
state=$run/lhm-ssh-rollback

die() { printf 'install-ssh-watchdog: %s\n' "$*" >&2; exit 1; }

trusted_dir() {
    local found
    found=$(find -P "$1" -maxdepth 0 -type d -uid 0 ! -perm /022 -printf x) \
        || die "cannot inspect $1"
    [[ $found == x ]] || die "untrusted directory: $1"
}

# Enumerate an inspected parent: unlike test -e, this sees dangling links and
# distinguishes an absent entry from a failed inspection.
entry() {
    find -P "$1" -mindepth 1 -maxdepth 1 -name "$2" -printf x -quit
}

check_available() {
    local found
    trusted_dir /
    trusted_dir "$opt"
    trusted_dir "$run"
    found=$(entry "$run" lhm-ssh-rollback) || die "cannot inspect $run"
    if [[ -n $found ]]; then
        trusted_dir "$state"
        found=$(entry "$state" pending.json) || die "cannot inspect $state"
        [[ -z $found ]] || die 'an SSH rollback transaction is pending'
    fi
    found=$(entry "$opt" lhm-ssh-rollback) || die "cannot inspect $opt"
    [[ -z $found ]] || die "destination already exists: $dest"
}

check_available
stage=$(mktemp -d -- "$opt/.lhm-ssh-rollback.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
cat > "$stage/source.tar"
actual=$(sha256sum < "$stage/source.tar")
[[ ${actual%% *} == "$digest" ]] || die 'source archive digest mismatch'

runtime=$stage/runtime
mkdir -p -- "$runtime/python" "$runtime/src"
bad=$(find -L "$python_prefix" ! -type d ! -type f -print -quit) \
    || die 'cannot inspect CPython image'
[[ -z $bad ]] || die 'CPython image contains a special file or a dangling link'
cp -RL -- "$python_prefix/." "$runtime/python/"
tar -xf "$stage/source.tar" -C "$runtime/src" --no-same-owner --no-same-permissions
chmod -R go-w,a-s,a-t -- "$runtime"

bad=$(find -P "$runtime" \( ! -uid 0 -o -perm /7022 \
    -o \( ! -type d ! -type f \) -o \( -type f -links +1 \) \) -print -quit)
[[ -z $bad ]] || die 'staged runtime contains an untrusted path'
bad=$(find -P "$runtime/src" -type f ! -name '*.py' -print -quit)
[[ -z $bad && -f "$runtime/src/lhm/__init__.py" &&
    -f "$runtime/src/lhm/modules/ssh_watchdog.py" ]] || die 'invalid staged worker sources'

# Match the launcher's isolated prefix checks and probe the real worker.
"$runtime/python/bin/python3.15" -I -S -B -c '
import sys
src, op, txid = sys.argv[1:]
prefix = sys.executable.rsplit("/", 2)[0]
if (sys.version_info[:2] != (3, 15) or sys.prefix != prefix
        or sys.exec_prefix != prefix or sys.base_prefix != prefix
        or not all(p.startswith(prefix + "/") for p in sys.path)):
    raise SystemExit("invalid SSH rollback interpreter prefix")
sys.path.append(src)
from lhm.modules.ssh_watchdog import main
raise SystemExit(main(op, txid))
' "$runtime/src" probe 00000000000000000000000000000000 > "$stage/probe"
printf '%s\n' "$identity" | cmp -s -- "$stage/probe" - \
    || die 'worker protocol/schema or source fingerprint mismatch'

check_available
# Never fall back to a separate existence check and rename.
"$runtime/python/bin/python3.15" -I -S -B -c '
import ctypes
import os
import sys

try:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    raise SystemExit("install-ssh-watchdog: atomic no-replace rename is unavailable")

renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
renameat2.restype = ctypes.c_int
AT_FDCWD, RENAME_NOREPLACE = -100, 1
src, dest = map(os.fsencode, sys.argv[1:])
if renameat2(AT_FDCWD, src, AT_FDCWD, dest, RENAME_NOREPLACE) != 0:
    error = os.strerror(ctypes.get_errno())
    raise SystemExit(f"install-ssh-watchdog: cannot atomically publish runtime: {error}")
' "$runtime" "$dest"
found=$(entry "$stage" runtime) || die "cannot inspect $stage after publish"
[[ -z $found ]] || die "destination was not published: $dest"
printf 'Installed %s\n' "$dest"
ROOT
)
sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/bash -c "$root_script" bash "$python_prefix" "$identity" "$digest" < "$archive"
