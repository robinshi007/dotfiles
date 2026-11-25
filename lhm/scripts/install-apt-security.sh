#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s [--help | --dry-run]\n' "${0##*/}"
    printf '%s\n' 'Install the independent APT security worker (first install only).' \
        'Run unprivileged after uv sync. --dry-run shows the plan without sudo.'
}

die() { printf 'install-apt-security: %s\n' "$*" >&2; exit 1; }

dry_run=false
case "$#:${1-}" in
    0:) ;;
    1:--help) usage; exit 0 ;;
    1:--dry-run) dry_run=true ;;
    *) usage >&2; exit 2 ;;
esac
(( EUID != 0 )) || die 'run as an unprivileged user, not with sudo'
umask 077

project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repo=$(cd -- "$project/.." && pwd -P)
commit=$(git -C "$repo" rev-parse --verify 'HEAD^{commit}')
git -C "$repo" show "$commit:lhm/scripts/install-apt-security.sh" |
    cmp -s -- "${BASH_SOURCE[0]}" - || die 'run the installer from reviewed Git HEAD'

python_prefix=$(cd -- "$project" && uv run --locked --no-sync --no-python-downloads \
    --managed-python python -I -S -B -c '
import sys
from pathlib import Path

if (sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 15)
        or sys.prefix == sys.base_prefix):
    raise SystemExit("run uv sync with managed CPython 3.15 first")
print(Path(sys.base_prefix).resolve(strict=True))
') || die 'cannot discover the lhm Python image; check uv sync'
case "$python_prefix" in
    ''|/|/usr|/usr/local|/opt|[!/]*) die 'expected a standalone CPython installation prefix' ;;
esac
[[ $python_prefix != *$'\n'* && -x "$python_prefix/bin/python3.15" &&
    -f "$python_prefix/lib/python3.15/encodings/__init__.py" ]] \
    || die 'CPython prefix is missing the interpreter or its standard library'

git -C "$repo" ls-tree -rz --full-tree "$commit" -- lhm/src/lhm lhm/templates |
    while IFS= read -r -d '' entry; do
        case "${entry%%$'\t'*}:${entry#*$'\t'}" in
            '100644 blob '*:lhm/src/lhm/*.py|'100755 blob '*:lhm/src/lhm/*.py|\
            '100644 blob '*:lhm/templates/*.tmpl|'100755 blob '*:lhm/templates/*.tmpl) ;;
            *) die 'committed worker tree contains an unexpected file' ;;
        esac
    done

printf 'First install at /usr/local/libexec/lhm-apt-security (no APT or timer changes).\n'
printf '  Bundle managed CPython image: %q\n  Archive sources and templates from HEAD: %s\n' \
    "$python_prefix" "$commit"
printf '%s\n' 'Deploy only from a reviewed commit containing both installer and worker.' \
    'Verify the CPython image and all its symlink targets; do not modify them during installation.' \
    'Reinstallation is refused. Stop automatic upgrades before retiring an installed launcher.'
if "$dry_run"; then
    exit 0
fi

printf 'Proceed with sudo? Type y: '
if [[ ! -t 0 ]] || ! IFS= read -r answer || [[ $answer != y ]]; then
    printf '\nAborted.\n' >&2
    exit 3
fi

# Assemble and dereference inputs as the caller, never by following an
# unprivileged path from the privileged process.
bundle=$(mktemp -d)
trap 'rm -rf -- "$bundle"' EXIT
trap 'exit 1' HUP INT TERM
git -C "$repo" archive --format=tar "$commit" lhm/src/lhm lhm/templates |
    tar -xf - -C "$bundle" --strip-components=1 --no-same-permissions
identity=$(/usr/bin/python3 -I -S -B -c '
import runpy
import sys
from pathlib import Path

root = Path(sys.argv[1])
worker = runpy.run_path(str(root / "src/lhm/core/apt_runtime.py"))
(root / "entry.py").write_text(worker["ENTRYPOINT"], encoding="ascii")
print(worker["runtime_identity"](root))
' "$bundle") || die 'cannot identify the committed worker release'
bad=$(find -L "$python_prefix" ! -type d ! -type f -print -quit) \
    || die 'cannot inspect CPython image'
[[ -z $bad ]] || die 'CPython image contains a special file or a dangling link'
tar --dereference --hard-dereference --transform='s,^\.,python,' \
    -cf "$bundle/artifact.tar" -C "$python_prefix" .
tar -rf "$bundle/artifact.tar" -C "$bundle" src templates entry.py
digest=$(sha256sum < "$bundle/artifact.tar")

root_script=$(cat <<'ROOT'
set -euo pipefail
umask 077
cd /
libexec=/usr/local/libexec
dest=$libexec/lhm-apt-security

die() { printf 'install-apt-security: %s\n' "$*" >&2; exit 1; }
trusted_dir() {
    local found
    found=$(find -P "$1" -maxdepth 0 -type d -uid 0 ! -perm /022 -printf x) \
        || die "cannot inspect $1"
    [[ $found == x ]] || die "untrusted directory: $1"
}

trusted_dir /
trusted_dir /usr
trusted_dir /usr/local
if [[ ! -e $libexec && ! -L $libexec ]]; then
    mkdir -m 0755 -- "$libexec" || [[ -d $libexec ]]
fi
trusted_dir "$libexec"
found=$(find -P "$libexec" -mindepth 1 -maxdepth 1 -name lhm-apt-security -printf x -quit) \
    || die "cannot inspect $libexec"
[[ -z $found ]] || die "destination already exists: $dest"

# The private runtime stays in place; rename the sole launcher inode into
# position as the publication point.
stage=$(mktemp -d -- "$libexec/.lhm-apt-security.XXXXXXXX")
publishing=false
cleanup() {
    if ! "$publishing" || [[ -e "$stage/launcher" ]]; then
        rm -rf -- "$stage"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

max_bytes=$((256 * 1024 * 1024))
timeout -k 5s 120s head -c "$((max_bytes + 1))" > "$stage/artifact.tar"
(( $(stat -c %s -- "$stage/artifact.tar") <= max_bytes )) || die 'artifact is too large'
actual=$(sha256sum < "$stage/artifact.tar")
[[ ${actual%% *} == "$1" ]] || die 'artifact digest mismatch'

# Extract only ordinary paths into the private stage, applying our own modes
# and ownership. Do not process links, special files or compressed input.
timeout -k 5s 120s /usr/bin/python3 -I -S -B - "$stage" "$max_bytes" <<'PY'
import shutil
import sys
import tarfile
from pathlib import Path

root = Path(sys.argv[1])
max_bytes = int(sys.argv[2])
size = 0
with tarfile.open(root / "artifact.tar", "r:") as archive:
    for count, member in enumerate(archive, start=1):
        parts = member.name.split("/")
        size += member.size
        if (
            count > 32768 or not 0 <= size <= max_bytes
            or parts[0] not in {"python", "src", "templates", "entry.py"}
            or any(part in {"", ".", ".."} for part in parts)
            or member.type not in {tarfile.DIRTYPE, tarfile.REGTYPE}
            or member.sparse is not None
            or not 0 <= member.size <= max_bytes
            or (parts[0] == "entry.py" and (len(parts) != 1 or not member.isfile()))
            or (parts[0] == "src" and len(parts) > 1 and parts[1] != "lhm")
            or (parts[0] == "src" and member.isfile() and not member.name.endswith(".py"))
            or (parts[0] == "templates" and member.isfile() and not member.name.endswith(".tmpl"))
        ):
            raise SystemExit("install-apt-security: unsafe artifact entry")
        out = root.joinpath(*parts)
        if member.isdir():
            out.mkdir(mode=0o700)
        else:
            with archive.extractfile(member) as source, out.open("xb") as dest:
                shutil.copyfileobj(source, dest)
            if member.mode & 0o100:
                out.chmod(0o700)
PY
rm -- "$stage/artifact.tar"

{
    cat <<'LAUNCH'
#!/bin/sh
set -eu
umask 022
cd /
LAUNCH
    printf 'runtime="%s"\n' "$stage"
    cat <<'LAUNCH'
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root \
    "$runtime/python/bin/python3.15" -I -S -B "$runtime/entry.py" "$@"
LAUNCH
} > "$stage/launcher"
chmod 0755 -- "$stage/launcher"
bad=$(find -P "$stage" \( ! -uid 0 -o -perm /7022 -o \
    \( ! -type d ! -type f \) -o \( -type f -links +1 \) \) -printf x -quit) \
    || die 'cannot inspect staged worker tree'
[[ -z $bad ]] || die 'staged worker tree contains an untrusted path'
timeout -k 5s 30s "$stage/launcher" --probe > "$stage/probe" || die 'staged worker probe failed'
printf '%s\n' "$2" | cmp -s -- "$stage/probe" - || die 'staged worker protocol or build mismatch'
rm -- "$stage/probe"

publishing=true
/usr/bin/python3 -I -S -B - "$stage/launcher" "$dest" <<'PY'
import ctypes
import os
import sys

try:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    raise SystemExit("install-apt-security: atomic no-replace rename is unavailable")

renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
renameat2.restype = ctypes.c_int
AT_FDCWD, RENAME_NOREPLACE = -100, 1
src, dest = map(os.fsencode, sys.argv[1:])
if renameat2(AT_FDCWD, src, AT_FDCWD, dest, RENAME_NOREPLACE) != 0:
    raise SystemExit(
        f"install-apt-security: cannot publish launcher without replacing: "
        f"{os.strerror(ctypes.get_errno())}"
    )
PY
printf 'Installed %s (runtime: %s)\n' "$dest" "$stage"
ROOT
)
sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/bash -c "$root_script" bash "${digest%% *}" "$identity" < "$bundle/artifact.tar"
