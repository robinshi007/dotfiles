#!/usr/bin/env bash
# Environment pre-check and Python tooling bootstrap.
#   ./precheck.sh          check only, no changes
#   ./precheck.sh -r       check, then create/install (update/delete ask Yes/No)
#   ./precheck.sh -r -y    check, then create/install/update, no prompts
# Idempotent: safe to re-run.
# Refuse to be sourced: 'exit' below would kill the caller's shell.
(return 0 2>/dev/null) && { echo "precheck.sh: source detected. Run it as './precheck.sh' instead." >&2; return 1; }

set -euo pipefail

ASSUME_YES=0 APPLY=0
while getopts "ry" opt; do
    case $opt in
        r) APPLY=1 ;;
        y) ASSUME_YES=1 ;;
        *) echo "Usage: $0 [-r] [-y]" >&2; exit 1 ;;
    esac
done
((ASSUME_YES && ! APPLY)) && { echo "WARN: -y requires -r" >&2; exit 1; }

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\e[32m' YELLOW=$'\e[33m' RED=$'\e[31m' RESET=$'\e[0m'
else
    GREEN='' YELLOW='' RED='' RESET=''
fi
ok()    { echo "[precheck] ${GREEN}OK: $*${RESET}"; }
warn()  { echo "[precheck] ${YELLOW}WARN: $*${RESET}" >&2; }
error() { echo "[precheck] ${RED}ERROR: $*${RESET}" >&2; }
info()  { echo "[precheck] $*"; }

# Prompt for update/delete ops. Auto-yes with -r -y, asks otherwise, skips on No.
confirm() {
    local msg=$1
    if ((ASSUME_YES)); then return 0; fi
    read -r -p "[precheck] $msg [y/N] " ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ---------- checks (always run, fail closed) ----------
[[ "$SHELL" != */bash ]] && { error "Default shell is '$SHELL', expected bash. Run: chsh -s /bin/bash"; exit 1; }
if [[ "$(bash -c 'echo $BASH_VERSION' 2>/dev/null || true)" =~ ^([0-9]+)\.([0-9]+) ]]; then
    major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]}
    (( major < 5 || (major == 5 && minor < 2) )) && { error "bash ${major}.${minor} found, need >= 5.2."; exit 1; }
else
    error "Cannot determine bash version."; exit 1
fi
ok "bash ${major}.${minor} as default shell"

. /etc/os-release
distro=${ID:-} ver=${VERSION_ID:-}
case "$distro" in
    debian) supported=("12" "13") ;;
    ubuntu) supported=("24.04" "26.04") ;;
    *) error "Unsupported distro: '$distro' (need Debian or Ubuntu)."; exit 1 ;;
esac
[[ " ${supported[*]} " == *" $ver "* ]] || { error "Unsupported $distro version $ver (need one of: ${supported[*]})."; exit 1; }
ok "$PRETTY_NAME"

# ---------- check-only mode ----------
# ---------- tool presence + versions (informational, both modes) ----------
for tool in python3 pipx uv; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool installed: $("$tool" --version 2>&1 | head -1)"
    else
        warn "$tool not installed. Re-run with -r to install"
    fi
done

if command -v uv >/dev/null 2>&1; then
    installed_py=$(uv python list --only-installed 2>/dev/null | awk '$2 ~ /\.local\/share\/uv\// {print $1}' | sed 's/^cpython-//; s/-.*//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -Vu | tr '\n' ' ' || true)
    installed_py=${installed_py% }
    if [[ -n "$installed_py" ]]; then
        ok "uv-managed pythons: $installed_py"
        default_py=$(uv python find 2>/dev/null || true)
        ok "uv default python: $( [[ -n "$default_py" ]] && "$default_py" --version 2>&1 | awk '{print $NF}' || echo "none")"
    else
        warn "uv installed but no uv-managed python. Re-run with -r to install"
    fi
fi

if ((APPLY)); then
    info "Apply mode (-r): will create/install (update/delete: $( ((ASSUME_YES)) && echo auto-yes || echo ask ))"
else
    info "Check-only mode. Re-run with -r to apply, add -y to skip prompts."
    exit 0
fi

# ---------- system update (destructive-ish: ask without -y) ----------
if confirm "Run 'apt update && apt upgrade -y'? (system update)"; then
    sudo apt update
    sudo apt upgrade -y
else
    info "Skipped: apt update/upgrade"
fi

# ---------- install common packages (skip already installed) ----------
pkgs=()
for p in curl git vim ripgrep jq tmux python3 python3-pip pipx; do
    dpkg -s "$p" >/dev/null 2>&1 || pkgs+=("$p")
done
if ((${#pkgs[@]})); then
    info "Installing missing packages: ${pkgs[*]}"
    sudo apt install -y "${pkgs[@]}"
else
    info "OK: all common packages already installed"
fi

# Idempotent ensurepath: skip when PATH entry already in .bashrc (pipx warns on re-run)
if ! grep -qs 'pipx/venvs/bin\|\.local/bin' ~/.bashrc 2>/dev/null; then
    pipx ensurepath >/dev/null
fi
export PATH="$HOME/.local/bin:$PATH"

# ---------- uv via pipx ----------
if ! command -v uv >/dev/null 2>&1; then
    info "Installing uv via pipx..."
    pipx install uv
else
    info "OK: uv $(uv --version | awk '{print $2}') already installed"
fi

# ---------- latest python via uv, set as default ----------
latest=$(uv python list --only-installed 2>/dev/null | sed 's/^cpython-//; s/-.*//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -Vu | tail -1 || true)
fresh=$(uv python list 2>/dev/null | awk '/^ cpython-/ {print $1}' | sed 's/^cpython-//; s/-.*//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -Vu | tail -1 || true)
if [[ -z "$latest" ]]; then
    info "Installing latest cpython via uv..."
    uv python install
elif [[ -n "$fresh" && "$fresh" != "$latest" ]]; then
    # an even newer release exists: that's an update -> ask
    if confirm "Newer python than ${latest} available (${fresh}). Install it?"; then
        uv python install
    else
        info "Skipped: newer python"
    fi
else
    info "OK: python $latest (latest available) already installed"
fi

default_py=$(uv python find 2>/dev/null || true)
if [[ -n "$default_py" && -f "$default_py" ]] && ! grep -qs 'precheck uv python' ~/.bashrc; then
    info "Setting uv python as default in ~/.bashrc"
    cat >> ~/.bashrc <<EOF
# precheck uv python: default to uv-managed python
export PATH="$(dirname "$default_py"):\$PATH"
EOF
fi

info "Done. Open a new shell (or: source ~/.bashrc) to pick up PATH changes."
