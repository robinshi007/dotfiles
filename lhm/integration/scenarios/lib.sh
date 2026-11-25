#!/usr/bin/env bash
# Shared helpers for lhm integration scenarios. Sourced, never executed.
# Every scenario runs inside a fresh privileged systemd container with
# LHM_CONFIRM_BYPASS=1 already set by run.sh.
set -uo pipefail

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

ok()   { PASS_COUNT=$((PASS_COUNT + 1)); printf '  PASS  %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '  FAIL  %s\n' "$*"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf '  SKIP  %s\n' "$*"; }

# assert_contains OUTPUT NEEDLE LABEL
assert_contains() {
    if printf '%s' "$1" | grep -qF -- "$2"; then ok "$3"; else
        fail "$3 (expected '$2' in: $(printf '%s' "$1" | tail -n 3 | tr '\n' '|'))"
    fi
}

# assert_not_contains OUTPUT NEEDLE LABEL
assert_not_contains() {
    if printf '%s' "$1" | grep -qF -- "$2"; then
        fail "$3 (unexpected '$2')"
    else ok "$3"; fi
}

# assert_eq ACTUAL EXPECTED LABEL
assert_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else fail "$3 (got '$1', want '$2')"; fi
}

assert_file() {
    if [ -f "$1" ]; then ok "$2"; else fail "$2 (missing $1)"; fi
}

# run_lhm ARGS...: run lhm, keep combined output in $LHM_OUT and the exit code
# in $LHM_RC, and echo the output so `docker logs` shows what happened.
# Never aborts: each scenario decides what a non-zero rc means.
run_lhm() {
    printf -- '-- lhm %s\n' "$*"
    LHM_OUT=$(lhm "$@" 2>&1)
    LHM_RC=$?
    printf '%s\n' "$LHM_OUT" | sed 's/^/    /'
    return 0
}

expect_lhm_ok() {
    assert_eq "$LHM_RC" 0 "$1 (exit 0)"
}

# --- SSH watchdog (02, 03 and 08) --------------------------------------------
require_ssh_test_container() {
    if [[ ${container:-} != docker || ! -f /.dockerenv ||
          ! -d /run/systemd/system || $EUID != 0 ]]; then
        fail "SSH scenarios require a fresh lhm systemd test container"
        finish
    fi
}

setup_ssh_test_client() {
    local host_key
    host_key=$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub) || return 1
    printf '%s %s\n' 127.0.0.1 "$host_key" '[127.0.0.1]:22345' "$host_key" \
        > /root/lhm-test-known-hosts || return 1
    SSH_OPTS=(-F /dev/null -o StrictHostKeyChecking=yes
              -o UserKnownHostsFile=/root/lhm-test-known-hosts -o GlobalKnownHostsFile=/dev/null
              -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o BatchMode=yes
              -o ConnectTimeout=10)

    # Container only: keep sshd's context and let 02 try the test bypass.
    install -m 0440 /dev/null /etc/sudoers.d/lhm-integration || return 1
    cat > /etc/sudoers.d/lhm-integration <<'EOF' || return 1
Defaults:deploy env_keep += "SSH_CONNECTION LHM_CONFIRM_BYPASS"
deploy ALL=(root) NOPASSWD: /usr/local/bin/lhm apply ssh-hardening, \
    /usr/local/bin/lhm apply ssh-hardening --ssh-user deploy, /usr/local/bin/lhm ssh-confirm *
EOF
    visudo -cf /etc/sudoers.d/lhm-integration
}

# Each call opens a fresh connection; args are fixed words or the validated ID.
run_ssh_lhm() {
    local port=$1 answers=$2
    shift 2
    printf -- '-- SSH on %s: sudo lhm %s\n' "$port" "$*"
    LHM_OUT=$(ssh "${SSH_OPTS[@]}" -tt -p "$port" -i /root/deploy deploy@127.0.0.1 \
        sudo -n /usr/local/bin/lhm "$@" <<< "$answers" 2>&1)
    LHM_RC=$?
    printf '%s\n' "$LHM_OUT" | tr -d '\r' | sed 's/^/    /'
}

apply_ssh_pending() {
    run_ssh_lhm 22 y apply ssh-hardening "$@"
    if [[ $LHM_RC != 0 ]]; then
        fail "apply ssh-hardening did not reach pending (exit $LHM_RC)"
        return 1
    fi
    LHM_SSH_ID=$(grep -oE 'lhm ssh-confirm [[:alnum:]_-]+' <<< "$LHM_OUT" | cut -d' ' -f3 | sort -u)
    if [[ ! $LHM_SSH_ID =~ ^[[:alnum:]][[:alnum:]_-]*$ ]]; then
        fail "pending SSH apply did not report exactly one ssh-confirm ID"
        return 1
    fi
    ok "SSH apply reported a pending confirmation ID"
}

confirm_ssh_pending() {
    run_ssh_lhm 22345 y ssh-confirm "$LHM_SSH_ID"
    expect_lhm_ok "confirm SSH hardening via a fresh key login, sudo and one TTY answer"
    [[ $LHM_RC == 0 ]]
}

# --- kernel.global sysctls ----------------------------------------------------
# kernel.* sysctls are NOT namespaced: a container writing them changes the
# HOST kernel. The template sets a few that are irreversible or disruptive in a
# container, so the scenarios bind-mount /dev/null over them (writes discarded,
# reads empty) and restore the observable keys on exit.
KERNEL_SHIELDS=(kernel/kexec_load_disabled kernel/unprivileged_userns_clone
                kernel/unprivileged_bpf_disabled kernel/yama/ptrace_scope
                kernel/perf_event_paranoid
                fs/suid_dumpable fs/protected_hardlinks fs/protected_symlinks
                fs/protected_fifos fs/protected_regular)

shield_kernel_keys() {
    local key
    for key in "${KERNEL_SHIELDS[@]}"; do
        if mount --bind /dev/null "/proc/sys/$key" 2>/dev/null; then
            printf '  info  shielded %s from host writes\n' "${key//\//.}"
        else
            printf '  info  could not shield %s (host value may change)\n' "${key//\//.}"
        fi
    done
}

# save_kernel_keys KEY...: remember values so restore_kernel_keys can undo them.
SAVED_KEYS=()
save_kernel_keys() {
    local key
    for key in "$@"; do
        SAVED_KEYS+=("$key=$(sysctl -n "$key" 2>/dev/null)")
    done
}

restore_kernel_keys() {
    local entry key value
    for entry in "${SAVED_KEYS[@]:-}"; do
        [ -n "$entry" ] || continue
        key=${entry%%=*}
        value=${entry#*=}
        [ -n "$value" ] || continue
        sysctl -q -w "$key=$value" 2>/dev/null || true
    done
}

# wait_service NAME [TIMEOUT]
wait_service() {
    local name=$1 limit=${2:-30} i
    for i in $(seq 1 "$limit"); do
        systemctl is-active --quiet "$name" && return 0
        sleep 1
    done
    return 1
}

finish() {
    printf '  -- %d passed, %d failed, %d skipped\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    [ "$FAIL_COUNT" -eq 0 ] || exit 1
    [ "$SKIP_COUNT" -eq 0 ] || exit 77
    exit 0
}
