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
