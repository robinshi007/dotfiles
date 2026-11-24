#!/usr/bin/env bash
# 09: `lhm rollback FILE` restores the newest .bak, after backing up the
# current file (so the rollback itself can be undone).
. /opt/scenarios/lib.sh

target=/etc/sysctl.d/99-lhm.conf
shield_kernel_keys
save_kernel_keys kernel.kptr_restrict kernel.dmesg_restrict
trap restore_kernel_keys EXIT

mkdir -p "$(dirname "$target")"
original='# pre-existing admin content (must come back after rollback)
net.ipv4.conf.all.rp_filter = 0
'
printf '%s' "$original" > "$target"

run_lhm apply sysctl
expect_lhm_ok "apply sysctl (creates 99-lhm.conf.bak)"
assert_file "$target.bak" "backup written before the first change"
# Compare with cmp: `$(cat ...)` strips the trailing newline and would make an
# exact byte comparison impossible.
if printf '%s' "$original" | cmp -s - "$target.bak"; then
    ok "backup holds the original content (byte-identical)"
else
    fail "backup differs from the original content"
fi
assert_contains "$(cat "$target")" "# ===== lhm sysctl hardening =====" "drop-in installed"

run_lhm rollback "$target"
expect_lhm_ok "rollback $target"

if printf '%s' "$original" | cmp -s - "$target"; then
    ok "original content restored (byte-identical)"
else
    fail "original content not restored: $(head -n 2 "$target" | tr '\n' '|')"
fi
assert_file "$target.bak.1" "current file backed up before rollback (undoable)"
assert_contains "$(cat "$target.bak.1")" "# ===== lhm sysctl hardening =====" \
    "rollback backup holds the hardened version"

# Rolling back again must go one step further back (the hardened file), proving
# the newest-backup selection works rather than replaying the same .bak.
run_lhm rollback "$target"
expect_lhm_ok "second rollback $target"
assert_contains "$(cat "$target")" "# ===== lhm sysctl hardening =====" \
    "second rollback restores the hardened version"

# An unmanaged file must be refused even when a matching backup exists.
printf 'no backup here\n' > /tmp/lhm-rollback-orphan
printf 'should not be restored\n' > /tmp/lhm-rollback-orphan.bak
run_lhm rollback /tmp/lhm-rollback-orphan
assert_eq "$LHM_RC" 2 "rollback of unmanaged file exits non-zero"
assert_contains "$LHM_OUT" "lhm-managed" "rollback of unmanaged file explains why"
assert_eq "$(cat /tmp/lhm-rollback-orphan)" "no backup here" "orphan file untouched"

finish
