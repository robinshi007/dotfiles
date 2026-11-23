#!/usr/bin/env bash
# 05: `lhm apply sysctl` against the live kernel.
# kernel.* sysctls are global (not namespaced): see lib.sh shield/restore.
. /opt/scenarios/lib.sh

shield_kernel_keys
save_kernel_keys kernel.kptr_restrict kernel.dmesg_restrict
trap restore_kernel_keys EXIT

run_lhm apply sysctl
expect_lhm_ok "apply sysctl"

assert_file /etc/sysctl.d/99-lhm.conf "99-lhm.conf drop-in written"
assert_contains "$(cat /etc/sysctl.d/99-lhm.conf)" "kernel.kptr_restrict = 2" "drop-in kptr_restrict"
assert_contains "$(cat /etc/sysctl.d/99-lhm.conf)" "net.ipv4.conf.all.rp_filter = 1" "drop-in rp_filter"

# Live values read through /proc/sys, the same path lhm's spot checks use.
assert_eq "$(cat /proc/sys/kernel/kptr_restrict 2>&1)" "2" "live kernel.kptr_restrict=2"
assert_eq "$(cat /proc/sys/kernel/dmesg_restrict 2>&1)" "1" "live kernel.dmesg_restrict=1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>&1)" "1" \
    "live net.ipv4.conf.all.rp_filter=1 (netns-local)"

# Second run: identical file and values already loaded -> no CHANGED, no reload.
run_lhm apply sysctl
expect_lhm_ok "second apply sysctl"
assert_not_contains "$LHM_OUT" "CHANGED" "second apply reports no CHANGED"
assert_eq "$(cat /proc/sys/kernel/kptr_restrict 2>&1)" "2" "value stable across re-apply"

finish
