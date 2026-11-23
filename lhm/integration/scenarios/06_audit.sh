#!/usr/bin/env bash
# 06: `lhm apply audit` — auditd service, rules drop-in, augenrules.
#
# Kernel caveat: the audit netlink socket is only reachable from the initial
# PID namespace, so auditd/auditctl inside a normal Docker container return
# EPERM even with --privileged (verified on 6.12: `auditctl -s` fails unless
# the container is run with --pid=host, which is incompatible with systemd as
# PID 1). When the kernel refuses audit, this scenario checks the fail-closed
# behaviour and the file/augenrules layer instead, and reports SKIPPED.
. /opt/scenarios/lib.sh

run_lhm apply audit

if auditctl -s >/dev/null 2>&1; then
    expect_lhm_ok "apply audit"
    assert_eq "$(systemctl is-active auditd 2>&1)" "active" "auditd active"
    assert_file /etc/audit/rules.d/99-lhm.rules "99-lhm.rules written"

    check_out=$(augenrules --check 2>&1)
    assert_eq "$?" "0" "augenrules --check clean"
    assert_contains "$(cat /etc/audit/rules.d/99-lhm.rules)" "-w /etc/passwd -p wa -k identity" \
        "identity rules present in the drop-in"

    loaded=$(auditctl -l 2>&1)
    assert_contains "$loaded" "identity" "rules loaded in the kernel (auditctl -l)"
    assert_contains "$loaded" "/etc/passwd" "passwd watch loaded"

    status=$(auditctl -s 2>&1)
    assert_contains "$status" "enabled 2" "rules are immutable (-e 2)"

    # Re-apply must be a no-op: identical file + running auditd. The module
    # must NOT try to reload immutable rules (that would fail by design).
    run_lhm apply audit
    expect_lhm_ok "second apply audit"
    assert_not_contains "$LHM_OUT" "CHANGED" "second apply is a no-op"
    finish
fi

printf '  info  kernel refuses the audit netlink socket in this container; '\
'checking the fail-closed path instead\n'
printf '  info  auditctl -s: %s\n' "$(auditctl -s 2>&1 | head -n 1)"

# The rules file must still be written before the load is attempted.
assert_file /etc/audit/rules.d/99-lhm.rules "99-lhm.rules written"
assert_contains "$(cat /etc/audit/rules.d/99-lhm.rules)" "-k identity" "identity key in rules"
assert_contains "$(cat /etc/audit/rules.d/99-lhm.rules)" "-e 2" "immutable flag is last"

# fail closed: a refused augenrules --load is a FAIL with a rollback hint, not
# a silent success (DESIGN.md safety rule 8).
assert_eq "$LHM_RC" 1 "apply audit exits non-zero when the kernel refuses the load"
assert_contains "$LHM_OUT" "FAIL" "apply audit reports FAIL"
assert_contains "$LHM_OUT" "lhm rollback /etc/audit/rules.d/99-lhm.rules" "rollback hint printed"

assert_eq "$(augenrules --check >/dev/null 2>&1; echo $?)" "0" "augenrules --check accepts the rules"

skip "auditd live checks: kernel denies the audit netlink socket in containers (see README)"
finish
