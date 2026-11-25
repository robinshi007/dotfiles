#!/usr/bin/env bash
# 08: idempotency on real systemd/apt: a second apply of the same modules must
# report no CHANGED, exit 0, and leave every managed file byte-identical.
. /opt/scenarios/lib.sh

require_ssh_test_container
ssh-keygen -q -t ed25519 -N '' -f /root/deploy

run_lhm apply ssh-user deploy --key /root/deploy.pub --sudo
expect_lhm_ok "first apply ssh-user"
setup_ssh_test_client || { fail "configure the SSH test client and sudo"; finish; }
apply_ssh_pending || finish
confirm_ssh_pending || finish

# `apply sysctl` below touches kernel.* keys that are NOT namespaced; shield the
# one-way / container-breaking ones and restore the observable ones (see lib.sh).
shield_kernel_keys
save_kernel_keys kernel.kptr_restrict kernel.dmesg_restrict
trap restore_kernel_keys EXIT

run_lhm apply sysctl
expect_lhm_ok "first apply sysctl"
run_lhm apply fail2ban
expect_lhm_ok "first apply fail2ban"

FILES=(
    /etc/ssh/sshd_config.d/99-lhm.conf
    /etc/sysctl.d/99-lhm.conf
    /etc/fail2ban/jail.d/99-lhm.local
    /home/deploy/.ssh/authorized_keys
)

# Snapshot content + the full backup file list: a second write would either
# change the hash or create a new .bak/.bak.N.
snapshot() {
    local f
    for f in "${FILES[@]}"; do
        printf '%s  ' "$f"
        sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || echo MISSING
    done
    printf 'backups  '
    ls -1 /etc/ssh/sshd_config.d/99-lhm.conf.bak* /etc/sysctl.d/99-lhm.conf.bak* \
          /etc/fail2ban/jail.d/99-lhm.local.bak* 2>/dev/null | tr '\n' ' '
    echo
}
before=$(snapshot)
printf '%s\n' "$before" | sed 's/^/    before| /'

# Second pass: the same three modules, unchanged arguments.
for module in "ssh-hardening" "sysctl" "fail2ban"; do
    if [[ "$module" == ssh-hardening ]]; then
        run_lhm apply "$module" --ssh-user deploy
    else
        run_lhm apply "$module"
    fi
    expect_lhm_ok "second apply $module"
    assert_not_contains "$LHM_OUT" "CHANGED" "second apply $module: no CHANGED"
    assert_contains "$LHM_OUT" "SKIPPED" "second apply $module: SKIPPED reported"
done

after=$(snapshot)
printf '%s\n' "$after" | sed 's/^/    after | /'
assert_eq "$after" "$before" "managed files and .bak set unchanged (sha256sum)"

# ssh-user is idempotent too (user exists, key present).
run_lhm apply ssh-user deploy --key /root/deploy.pub --sudo
expect_lhm_ok "second apply ssh-user"
assert_not_contains "$LHM_OUT" "CHANGED" "second apply ssh-user: no CHANGED"

# `lhm check` is the built-in idempotency audit: the modules applied above must
# be OK. Modules this scenario never applied (firewall, audit, ...) legitimately
# report needs-change, so the assertion is scoped to the three applied areas.
run_lhm check
expect_lhm_ok "lhm check"
check_rows=$(grep -E '^(ssh|sysctl|fail2ban)[[:space:]]' <<< "$LHM_OUT")
for area in ssh sysctl fail2ban; do
    assert_contains "$check_rows" "$area" "lhm check covers $area"
done
assert_not_contains "$check_rows" "needs-change" "applied areas report OK in lhm check"

finish
