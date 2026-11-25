#!/usr/bin/env bash
# 03: `lhm apply firewall` inside a privileged container.
# A container netns is NOT the host firewall, so this asserts ufw's own state
# and rule ordering only. It deliberately does not test host connectivity.
. /opt/scenarios/lib.sh

require_ssh_test_container
# SSH must already be hardened (the module probes live listeners); a fresh
# container has sshd on 22, which lhm must keep open as well as 22345.
ssh-keygen -q -t ed25519 -N '' -f /root/deploy
run_lhm apply ssh-user deploy --key /root/deploy.pub
expect_lhm_ok "apply ssh-user deploy (precondition)"
setup_ssh_test_client || { fail "configure the SSH test client and sudo"; finish; }
apply_ssh_pending --ssh-user deploy || finish
confirm_ssh_pending || finish

run_lhm apply firewall
expect_lhm_ok "apply firewall"

status=$(ufw status verbose 2>&1)
printf '%s\n' "$status" | sed 's/^/    ufw| /'

assert_contains "$status" "Status: active" "ufw active"
assert_contains "$status" "Default: deny (incoming)" "default deny incoming"
assert_contains "$status" "allow (outgoing)" "default allow outgoing"
assert_contains "$status" "22345/tcp" "22345/tcp allowed"
assert_contains "$status" "ALLOW IN" "explicit ALLOW IN rule present"

# Ordering: the SSH allow rule must appear before any default deny is implied
# for the port; more precisely, 22345 must be the first allowed rule so an
# operator reading `ufw status` sees the anti-lockout rule first.
first_rule=$(printf '%s\n' "$status" | awk '/^--/{flag=1;next} flag && NF {print; exit}')
assert_contains "$first_rule" "22345/tcp" "22345/tcp is the FIRST rule (anti-lockout order)"

# Default-deny must be recorded in ufw's own config, not just the live ruleset.
assert_contains "$(cat /etc/ufw/ufw.conf 2>&1)" "ENABLED=yes" "ufw enabled in /etc/ufw/ufw.conf"
assert_contains "$(sed -n 's/^DEFAULT_INPUT_POLICY=//p' /etc/default/ufw 2>&1)" "DROP" \
    "DEFAULT_INPUT_POLICY=DROP in /etc/default/ufw"

finish
