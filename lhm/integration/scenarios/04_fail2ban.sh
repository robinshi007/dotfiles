#!/usr/bin/env bash
# 04: `lhm apply fail2ban`: package, sshd jail on 22345, service active, and a
# working fail2ban-client query (jail really loaded by the daemon).
. /opt/scenarios/lib.sh

run_lhm apply fail2ban
expect_lhm_ok "apply fail2ban"

assert_eq "$(systemctl is-active fail2ban 2>&1)" "active" "fail2ban active"
assert_eq "$(systemctl is-enabled fail2ban 2>&1)" "enabled" "fail2ban enabled"
assert_file /etc/fail2ban/jail.local "jail.local written"

jail=$(cat /etc/fail2ban/jail.local)
assert_contains "$jail" "port = 22345" "jail.local sshd jail uses port 22345"
assert_contains "$jail" "backend = systemd" "jail.local uses the systemd backend"
assert_contains "$jail" "enabled = true" "sshd jail enabled"

# fail2ban-client talks to the running daemon over its socket: this is the real
# check that the jail parsed and loaded, not just that the file exists.
if out=$(fail2ban-client status sshd 2>&1); then
    ok "fail2ban-client status sshd works"
    assert_contains "$out" "Currently banned" "sshd jail reports ban counters"
else
    fail "fail2ban-client status sshd failed: $(printf '%s' "$out" | tail -n 2 | tr '\n' '|')"
fi

# The jail must be present in the daemon's live jail list too.
assert_contains "$(fail2ban-client status 2>&1)" "sshd" "sshd in the live jail list"

# The template's banaction is nftables-multiport: prove a ban really lands in
# the ruleset. Without the nft binary (only a Recommends of fail2ban) the jail
# still starts but every ban fails at runtime.
if command -v nft >/dev/null 2>&1; then
    if nft list tables >/dev/null 2>&1; then ok "nftables reachable for banaction"; else
        fail "nft list tables failed (banaction nftables-multiport cannot work)"
    fi
    if out=$(fail2ban-client set sshd banip 203.0.113.7 2>&1); then
        ok "fail2ban-client set sshd banip accepted"
    else
        fail "manual ban failed: $(printf '%s' "$out" | tail -n 2 | tr '\n' '|')"
    fi
    sleep 1
    banned=$(fail2ban-client status sshd 2>&1)
    assert_contains "$banned" "203.0.113.7" "banned IP listed by the jail"
    ruleset=$(nft list ruleset 2>&1)
    assert_contains "$ruleset" "f2b-table" "ban created the f2b nftables table"
    # Unban again so the jail is left clean for the log/state assertions.
    fail2ban-client set sshd unbanip 203.0.113.7 >/dev/null 2>&1 || true
else
    fail "nft binary missing: banaction nftables-multiport cannot work (nftables is only a Recommends of fail2ban)"
fi

finish
