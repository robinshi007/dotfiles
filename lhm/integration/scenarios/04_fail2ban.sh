#!/usr/bin/env bash
# 04: `lhm apply fail2ban`: package, jail.d drop-in (never jail.local), the
# caddy-lhm filter, service active, and a working fail2ban-client query.
. /opt/scenarios/lib.sh

# A hand-maintained jail.local must survive byte-identical (it holds the host's
# own jails). Seed one so the checksum comparison has something to compare.
mkdir -p /etc/fail2ban
if [ ! -f /etc/fail2ban/jail.local ]; then
    printf '[DEFAULT]\nbantime = 1h\n\n[dropbear]\nenabled = true\nport = ssh\n' \
        > /etc/fail2ban/jail.local
fi
jail_local_before=$(sha256sum /etc/fail2ban/jail.local | cut -d' ' -f1)

run_lhm apply fail2ban
expect_lhm_ok "apply fail2ban"

assert_eq "$(systemctl is-active fail2ban 2>&1)" "active" "fail2ban active"
assert_eq "$(systemctl is-enabled fail2ban 2>&1)" "enabled" "fail2ban enabled"

dropin=/etc/fail2ban/jail.d/99-lhm.local
assert_file "$dropin" "jail.d/99-lhm.local written"
jail=$(cat "$dropin")
assert_contains "$jail" "port = 22345" "sshd jail uses port 22345"
assert_contains "$jail" "backend = systemd" "sshd jail uses the systemd backend"
assert_contains "$jail" "mode = aggressive" "sshd jail uses aggressive mode"
assert_contains "$jail" "maxretry = 3" "sshd jail maxretry 3"
assert_contains "$jail" "findtime = 30m" "sshd jail findtime 30m"
assert_contains "$jail" "bantime = 8h" "sshd jail bantime 8h"
assert_contains "$jail" "bantime.increment = true" "incrementing bans on"
assert_contains "$jail" "bantime.factor = 3" "increment factor 3"
assert_contains "$jail" "bantime.maxtime = 4w" "increment capped at 4w"
assert_contains "$jail" "bantime.rndtime = 30m" "ban time jitter 30m"
assert_contains "$jail" "enabled = false" "caddy jail off without --caddy"

# The legacy jail.local is never touched.
assert_eq "$(sha256sum /etc/fail2ban/jail.local | cut -d' ' -f1)" "$jail_local_before" \
    "legacy jail.local untouched (sha256sum)"

# increment needs a dbfile; Debian/Ubuntu packaging enables it by default.
db=$(fail2ban-client -d 2>/dev/null | grep -oE "'dbfile', '[^']+'" | cut -d"'" -f4)
if [ -n "$db" ] && [ -f "$db" ]; then
    ok "dbfile present: $db (bantime.increment can persist ban counts)"
else
    fail "no dbfile configured/found (bantime.increment silently does nothing)"
fi

# The daemon must have parsed bantime.increment for the sshd jail.
if dump=$(fail2ban-client -d 2>&1) && grep -q "'sshd', 'bantime.increment', True" <<< "$dump"; then
    ok "fail2ban-client -d reports sshd bantime.increment = true"
else
    fail "fail2ban-client -d lacks sshd bantime.increment = true"
fi

# fail2ban-client talks to the running daemon over its socket: this is the real
# check that the jail parsed and loaded, not just that the file exists.
if out=$(fail2ban-client status sshd 2>&1); then
    ok "fail2ban-client status sshd works"
    assert_contains "$out" "Currently banned" "sshd jail reports ban counters"
else
    fail "fail2ban-client status sshd failed: $(printf '%s' "$out" | tail -n 2 | tr '\n' '|')"
fi

# Effective values, as the daemon reports them.
assert_eq "$(fail2ban-client get sshd bantime 2>&1)" "28800" "sshd bantime = 28800s (8h)"
assert_eq "$(fail2ban-client get sshd maxretry 2>&1)" "3" "sshd maxretry = 3"
assert_eq "$(fail2ban-client get sshd findtime 2>&1)" "1800" "sshd findtime = 1800s (30m)"

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

# --- caddy jail: enabled only with --caddy, and caddy is not in the image ----
# The image deliberately does not install caddy, so enabling the jail would make
# fail2ban fail to start (missing unit). Prove the flag is honest: it turns the
# jail on AND the scenario reports a clear SKIP for the live check.
if command -v caddy >/dev/null 2>&1; then
    run_lhm apply fail2ban --caddy
    expect_lhm_ok "apply fail2ban --caddy"
    assert_file /etc/fail2ban/filter.d/caddy-lhm.conf "caddy-lhm filter installed"
    if fail2ban-client status caddy >/dev/null 2>&1; then
        ok "caddy jail live"
    else
        fail "caddy jail not live"
    fi
else
    # Not a scenario-level skip(): everything above still ran. Caddy is
    # deliberately absent from the image, so the live jail cannot be tested.
    printf '  info  SKIP caddy live jail test: caddy is not installed in the image\n'
    if [ -f /etc/fail2ban/filter.d/caddy-lhm.conf ]; then
        fail "caddy filter written although --caddy was not passed"
    else
        ok "caddy filter not written without --caddy"
    fi
fi

finish
