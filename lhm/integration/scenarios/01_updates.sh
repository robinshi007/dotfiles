#!/usr/bin/env bash
# 01: dry-run plans isolated downloads without touching real APT or network.
. /opt/scenarios/lib.sh

run_lhm apply updates --security-only --dry-run
expect_lhm_ok "security-only dry run"
assert_contains "$LHM_OUT" "isolated apt-get security upgrade" "isolated upgrade is planned"
assert_not_contains "$LHM_OUT" "apt upgrade" "no ordinary upgrade fallback"
if [[ -e /etc/apt/apt.conf.d/51-lhm ]]; then
    fail "refusal must not write an unattended-upgrades policy"
else
    ok "no unattended-upgrades policy was written"
fi

finish
