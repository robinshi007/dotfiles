#!/usr/bin/env bash
# 01: `lhm apply updates` on a real Ubuntu: unattended-upgrades installed and
# the 51-lhm security-only apt config written.
. /opt/scenarios/lib.sh

run_lhm apply updates
expect_lhm_ok "apply updates"
assert_contains "$LHM_OUT" "verify: service active/enabled and 51-lhm current" "verify step OK"

assert_file /etc/apt/apt.conf.d/51-lhm "51-lhm written"
conf=$(cat /etc/apt/apt.conf.d/51-lhm)
assert_contains "$conf" 'APT::Periodic::Unattended-Upgrade "1";' "unattended-upgrade enabled in 51-lhm"
assert_contains "$conf" 'Unattended-Upgrade::Allowed-Origins' "security-only origins present"
# The template escapes `$` as `$$` for string.Template, so the rendered file must
# contain unattended-upgrades' own `${distro_id}` placeholders exactly once
# (a literal `$$` would mean double-substitution broke them).
assert_contains "$conf" '"${distro_id}:${distro_codename}-security";' "apt placeholders rendered"
assert_not_contains "$conf" '$$' "no leftover template escaping ($$)"

# unattended-upgrades ships a oneshot unit triggered by apt-daily-upgrade.timer:
# `is-enabled` is the meaningful state, `is-active` only after a run.
assert_eq "$(systemctl is-enabled unattended-upgrades 2>&1)" \
    "enabled" "unattended-upgrades enabled"
assert_eq "$(dpkg-query -W -f='${Status}' unattended-upgrades 2>&1)" \
    "install ok installed" "unattended-upgrades package installed"
printf '  info  unattended-upgrades is-active: %s (oneshot, triggered by apt-daily-upgrade.timer)\n' \
    "$(systemctl is-active unattended-upgrades 2>&1)"

finish
