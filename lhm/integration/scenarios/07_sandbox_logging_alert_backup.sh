#!/usr/bin/env bash
# 07: sandbox, logging, alert and backup modules in one container.
#   sandbox ssh      -> drop-in + systemd-analyze security on the real unit
#   logging          -> persistent journal directory
#   alert            -> timer active; webhook delivery is NOT required (pointed
#                       at https://127.0.0.1:1/hook, which fails silently)
#   backup --target  -> timer active, one archived run with a sha256 manifest
. /opt/scenarios/lib.sh

echo "-- sandbox ssh --"
run_lhm apply sandbox ssh
expect_lhm_ok "apply sandbox ssh"
dropin=/etc/systemd/system/ssh.service.d/99-lhm-sandbox.conf
assert_file "$dropin" "sandbox drop-in written for ssh.service"
assert_contains "$(cat "$dropin")" "ProtectHome=read-only" "ProtectHome=read-only (sshd key reads)"
if out=$(systemd-analyze security ssh.service 2>&1); then
    ok "systemd-analyze security ssh.service runs"
    assert_contains "$out" "Overall exposure level" "exposure score reported"
else
    fail "systemd-analyze security ssh.service failed: $(printf '%s' "$out" | tail -n 2 | tr '\n' '|')"
fi
assert_eq "$(systemctl is-active ssh 2>&1)" "active" "ssh still runs under the sandbox"

echo "-- logging --"
run_lhm apply logging
expect_lhm_ok "apply logging"
assert_file /etc/systemd/journald.conf.d/99-lhm.conf "journald drop-in written"
assert_file /etc/logrotate.d/lhm-audit "logrotate config written"
if [ -d /var/log/journal ]; then ok "/var/log/journal exists (persistent journal)"; else
    fail "/var/log/journal missing after logging apply"
fi
assert_contains "$(cat /etc/systemd/journald.conf.d/99-lhm.conf)" "Storage=persistent" \
    "Storage=persistent configured"

echo "-- alert --"
run_lhm apply alert --webhook https://127.0.0.1:1/hook
expect_lhm_ok "apply alert"
assert_file /usr/local/lib/lhm/lhm-alert.sh "alert script installed"
assert_eq "$(stat -c '%a' /usr/local/lib/lhm/lhm-alert.sh 2>&1)" "700" "alert script is 0700 (secret)"
assert_eq "$(systemctl is-active lhm-alert.timer 2>&1)" "active" "lhm-alert.timer active"
assert_contains "$(cat /usr/local/lib/lhm/lhm-alert.sh)" "127.0.0.1:1" "webhook URL in the script only"
assert_not_contains "$(cat /etc/systemd/system/lhm-alert.service)" "127.0.0.1" \
    "unit file has no webhook URL"
# A delivery attempt is allowed to fail (by design) but must not kill the unit.
if out=$(/usr/local/lib/lhm/lhm-alert.sh 2>&1); then
    ok "alert script runs once with an unreachable webhook"
else
    fail "alert script crashed: $(printf '%s' "$out" | tail -n 2 | tr '\n' '|')"
fi

echo "-- backup --"
run_lhm apply backup --target /var/backups/lhm
expect_lhm_ok "apply backup"
assert_eq "$(systemctl is-active lhm-backup.timer 2>&1)" "active" "lhm-backup.timer active"
assert_eq "$(systemctl is-enabled lhm-backup.timer 2>&1)" "enabled" "lhm-backup.timer enabled"

archives=$(ls -1 /var/backups/lhm/lhm-backup-*.tar.gz 2>/dev/null | wc -l)
if [ "$archives" -ge 1 ]; then ok "backup archive present ($archives)"; else
    fail "no lhm-backup-*.tar.gz in /var/backups/lhm"
fi
latest=$(ls -1t /var/backups/lhm/lhm-backup-*.tar.gz 2>/dev/null | head -n 1)
if [ -n "$latest" ] && [ -f "$latest.sha256" ]; then ok "sha256 manifest next to the newest archive"; else
    fail "sha256 manifest missing for $latest"
fi
if [ -n "$latest" ] && (cd /var/backups/lhm && sha256sum -c "$(basename "$latest").sha256" >/dev/null 2>&1); then
    ok "manifest verifies"
else
    fail "sha256sum -c failed for the newest archive"
fi

# One extra direct run to prove the script is re-runnable (rotation path).
# STAMP has second granularity, so two runs in the same second reuse one name;
# sleep past the boundary or the "new archive" assertion can never hold.
sleep 1
before=$archives
out=$(/usr/local/lib/lhm/lhm-backup.sh 2>&1)
rc=$?
assert_eq "$rc" 0 "backup script rerun exits 0"
after=$(ls -1 /var/backups/lhm/lhm-backup-*.tar.gz 2>/dev/null | wc -l)
if [ "$after" -gt "$before" ]; then ok "rerun produced a new archive ($before -> $after)"; else
    fail "rerun produced no new archive ($before -> $after)"
fi

finish
