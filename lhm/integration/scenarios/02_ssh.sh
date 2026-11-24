#!/usr/bin/env bash
# 02: SSH anti-lockout chain end to end.
#   deploy user + authorized_keys -> sshd drop-in -> socket unit dance -> reload
#   -> sshd -T agreement -> real TCP listener -> real key login and watchdog
#   confirmation (and real rejection with a wrong key).
. /opt/scenarios/lib.sh

require_ssh_test_container
ssh-keygen -q -t ed25519 -N '' -f /root/deploy
ssh-keygen -q -t ed25519 -N '' -f /root/wrong

# Container-specific safety: the base image enables ssh.socket (Debian/Ubuntu
# 24.04 default), so lhm must disable it or port 22345 would never listen.
printf '  info  before: ssh.socket=%s ssh.service=%s\n' \
    "$(systemctl is-enabled ssh.socket 2>&1)" "$(systemctl is-enabled ssh.service 2>&1)"

run_lhm apply ssh-user deploy --key /root/deploy.pub --sudo
expect_lhm_ok "apply ssh-user deploy"

assert_eq "$(id -u deploy 2>&1 | grep -c .)" "1" "deploy user exists"
assert_eq "$(stat -c '%a' /home/deploy/.ssh)" "700" "~deploy/.ssh is 0700"
assert_eq "$(stat -c '%a' /home/deploy/.ssh/authorized_keys)" "600" "authorized_keys is 0600"
assert_eq "$(stat -c '%U' /home/deploy/.ssh/authorized_keys)" "deploy" "authorized_keys owned by deploy"
assert_contains "$(cat /home/deploy/.ssh/authorized_keys)" "$(cut -d' ' -f1,2 /root/deploy.pub)" \
    "public key installed"

setup_ssh_test_client || { fail "configure the SSH test client and sudo"; finish; }
apply_ssh_pending || finish

assert_file /etc/ssh/sshd_config.d/99-lhm.conf "99-lhm.conf drop-in written"
assert_contains "$(cat /etc/ssh/sshd_config.d/99-lhm.conf)" "Port 22345" "drop-in sets Port 22345"

effective=$(sshd -T 2>&1)
assert_contains "$effective" "port 22345" "sshd -T port 22345"
assert_contains "$effective" "permitrootlogin no" "sshd -T permitrootlogin no"
assert_contains "$effective" "passwordauthentication no" "sshd -T passwordauthentication no"
assert_contains "$effective" "allowusers deploy" "sshd -T allowusers deploy"

# Socket activation must be gone, otherwise sshd never binds 22345.
if systemctl is-active --quiet ssh.socket; then
    fail "ssh.socket still active (would own port 22)"
else
    ok "ssh.socket disabled"
fi

listening=$(ss -tln 2>&1)
assert_contains "$listening" ":22345" "sshd LISTENs on 22345 (ss -tln)"
assert_not_contains "$listening" ":22 " "sshd no longer LISTENs on 22"

if systemctl is-active --quiet ssh; then ok "ssh.service active"; else fail "ssh.service inactive"; fi

# Real end-to-end login: the only network path this test accepts.
if out=$(ssh "${SSH_OPTS[@]}" -p 22345 -i /root/deploy deploy@127.0.0.1 true 2>&1); then
    ok "ssh key login works (deploy@127.0.0.1:22345)"
else
    fail "ssh key login failed: $(printf '%s' "$out" | tail -n 3 | tr '\n' '|')"
fi

# Even the test bypass cannot confirm from a real SSH session without a TTY.
if out=$(ssh "${SSH_OPTS[@]}" -T -p 22345 -i /root/deploy deploy@127.0.0.1 \
        LHM_CONFIRM_BYPASS=1 sudo -n /usr/local/bin/lhm ssh-confirm "$LHM_SSH_ID" </dev/null 2>&1); then
    fail "ssh-confirm accepted the test bypass without a TTY"
else
    assert_contains "$out" "TTY" "ssh-confirm refuses a non-TTY even with the test bypass"
fi
confirm_ssh_pending || finish

if out=$(ssh "${SSH_OPTS[@]}" -p 22345 -i /root/wrong deploy@127.0.0.1 true 2>&1); then
    fail "ssh accepted a wrong key"
else
    ok "ssh rejects a wrong key (rc=$?)"
fi

# Password auth must be refused as well (no password is set anyway; this
# asserts the config really is key-only rather than silently falling back).
if out=$(ssh "${SSH_OPTS[@]}" -p 22345 -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no -i /root/deploy deploy@127.0.0.1 true 2>&1); then
    fail "password authentication was accepted"
else
    ok "password authentication refused"
fi

finish
