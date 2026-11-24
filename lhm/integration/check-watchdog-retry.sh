#!/usr/bin/env bash
# Opt-in smoke test; never call the system manager or the SSH watchdog.
set -euo pipefail

skip() { printf 'SKIP: %s\n' "$*" >&2; exit 77; }
[[ ${1-} == --isolated-user-manager && $# -eq 1 && $EUID -ne 0 ]] ||
    skip 'opt in as non-root in a disposable VM or with an isolated user manager'
for tool in systemctl systemd-run timeout; do
    command -v "$tool" >/dev/null || skip "$tool is missing"
done
[[ ${XDG_RUNTIME_DIR-} == /* && -O $XDG_RUNTIME_DIR &&
   ( -S $XDG_RUNTIME_DIR/systemd/private || -S $XDG_RUNTIME_DIR/bus ) ]] ||
    skip 'no isolated user-manager socket in an owned XDG_RUNTIME_DIR'
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS
ctl=(timeout -k 1s 5s systemctl --user)
"${ctl[@]}" show --property=Version --value >/dev/null 2>&1 ||
    skip 'the isolated systemd user manager is not reachable'

work=$(mktemp -d -t lhm-watchdog-retry-XXXXXXXXXX)
unit=${work##*/}
cleanup() {
    printf 'Cleaning up %s.timer and %s.service\n' "$unit" "$unit"
    "${ctl[@]}" stop "$unit.timer" "$unit.service" >/dev/null 2>&1 || :
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"$work/stub.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-}" = record ]; then
    printf '%s %s\n' "$EXIT_CODE" "$EXIT_STATUS" >>attempts
elif [ ! -s attempts ]; then
    exit 75
else
    exit 0
fi
EOF

# ExecStopPost records the exit status seen by systemd, even after unit collection.
timeout -k 1s 5s systemd-run --user --collect --unit="$unit" \
    --on-active=1s --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no \
    --service-type=exec --property=StartLimitIntervalSec=0 --property=Restart=no \
    --property=RestartSec=5s --property=RestartForceExitStatus=75 \
    --working-directory="$work" --property='ExecStopPost=/bin/sh ./stub.sh record' \
    -- /bin/sh ./stub.sh

expected=$'exited 75\nexited 0'
deadline=$((SECONDS + 15))
while (( SECONDS < deadline )); do
    if [[ -f $work/attempts && $(<"$work/attempts") == "$expected" ]]; then
        printf 'PASS: systemd observed these attempts in order:\n%s\n' "$expected"
        exit 0
    fi
    sleep 0.1
done
printf 'FAIL: expected exit 75 followed by exit 0; observed:\n' >&2
if [[ -s $work/attempts ]]; then cat "$work/attempts" >&2; else echo '(no attempts)' >&2; fi
exit 1
