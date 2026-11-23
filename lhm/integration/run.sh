#!/usr/bin/env bash
# Run the lhm integration scenarios in throwaway systemd containers.
#
#   cd lhm/integration && sudo ./run.sh            # build + all scenarios
#   cd lhm/integration && sudo ./run.sh 02 05      # build + selected ones
#   sudo ./run.sh --no-build                       # reuse the last image
#
# Each scenario gets a FRESH container (systemd as PID 1) so a failed apply
# never leaks state into the next test. Exit codes: 0 all pass, 1 any FAIL.
set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LHMDIR=$(dirname -- "$HERE")
SCENARIOS_DIR="$HERE/scenarios"
IMAGE="lhm-integration:latest"
# Per-scenario wall-clock cap: scenario 01 runs a real apt upgrade, 07 tars /etc.
SCENARIO_TIMEOUT=${SCENARIO_TIMEOUT:-1800}
BUILD=1
SELECT=()

if [ "$(id -u)" -eq 0 ]; then DOCKER=(docker); else DOCKER=(sudo docker); fi

for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) SELECT+=("$arg") ;;
    esac
done

# --- build -------------------------------------------------------------------
if [ "$BUILD" -eq 1 ]; then
    echo "== build $IMAGE =="
    # Context is lhm/ (Dockerfile copies pyproject.toml, uv.lock, src/, templates/).
    if ! "${DOCKER[@]}" build -q -f "$HERE/Dockerfile" -t "$IMAGE" "$LHMDIR"; then
        echo "build failed" >&2
        exit 1
    fi
fi

# --- scenario discovery ------------------------------------------------------
mapfile -t ALL < <(find "$SCENARIOS_DIR" -maxdepth 1 -name '[0-9][0-9]_*.sh' | sort)
if [ "${#ALL[@]}" -eq 0 ]; then
    echo "no scenarios under $SCENARIOS_DIR" >&2
    exit 1
fi
CHOSEN=()
for path in "${ALL[@]}"; do
    name=$(basename -- "$path")
    if [ "${#SELECT[@]}" -eq 0 ]; then
        CHOSEN+=("$path")
        continue
    fi
    for want in "${SELECT[@]}"; do
        if [[ "$name" == "$want"* ]]; then
            CHOSEN+=("$path")
            break
        fi
    done
done
if [ "${#CHOSEN[@]}" -eq 0 ]; then
    echo "no scenario matched: ${SELECT[*]}" >&2
    exit 1
fi

# --- one container per scenario ----------------------------------------------
# --privileged: systemd, ufw (netfilter), auditd, and the kernel sysctls need it.
# --cgroupns=private + tmpfs /run: the systemd-in-docker pattern; without it
#   systemd cannot mount its cgroup hierarchy or create /run/systemd.
# STOPSIGNAL SIGRTMIN+3 in the image makes `docker stop` a clean shutdown.
wait_for_systemd() {
    local name=$1 i
    for i in $(seq 1 60); do
        state=$("${DOCKER[@]}" exec "$name" systemctl is-system-running 2>/dev/null)
        case "$state" in
            running|degraded)
                # "degraded" is normal here: units that cannot start in a
                # container (e.g. apparmor) do not affect the scenarios.
                return 0 ;;
            starting|"")
                sleep 1 ;;
            *)
                echo "systemd state: $state" >&2
                return 1 ;;
        esac
    done
    echo "systemd did not finish booting" >&2
    return 1
}

declare -A RESULT
FAILED_TOTAL=0
for path in "${CHOSEN[@]}"; do
    name=$(basename -- "$path" .sh)
    container="lhm-it-$name-$$"
    echo
    echo "== $name =="
    "${DOCKER[@]}" rm -f "$container" >/dev/null 2>&1
    if ! "${DOCKER[@]}" run -d --name "$container" \
            --privileged --cgroupns=private \
            --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
            -v "$SCENARIOS_DIR":/opt/scenarios:ro \
            "$IMAGE" >/dev/null; then
        RESULT[$name]="FAIL (container start)"
        FAILED_TOTAL=$((FAILED_TOTAL + 1))
        continue
    fi
    if ! wait_for_systemd "$container"; then
        RESULT[$name]="FAIL (systemd boot)"
        FAILED_TOTAL=$((FAILED_TOTAL + 1))
        "${DOCKER[@]}" logs --tail 50 "$container" 2>&1 | sed 's/^/    | /'
        "${DOCKER[@]}" rm -f "$container" >/dev/null 2>&1
        continue
    fi

    # LHM_CONFIRM_BYPASS=1 is the documented test escape hatch: it skips the
    # two y/N prompts only (idempotency checks still run first).
    # `timeout` bounds a scenario that wedges (e.g. a hung apt lock); 124 then
    # shows up as a normal failure instead of blocking CI forever.
    timeout --kill-after=30 "$SCENARIO_TIMEOUT" \
        "${DOCKER[@]}" exec -e LHM_CONFIRM_BYPASS=1 \
        "$container" bash "/opt/scenarios/$(basename -- "$path")"
    rc=$?
    case "$rc" in
        0) RESULT[$name]="PASS" ;;
        77) RESULT[$name]="SKIPPED (environment)" ;;
        *) RESULT[$name]="FAIL (exit $rc)"; FAILED_TOTAL=$((FAILED_TOTAL + 1)) ;;
    esac
    if [ "$rc" -ne 0 ]; then
        echo "-- last 40 log lines of $container --"
        "${DOCKER[@]}" logs --tail 40 "$container" 2>&1 | sed 's/^/    | /'
    fi
    "${DOCKER[@]}" rm -f "$container" >/dev/null 2>&1
done

echo
echo "== summary =="
for path in "${CHOSEN[@]}"; do
    name=$(basename -- "$path" .sh)
    printf '  %-42s %s\n' "$name" "${RESULT[$name]:-not run}"
done
[ "$FAILED_TOTAL" -eq 0 ] || exit 1
