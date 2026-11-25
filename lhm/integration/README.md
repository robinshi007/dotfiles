# lhm integration tests (Docker)

Black-box tests of `lhm apply`/`lhm ssh-confirm`/`lhm check`/`lhm rollback`
against a real Ubuntu 24.04 + systemd + apt + sshd + ufw + fail2ban + auditd.
The unit suite fakes host-management commands and cannot observe systemd unit
semantics, `sshd -T` vs. the socket unit, ufw rule order, fail2ban's nftables
action, or whether an archive is actually written — these scenarios can.

## Run

Run the privileged suite only inside a **disposable VM** with Docker. Some
scenarios can change the Docker host's kernel; do not use a workstation,
production machine, or a host Docker socket mounted into the VM.

```sh
cd lhm/integration
sudo ./run.sh                 # build the image, then every scenario
sudo ./run.sh 02 05           # build, then only scenarios whose name starts 02/05
sudo ./run.sh --no-build 02   # reuse the last image (fast iteration)
```

Exit codes: `0` all pass, `1` any failure, `77` for a container in which every
scenario was skipped (environment limitation, see below). Each scenario runs in
a **fresh** container, so state never leaks between them.

Requirements in the VM: Docker and root or `sudo`. The image build downloads
a managed CPython 3.15 via `uv` (~40 MB) and takes a few minutes on a cold cache.

## Image

`Dockerfile` builds `lhm-integration:latest` from `ubuntu:24.04`:

* systemd as PID 1 (`STOPSIGNAL SIGRTMIN+3`), run with
  `--privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock`.
* Pre-installs every package lhm manages (systemd, dbus, openssh-server +
  client, ufw, iptables, **nftables**, fail2ban + python3-systemd, auditd,
  unattended-upgrades, curl, iproute2, …) so scenarios test lhm, not apt.
  `nftables` is explicit because it is only a *Recommends* of fail2ban while
  the shipped `jail.d/99-lhm.local` uses `banaction = nftables-multiport`.
  The image also installs sudo for the real SSH confirmation scenarios.
* `uv sync --python 3.15` installs lhm into `/opt/lhm-venv`, with
  `/usr/local/bin/lhm` symlinked to it. The project is copied at build time, so
  rebuild after changing `src/`.
* The image copies the full uv-managed CPython prefix (including the standard
  library) to `/opt/lhm-ssh-rollback/python`, and the same lhm source to
  `/opt/lhm-ssh-rollback/src/lhm`. Both trees are root-owned, symlink-free, and
  not writable by group or others. The build probes the isolated watchdog
  launcher at `python/bin/python3.15` under that root. Live SSH apply
  uses `/usr/bin/busctl` and the system D-Bus socket at `/run/dbus/system_bus_socket`
  to verify the systemd timer deadline.

## Confirmation bypass

Each changed `apply` module and `rollback` normally require a TTY and one exact
`y`. `run.sh` sets `LHM_CONFIRM_BYPASS=1`, which skips **only** that prompt where
supported (the plan still prints, idempotency checks still run first, and
`--dry-run` still writes nothing). It is the documented hatch for this suite
and for root-owned unattended scripts; it is not a CLI flag. See
[`confirm.py`](../src/lhm/core/confirm.py).
It does not bypass `ssh-confirm`. Scenarios 02, 03, and 08 use a pinned ephemeral
host key and a new, non-multiplexed SSH transport for confirmation on port
22345 after applying on port 22. They use the test account's actual sudo on a
TTY to run the image's trusted `/usr/local/bin/lhm`, with one `y` for apply and
one `y` for `ssh-confirm`. Their sudo policy is installed only inside the test
container. These are drop-in-only changes. On a real host, keep independent
console access and confirm from a fresh key login before applying the firewall;
automatic SSH permission changes require a verified rescue/emergency console.

## Scenarios

| # | what it proves |
|---|----------------|
| 01 updates | `lhm apply updates --security-only --dry-run` plans an isolated security upgrade without an ordinary upgrade fallback or writing `51-lhm` |
| 02 ssh | user + key, drop-in, `sshd -T` agreement, listener on 22345, **real** key login and watchdog confirmation, non-TTY bypass/wrong key/password refused |
| 03 firewall | after fresh-session SSH confirmation, ufw active, default deny incoming, `22345/tcp` allowed and **first** in rule order |
| 04 fail2ban | service active, `jail.d/99-lhm.local` written (strict sshd values, bantime.increment in `fail2ban-client -d`), legacy `jail.local` untouched by sha256, a ban really creates the nftables set; the live caddy jail is skipped (caddy is not in the image) |
| 05 sysctl | live `kptr_restrict=2`, `dmesg_restrict=1`, `rp_filter=1`, second run is a no-op |
| 06 audit | rules drop-in + `augenrules --check`; live audit only where the kernel allows it (see below) |
| 07 … | sandbox ssh (drop-in + `systemd-analyze security`), persistent journal, alert timer, backup archive + `.sha256` |
| 08 idempotent | after confirming SSH, second apply of ssh/sysctl/fail2ban reports no CHANGED and file hashes are identical |
| 09 rollback | `lhm rollback` restores the original, backs the current file up first, fails closed without a backup |

Each scenario is capped by `SCENARIO_TIMEOUT` seconds (default 1800); override
for a slow VM: `sudo SCENARIO_TIMEOUT=3600 ./run.sh`.

## Optional: verify the watchdog retry

From `lhm/integration`, run as a non-root user with a dedicated, isolated
systemd user manager and its own `XDG_RUNTIME_DIR`, preferably in a **disposable
VM**. Never use `sudo`, your normal host user manager, or a privileged container.
`--isolated-user-manager` is an operator attestation: the script checks for an
owned runtime directory and a reachable user manager, but cannot create or
verify isolation.

```sh
./check-watchdog-retry.sh --isolated-user-manager
```

The one-shot transient timer triggers a harmless stub after one second. Expect
`exited 75` then `exited 0`: `RestartForceExitStatus=75` retries after **5 seconds**
despite `Restart=no`. The check waits up to 15 seconds for attempts and cleans
up its units and temporary files. It uses only the user manager, installs no
persistent units, and never touches SSH. Exit `77` means the opt-in guard or
user-manager prerequisites were not met. A passing run checks the stub retry,
not production watchdog recovery; offline unit verification proves neither.

## Optional: prove rollback survives a killed CLI

Use a fresh, disposable Ubuntu 24.04 systemd VM with independent console access
and no production credentials or network dependencies. This manual check is not
part of the routine suite. Provision the same standalone watchdog paths and
system D-Bus service described above inside the VM; a CLI virtualenv alone
cannot arm the watchdog. Do not set `LHM_CONFIRM_BYPASS`, shorten the production
timer, reboot, or manually restart SSH during the test.

1. Provision a throwaway admin with
   `sudo /opt/lhm/bin/lhm apply ssh-user NAME --key FILE --sudo`, substituting
   the absolute path to the trusted VM installation.
   Verify a fresh key login on port 22 using the VM's pinned host key. From an
   independent console, record whether `/etc/ssh/sshd_config.d/99-lhm.conf`
   exists and its hash if present, the `ssh.socket`/`ssh.service` enablement
   and active listening mode (socket or standalone), and the original port-22
   listener with `ss -ltnp`.
2. At a root VM console, use the trusted CLI to run
   `/opt/lhm/bin/lhm apply ssh-hardening --ssh-user NAME --dry-run` and verify
   that no permission changes are planned. Then launch the drop-in change in
   its Python debugger (for example, `/opt/lhm/bin/python -m pdb
   /opt/lhm/bin/lhm apply ssh-hardening --ssh-user NAME` in a root-controlled
   virtualenv).
   In `pdb`, set a breakpoint in the SSH apply implementation after the
   candidate listener is verified but before apply returns, then continue
   and confirm once. At
   the breakpoint, record the apply PID with `p __import__("os").getpid()`.
3. At the independent console verify the old listener is gone, the candidate
   listens on 22345, and `systemctl list-timers --all` shows the newly armed SSH
   rollback timer and its activation unit. Record those unit names. Send SIGKILL
   to **only the stopped apply PID** and verify it is gone; do not confirm.
4. In the same boot, let the real 10-minute deadline elapse from arming. Check
   the rollback service journal for a successful recovery, compare the drop-in
   presence/hash and unit states with the baseline, and verify 22345 is no
   longer listening and a **new** key login on the original port succeeds.

## What this does NOT cover

* **Container network ≠ host firewall.** Scenario 03 asserts ufw's own state
  and rule ordering only. It never claims the host stays reachable; that
  requires an out-of-band probe from another host.
* **Kernel-wide sysctls are not namespaced.** `kernel.*` writes change the
  *host* kernel. `lib.sh` bind-mounts `/dev/null` over the irreversible /
  disruptive keys and restores the observable ones, but `net.ipv4.*` is
  per-netns. The disposable VM is still required.
* **auditd cannot run in a normal container.** The audit netlink socket is
  only reachable from the initial PID namespace; with `--privileged` alone
  `auditctl -s` returns `EPERM` (verified on Linux 6.12, Docker 26.1.5).
  `--pid=host` fixes audit but breaks systemd-as-PID-1, so scenario 06 checks
  the file layer, `augenrules --check`, and lhm's *fail-closed* behaviour, and
  reports SKIPPED. Consequences for real hosts: `-e 2` (immutable) means rules
  can only be reloaded after a reboot, so a second `lhm apply audit` must be a
  no-op — that path is unit-tested, not integration-tested.
* **Live APT updates.** Scenario 01 is offline and does not need the trusted APT
  security worker. The image does not install it. Live `apply updates` requires
  [a matching trusted worker](../README.md#provision-the-apt-security-worker)
  and an active, enabled `apt-daily-upgrade.timer`; the suite does not test live
  upgrades or timer integration.
* sshd login is tested from the container to itself over loopback. It cannot
  detect a firewall or routing problem on the real path.
* auditd's own log rotation (`/var/log/audit`) is configured but not exercised.

## Adding a scenario

Drop `scenarios/NN_name.sh`, source `/opt/scenarios/lib.sh`, use the
`assert_*`/`run_lhm` helpers, finish with `finish`. The file is mounted from
the host read-only, so no rebuild is needed.
