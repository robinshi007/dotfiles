# lhm integration tests (Docker)

Black-box tests of `lhm apply`/`lhm check`/`lhm rollback` against a real
Ubuntu 24.04 + systemd + apt + sshd + ufw + fail2ban + auditd. The unit suite
(173 tests, fake `Runner`) cannot observe systemd unit semantics, `sshd -T`
vs. the socket unit, ufw rule order, fail2ban's nftables action, or whether an
archive is actually written — these scenarios can.

## Run

```sh
cd lhm/integration
sudo ./run.sh                 # build the image, then every scenario
sudo ./run.sh 02 05           # build, then only scenarios whose name starts 02/05
sudo ./run.sh --no-build 02   # reuse the last image (fast iteration)
```

Exit codes: `0` all pass, `1` any failure, `77` for a container in which every
scenario was skipped (environment limitation, see below). Each scenario runs in
a **fresh** container, so state never leaks between them.

Requirements: Docker, and root or `sudo` (`ALL docker commands need sudo` on
this host). The image build downloads a managed CPython 3.15 via `uv` (~40 MB)
and takes a few minutes on a cold cache.

## Image

`Dockerfile` builds `lhm-integration:latest` from `ubuntu:24.04`:

* systemd as PID 1 (`STOPSIGNAL SIGRTMIN+3`), run with
  `--privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock`.
* Pre-installs every package lhm manages (systemd, dbus, openssh-server +
  client, ufw, iptables, **nftables**, fail2ban + python3-systemd, auditd,
  unattended-upgrades, curl, iproute2, …) so scenarios test lhm, not apt.
  `nftables` is explicit because it is only a *Recommends* of fail2ban while
  the shipped `jail.d/99-lhm.local` uses `banaction = nftables-multiport`.
* `uv sync --python 3.15` installs lhm into `/opt/lhm-venv`, with
  `/usr/local/bin/lhm` symlinked to it. The project is copied at build time, so
  rebuild after changing `src/`.

## Confirmation bypass

`apply`/`rollback` normally require a TTY and two `y` answers. `run.sh` sets
`LHM_CONFIRM_BYPASS=1`, which skips **only** those two prompts (plan still
printed, idempotency checks still run first, and `--dry-run` still writes
nothing). It is the documented hatch for this suite and for root-owned
unattended scripts; it is not a CLI flag. See `src/lhm/core/confirm.py`.

## Scenarios

| # | what it proves |
|---|----------------|
| 01 updates | `unattended-upgrades` installed/enabled, `51-lhm` written with security-only origins |
| 02 ssh | user + key, drop-in, `sshd -T` agreement, listener on 22345, **real** key login, wrong key and password refused |
| 03 firewall | ufw active, default deny incoming, `22345/tcp` allowed and **first** in rule order |
| 04 fail2ban | service active, `jail.d/99-lhm.local` written (strict sshd values, bantime.increment in `fail2ban-client -d`), legacy `jail.local` untouched by sha256, a ban really creates the nftables set; the live caddy jail is skipped (caddy is not in the image) |
| 05 sysctl | live `kptr_restrict=2`, `dmesg_restrict=1`, `rp_filter=1`, second run is a no-op |
| 06 audit | rules drop-in + `augenrules --check`; live audit only where the kernel allows it (see below) |
| 07 … | sandbox ssh (drop-in + `systemd-analyze security`), persistent journal, alert timer, backup archive + `.sha256` |
| 08 idempotent | second apply of ssh/sysctl/fail2ban reports no CHANGED and file hashes are identical |
| 09 rollback | `lhm rollback` restores the original, backs the current file up first, fails closed without a backup |

Each scenario is capped by `SCENARIO_TIMEOUT` seconds (default 1800); override
for a slow mirror: `sudo SCENARIO_TIMEOUT=3600 ./run.sh`.

## What this does NOT cover

* **Container network ≠ host firewall.** Scenario 03 asserts ufw's own state
  and rule ordering only. It never claims the host stays reachable; that
  requires an out-of-band probe from another host.
* **Kernel-wide sysctls are not namespaced.** `kernel.*` writes change the
  *host* kernel. `lib.sh` bind-mounts `/dev/null` over the irreversible /
  disruptive keys and restores the observable ones, but `net.ipv4.*` is
  per-netns and safe. Run this suite on a disposable VM if you care.
* **auditd cannot run in a normal container.** The audit netlink socket is
  only reachable from the initial PID namespace; with `--privileged` alone
  `auditctl -s` returns `EPERM` (verified on Linux 6.12, Docker 26.1.5).
  `--pid=host` fixes audit but breaks systemd-as-PID-1, so scenario 06 checks
  the file layer, `augenrules --check`, and lhm's *fail-closed* behaviour, and
  reports SKIPPED. Consequences for real hosts: `-e 2` (immutable) means rules
  can only be reloaded after a reboot, so a second `lhm apply audit` must be a
  no-op — that path is unit-tested, not integration-tested.
* apt upgrade latency/network: scenario 01 really runs `apt-get upgrade`; with
  no network or a frozen mirror the module fails and the scenario fails with it.
* sshd login is tested from the container to itself over loopback. It cannot
  detect a firewall or routing problem on the real path.
* auditd's own log rotation (`/var/log/audit`) is configured but not exercised.

## Adding a scenario

Drop `scenarios/NN_name.sh`, source `/opt/scenarios/lib.sh`, use the
`assert_*`/`run_lhm` helpers, finish with `finish`. The file is mounted from
the host read-only, so no rebuild is needed.
