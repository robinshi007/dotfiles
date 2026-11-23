# lhm — Linux Hardening & Management CLI

A single-binary, stdlib-only (Python >= 3.15) command line tool to query and harden
Debian 12 / Ubuntu 22.04+ servers: system updates, SSH hardening, firewall,
fail2ban, sysctl/service sandboxing, audit, logging, alerting and backups.

Safety-first design:

- **Idempotent first** — every module probes current state; already-done steps are
  reported `SKIPPED` and need no confirmation.
- **Double confirmation** — every non-idempotent apply shows a full plan (with
  risks) and asks `y/N` twice. Non-interactive (no TTY) runs fail closed.
  `LHM_CONFIRM_BYPASS=1` skips only the two prompts (documented escape hatch for
  unattended root runs / CI).
- **Backups before edits** — any modified file is backed up first (`name.ext.bak`,
  then `.bak.1`, `.bak.2`...; existing backups are never overwritten).
- **Drop-in configs preferred** — sshd/sysctl/systemd/audit use `.d/` drop-ins
  (remove the file to revert); appends to main files use marked comment blocks.
- **Dry-run everywhere** — `--dry-run` records a plan and executes nothing.
- **Verify after apply** — every module validates its result (`sshd -T`,
  `ss -tlnp` actual listen port, `ufw status`, `augenrules --check`, ...) and
  reports PASS/FAIL; sshd writes are gated by `sshd -t` with automatic rollback.

## Install

```sh
cd lhm/
uv sync                 # or: uv tool install .  (requires uv, Python 3.15 managed automatically)
uv run lhm --help
```

Root is required for `apply` and `rollback`; `query`/`check` work unprivileged.

## Usage

```sh
lhm query system|ssh|firewall|services|ports|sysctl|audit|updates [--json]
lhm check                       # idempotency audit across all 11 areas

lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345] [--allow-user NAME]...
lhm apply firewall [--allow PORT/PROTO]...
lhm apply fail2ban [--bantime 1h --findtime 10m --maxretry 5]
lhm apply cleanup-services      # interactive: pick services/ports to disable
lhm apply sysctl
lhm apply sandbox [ssh|nginx|fail2ban]...
lhm apply audit | logging
lhm apply alert --webhook URL   # https only
lhm apply backup --target /var/backups/lhm
lhm apply all --ssh-user NAME --key FILE --webhook URL --target PATH
                                # ordered run, excludes cleanup-services
lhm rollback FILE               # restore newest backup (double-confirmed)

# globals: --dry-run --json --verbose
```

### The six hardening goals

1. `updates` — apt update/upgrade + unattended-upgrades for security updates.
2. `ssh-user` / `ssh-hardening` — create a sudo user with a validated pubkey,
   then a drop-in (`sshd_config.d/99-lhm.conf`): `Port 22345`,
   `PermitRootLogin no`, `PasswordAuthentication no`, pubkey-only auth.
   Anti-lockout: refuses to disable password auth without valid keys; disables
   socket-activated `ssh.socket`; verifies the *actual* listening port.
3. `firewall` — ufw: allow the current SSH port(s) and 22345/tcp *first*, then
   `default deny incoming`, `allow outgoing`, enable.
4. `fail2ban` — installs fail2ban + nftables (only a Recommends upstream!),
   `jail.local` with the sshd jail on port 22345; `cleanup-services` lists
   listening ports/enabled services (protected set excluded) for interactive
   disable.
5. `sysctl` / `sandbox` — hardened sysctl drop-in (`kptr_restrict`,
   `dmesg_restrict`, `rp_filter`, ...); systemd sandbox drop-ins for a fixed
   whitelist (ssh, nginx, fail2ban) with per-service exceptions and automatic
   rollback if a restart fails.
6. `audit` / `logging` / `alert` / `backup` — auditd rules (immutable `-e 2`),
   persistent journald + logrotate, daily webhook alert (journal errors +
   fail2ban bans) via a root-only 0700 script, daily tar backup of /etc + /home
   with sha256 manifest, 0700/0600 permissions, rotation.

### Session-lockout guards (run order matters)

`apply all` runs 1 → 6 in order and stops at the first FAIL with a rollback
hint. When applying manually, keep an existing SSH session open, and run
`firewall` only after `ssh-hardening` reports its actual listen-port verify OK.

## Testing

```sh
uv run pytest -q          # 185 unit tests, fake runner — no system calls
uv run ruff check
cd integration && sudo ./run.sh   # docker-based integration suite (9 scenarios)
```

The integration suite builds an Ubuntu 24.04 systemd image and exercises the
real chain end to end — including a real sshd on port 22345 with real key login,
ufw rule ordering, fail2ban bans landing in an actual nftables table, idempotent
re-runs and rollback. See `integration/README.md` for scope and caveats
(auditd netlink is unreachable inside containers, so scenario 06 is skipped).

## Layout

```
src/lhm/cli.py            argparse assembly, exit codes
src/lhm/core/             runner / confirm / backup / files / distro / checks / report
src/lhm/modules/          updates, ssh, firewall, fail2ban, services, sysctl,
                           sandbox, logging, audit, alert, backup
templates/                sshd, sysctl, jail.local, audit rules, journald,
                           logrotate, alert + backup timers/scripts
integration/              Dockerfile, run.sh, scenarios/01-09
DESIGN.md                 authoritative design (safety rules §Safety)
```

## Supported platforms

Debian 12 / Ubuntu 22.04+ (apt backend). The `DistroBackend` seam exists for
other backends; RHEL is unimplemented.
