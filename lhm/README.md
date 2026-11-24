# lhm — Linux Hardening & Management CLI

A single-binary, stdlib-only (Python >= 3.15) command line tool to query and harden
Debian 12 / Ubuntu 22.04+ servers: system updates, SSH hardening, firewall,
fail2ban, sysctl/service sandboxing, audit, logging, alerting and backups.

Safety-first design:

- **Idempotent first** — every module probes current state; already-done steps are
  reported `SKIPPED` and need no confirmation.
- **Single confirmation** — each apply that makes changes shows a full plan
  (with risks) and asks for one exact `y` per changed module. If there is no TTY
  and no active bypass, confirmation fails closed and exits **3** (`ABORTED`),
  never 0. `LHM_CONFIRM_BYPASS=1`
  (exactly `1`, no padding) skips only the prompt on operations that support
  the bypass for unattended root runs / CI. `ssh-confirm` and
  `apply cleanup-services` do not honor it.
- **Backups before edits** — any modified file is backed up first (`name.ext.bak`,
  then `.bak.1`, `.bak.2`...; existing backups are never overwritten).
- **Drop-in configs preferred** — sshd/sysctl/systemd/audit use `.d/` drop-ins
  (remove the file to revert); appends to main files use marked comment blocks.
- **Dry-run everywhere** — `--dry-run` records a plan and executes nothing.
- **Verify after apply** — every module validates its result (`sshd -T`,
  `ss -tlnp` actual listen port, `ufw status`, `augenrules --check`, ...) and
  reports PASS/FAIL; sshd writes are gated by `sshd -t` (and `sshd -T`, including
  `AllowUsers` covering every admin key); on failure lhm attempts recovery.
- **No secret echo** — webhook errors show only scheme + host, and `--verbose`
  prints `(content hidden: contains a secret)` instead of the alert script (the
  `.bak` copy and its diff are suppressed too).

## Install

```sh
cd lhm/
uv sync                 # or: uv tool install .  (requires uv, Python 3.15 managed automatically)
uv run lhm --help
```

Root is required for live `apply`, `ssh-confirm`, and `rollback`; `query`/`check` work
unprivileged. For root commands below, `/opt/lhm/bin/lhm` is an example absolute
path to a trusted, root-controlled CLI installed from a release wheel. A regular
`uv sync` or CLI install alone does not provision the SSH watchdog.

### Provision the SSH watchdog

Live SSH changes require systemd as PID 1 and a working system bus
(`/run/dbus/system_bus_socket`). The independent recovery worker uses exactly
`/opt/lhm-ssh-rollback/python/bin/python3.15` (standalone CPython with its
stdlib under that prefix) and `/opt/lhm-ssh-rollback/src/lhm` (the same lhm
release as the CLI). The full trees and all ancestors must be root-owned,
not group- or world-writable, and free of symlinks. The worker runs with
`-I -S -B` and imports lhm from this dedicated root-controlled copy, not from
your checkout, venv, user site, or uv runtime.

For a fresh deployment, stage a verified, relocatable CPython 3.15 install
image for the host and the matching trusted lhm release source in root-controlled
directories. Copy and dereference **only** those artifacts after verifying that
their symlink targets are also trusted. The Python image must contain both
`bin/python3.15` and its prefix-local standard library; do not copy a venv.

```sh
watchdog=/opt/lhm-ssh-rollback
python_image=/path/to/trusted/cpython-3.15-install-image
lhm_release=/path/to/trusted/lhm-release
sudo install -d -m 0700 "$watchdog"
sudo install -d -m 0755 "$watchdog/python" "$watchdog/src"
sudo cp -RL -- "$python_image/." "$watchdog/python/"
sudo cp -RL -- "$lhm_release/src/lhm" "$watchdog/src/"
sudo find "$watchdog/src/lhm" -type f -name '*.pyc' -delete
sudo chown -R root:root -- "$watchdog"
sudo chmod -R go-w -- "$watchdog"
```

On upgrade, replace the worker and CLI with matching releases, never while
a transaction is pending. LHM compares the isolated worker's protocol, state
format and Python source fingerprint with the CLI before arming.

## Usage

```sh
lhm query system|ssh|firewall|fail2ban|services|ports|sysctl|audit|updates [--json]
lhm query all                   # every section, == name == separators
lhm check                       # idempotency audit across all 11 areas

lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345] [--allow-user NAME]...
lhm ssh-confirm ID              # from a new SSH key login on the target port
lhm apply firewall [--allow PORT/PROTO]...
lhm apply fail2ban [--bantime 8h --findtime 30m --maxretry 3] [--caddy]
lhm apply cleanup-services      # interactive: pick services/ports to disable
lhm apply sysctl
lhm apply sandbox [ssh|nginx|fail2ban]...
lhm apply audit | logging
lhm apply alert --webhook URL   # https only
lhm apply backup --target /var/backups/lhm
lhm apply all --webhook URL --target PATH [--ssh-user NAME --key FILE]
                                # ordered run; no ssh-hardening or cleanup-services
lhm rollback FILE               # restore LHM's newest .bak[.N] (one prompt)

# globals: --dry-run --json --verbose --color auto|always|never
```

`lhm rollback` restores `FILE.bak`, `FILE.bak.1`, … only for known
lhm-managed system paths. It refuses symlinks and user-owned
`authorized_keys` (restore those manually as the account owner). It is not a general
snapshot or restore tool: packages, services and other prior state are not
recovered. It requires root, prints the plan, and prompts once on a TTY unless
the bypass is set. A refused confirmation exits **3** with nothing changed.

### Supported entry point

The `lhm` CLI is the only supported interface: it enforces root, single
confirmation and dry-run. Python modules and helpers are trusted internal
interfaces, not a substitute for the CLI's guards. In a CLI dry-run, the command
runner and managed filesystem helpers suppress mutations even if a caller
reaches a write path; a planned command is not a successful verification.
On timeout, the runner terminates the command's process group. Processes that
start a separate group or session and work handed off to another service are
outside that guarantee.

### The six hardening goals

1. `updates` — apt update/upgrade + unattended-upgrades for security updates.
2. `ssh-user` / `ssh-hardening` — create a sudo user with a validated pubkey,
   then a drop-in (`sshd_config.d/99-lhm.conf`): `Port 22345`,
   `PermitRootLogin no`, `PasswordAuthentication no`, pubkey-only auth, and
   `AuthorizedKeysFile .ssh/authorized_keys`.
   Key-file operations inside the managed account's home run as that account,
   not as root. For `--key FILE`, use a public-key file readable by the invoking
   sudo user, or put it in a root-controlled directory for direct root runs.
   Anti-lockout: refuses to disable password auth without valid keys; disables
   socket-activated `ssh.socket`; checks that SSH owns the actual listen port.
   On a failed check or activation, it attempts to restore the original drop-in
   and listener. A live change requires `ss` to confirm the previous listener
   and the new one. An already-current configuration may report `SKIPPED` if
   the listener cannot be inspected.
   Socket-to-service migration requires a single `ssh.service` or
   `sshd.service` target. An `Accept=yes` socket that launches `ssh@.service`
   per connection (as packaged in Ubuntu 22.04) is refused, not converted.
3. `firewall` — ufw: allow the current SSH port(s) and 22345/tcp *first*, then
   `default deny incoming`, `allow outgoing`, enable. When no SSH listener can be
   probed (`ss`/`sshd -T` missing) it refuses to continue unless you name the port
   yourself: `lhm apply firewall --allow 22/tcp` (the explicit anti-lockout escape
   hatch). If SSH socket state is unknown or an active socket cannot be fully
   verified, no UFW commands run even with `--allow`. Check systemd and the
   listeners from the local console before retrying.
   Only `ALLOW`/`ALLOW IN` rules count, never `ALLOW FWD`.
4. `fail2ban` — installs fail2ban + nftables (only a Recommends upstream!) and
   writes a **`jail.d/99-lhm.local` drop-in** with the sshd jail on port 22345.
   It never touches `/etc/fail2ban/jail.local`: load order is
   `jail.conf` → `jail.d/*.conf` → `jail.local` → `jail.d/*.local`, so the
   drop-in wins over a hand-maintained `jail.local`, which keeps the host's own
   custom jails intact. sshd jail: `mode = aggressive`, `maxretry = 3`,
   `findtime = 30m`, `bantime = 8h` with incrementing bans
   (`bantime.increment`, `factor = 3`, `maxtime = 4w`, `rndtime = 30m`), i.e.
   bantime · 2^n · 3 capped at 4 weeks — 8h, 48h, 4d, 8d, 16d, then 4w. The
   increment needs fail2ban's dbfile (packaging default
   `/var/lib/fail2ban/fail2ban.sqlite3`). `--caddy` also installs the
   lhm-provided `filter.d/caddy-lhm.conf` (fail2ban has no Caddy filter and no
   JSON parser) and enables a journald-based caddy jail on ports 80,443 for
   401/403/404/429 responses; caddy is **off by default** because an enabled jail
   for a missing `caddy.service` stops fail2ban from starting. `cleanup-services`
   lists listening ports/enabled services (protected set excluded) for
   interactive disable.
5. `sysctl` / `sandbox` — hardened sysctl drop-in (`kptr_restrict`,
   `dmesg_restrict`, `rp_filter`, ...); systemd sandbox drop-ins for a fixed
   whitelist (ssh, nginx, fail2ban) with per-service exceptions and automatic
   rollback if a restart fails.
6. `audit` / `logging` / `alert` / `backup` — auditd rules (immutable `-e 2`),
   persistent journald + logrotate, daily webhook alert (journal errors +
   fail2ban bans) via a root-only 0700 script, daily tar backup of /etc + /home
   with sha256 manifest, 0700/0600 permissions, rotation.

### Session-lockout guards (run order matters)

`apply all` runs 1 → 6 in order and stops at the first FAIL or ABORTED module.
It can provision an SSH user but does not run `ssh-hardening`. For a live SSH
hardening change, use the standalone workflow below and finish it before
running `apply firewall` or `apply sandbox`.

1. **Have local or out-of-band console access and keep the existing SSH session
   open.** Run `sudo /opt/lhm/bin/lhm apply ssh-hardening` (add `--port` if
   needed). Answer the single prompt with `y`. LHM then arms and verifies a
   **10-minute systemd recovery timer** before changing SSH and prints the
   transaction ID. A failed or unknown timer check blocks the change.
2. From your client, open a second connection as an approved administrator,
   using the real private key and the target port. Disable connection
   multiplexing so this is a fresh login, and verify that the key was used.
   This is a login test, not another CLI prompt:

   ```sh
   ssh -v -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes \
     -i ~/.ssh/admin_ed25519 -p 22345 admin@host
   ```

3. From that second session, substitute the printed ID and use the trusted
   absolute path to lhm. Answer its single prompt with `y`; there is no bypass.

   ```sh
   sudo env SSH_CONNECTION="$SSH_CONNECTION" /opt/lhm/bin/lhm ssh-confirm ID
   ```

The apply output (including PASS/CHANGED) verifies local state, not a real key
login or acceptance of the change. Confirmation checks that the OpenSSH
connection process started after the new configuration was verified. Run it
directly in the new session, not from a detached shell or a reused connection.
`SSH_CONNECTION` supplies the reported addresses and port for the configuration
check; it does not prove the actual destination port, key or authentication
factor. Verify the target port and key from the client. Keep the old
session until confirmation succeeds. If the change is not confirmed within
the window, systemd runs recovery even if the apply CLI was killed. This
protection is **same-boot only**; do not reboot while confirmation is pending.

After an attempted write of the new SSH drop-in, recovery must verify that the
previous configuration is back in use, even if apply never issued a reload.
An independent restart or socket activation could have picked up the new
file. Recovery prepares OpenSSH's privilege separation directory (`/run/sshd`)
before validating the restored configuration.

LHM keeps the pending journal at `/run/lhm-ssh-rollback/pending.json` and names
the transient units `lhm-ssh-rollback-<id>.timer` and
`lhm-ssh-rollback-<id>.service`. The worker exits with status **75** for
transient I/O errors (such as a journal read failure), unavailable probes,
pending SSH jobs, or listeners that are not ready. A failed recovery-time
`sshd -t` (including exit 255) also defers recovery without touching the daemon
at that gate. Only status 75 is configured to restart the worker after
**5 seconds**, with no start-rate limit in the current boot. Hard failures
such as corrupt state or external edits to the managed configuration require
manual recovery; the watchdog does not overwrite those edits or clear the
journal on failure.

If recovery fails, use the local console and replace `ID` below with the printed
transaction ID to inspect the unit and logs:

```sh
id=ID
sudo systemctl --system status "lhm-ssh-rollback-$id.timer" "lhm-ssh-rollback-$id.service"
sudo journalctl -b -u "lhm-ssh-rollback-$id.service"
```

An expired transient unit may no longer appear in `systemctl`; check the
journal. Do not delete `pending.json` just to clear a refusal.

While pending, a new SSH hardening apply and manual `lhm rollback` of the
managed SSH drop-in are refused. Old IDs cannot confirm newer changes, and
confirmation is serialized with recovery. Do not run `apply firewall` or
`apply sandbox` concurrently or edit the managed SSH config outside lhm.

## Automatic recovery limits (per module)

Recovery is deliberately narrow: lhm only undoes changes it made in that run.
An attempted recovery is not reported as verified unless the prior local state
can be confirmed. Otherwise, use the printed console guidance.

| module | automatic | manual (printed on FAIL) |
| ------ | --------- | ------------------------ |
| ssh | attempt to restore this run's prior drop-in and listener on failure or if the timer expires unconfirmed | if recovery fails or cannot be verified, check the systemd journal and recover from the local console; do not delete transaction state to clear a refusal |
| firewall | none | inspect `ufw status verbose` and recover the intended rules from the local console; lhm never disables UFW automatically |
| audit | none | inspect `auditctl -s`; if needed, restore the managed rules file from its backup. Immutable live rules require a reboot to change |
| sandbox | drop-in rollback if `systemctl restart` fails | start the service and inspect `systemctl status` manually |

Consequences: a failed run may be **partially applied** (earlier modules stay
applied, as the exit-code section notes). Config and listener checks (`sshd -T`,
`ss -tlnp`, `ufw status`) prove the *local* configuration, not that remote
password/key authentication actually succeeds — do not read a PASS as "I can log
in". Keep the proven admin session open and test key login from a second session
before closing it.

The SSH candidate file is placed in the real include directory for OpenSSH to
check. Until it is accepted or restored, a newly started sshd may already read
it. The timer schedules a recovery attempt; it cannot guarantee restoration.

Ed25519 key validation checks the wire format, not curve membership or subgroup
membership. Use a key generated by a trusted SSH client and test a new login
with its private key; neither local key validation nor a listening port proves
that a remote administrator can authenticate.

Before reloading SSH, lhm checks the effective key-file path and that at least
one authentication chain permits a public key for each selected administrator.
An additional factor is allowed. OpenSSH's configuration dump does not preserve boundaries
between paths, so lhm refuses an ambiguous `AuthorizedKeysFile` value rather
than guessing. Use a single, unambiguous managed key-file path. A connection
probe checks only the context it reports; other source addresses, hostnames
and local addresses can match different SSH rules.

## Colored output

Color is decided by `src/lhm/core/colors.py` (the only module that knows ANSI
codes). Default is `--color=auto`: color only when stdout is a TTY. `NO_COLOR`
(any value) turns auto coloring off; an explicit `--color=always` wins over
`NO_COLOR`, so piped output can be colored on purpose (`lhm query all
--color=always | less -R`); `--color=never` disables it outright.

- `query`: values are judged against lhm's hardening target — green = meets it,
  red = does not, yellow = cannot be probed (e.g. `sshd -T` needs root).
  `services` / `ports` / `system` have no target and stay uncolored.
- `check`: the state column (OK green, needs-change red, UNKNOWN yellow).
- `apply`: each executed command echoes as `$ cmd` in cyan; file changes print as
  `+ created` (green), `~ modified` (yellow), `- deleted` (red) and
  `@ symlink` (magenta). With `--verbose`, created/deleted changes print the full
  content and modified ones a red/green unified diff — except secret-bearing files
  (the alert script), which print `(content hidden: contains a secret)`.

## Exit codes

| code | meaning |
| ---- | ------- |
| 0 | every step OK / SKIPPED / CHANGED (or a dry-run plan) |
| 1 | a step FAILed (rollback hints are printed) |
| 2 | usage error (bad flags/paths) |
| 3 | ABORTED: the confirmation was refused (no TTY or an answer other than `y`), nothing was changed |

`apply all` stops at the first FAIL (1) or the first ABORTED module (3, naming
it); modules already applied stay applied.

```sh
lhm --color=always query all | less -R
NO_COLOR=1 lhm check            # plain text
lhm query ssh --color=never
```

## Testing

```sh
uv run pytest -q          # unit tests; host-management commands are faked
uv run ruff check
cd integration && sudo ./run.sh   # docker-based integration suite (9 scenarios)
```

The integration suite builds an Ubuntu 24.04 systemd image. Its scenarios
include a real sshd on port 22345 with real key login,
ufw rule ordering, fail2ban bans landing in an actual nftables table, idempotent
re-runs and rollback. See `integration/README.md` for scope and caveats
(auditd netlink is unreachable inside containers, so scenario 06 is skipped).

Test actual watchdog expiry only in a disposable systemd VM with console
access. Apply a live SSH change, leave it unconfirmed for the full 10 minutes
in the same boot, then check the recovery service log and verify the previous
configuration, listener and login. Unit tests do not exercise real timer expiry.

## Layout

```
src/lhm/cli.py            argparse assembly, exit codes
src/lhm/core/             runner / confirm / backup / files / distro / checks / report
src/lhm/modules/          updates, ssh, firewall, fail2ban, services, sysctl,
                           sandbox, logging, audit, alert, backup
templates/                sshd, sysctl, fail2ban (99-lhm.local + caddy filter),
                           audit rules, journald, logrotate, alert + backup
                           timers/scripts
integration/              Dockerfile, run.sh, scenarios/01-09
DESIGN.md                 authoritative design (safety rules §Safety)
```

## Supported platforms

Debian 12 / Ubuntu 22.04+ (apt backend). The `DistroBackend` seam exists for
other backends; RHEL is unimplemented.
