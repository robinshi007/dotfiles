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
  the bypass for unattended root runs / CI. `ssh-confirm`, `ssh-recover`, and
  `apply cleanup-services` do not honor it, nor does `ssh-hardening` when
  its plan includes chmod.
- **Backups before edits** — any modified file is backed up first (`name.ext.bak`,
  then `.bak.1`, `.bak.2`...; existing backups are never overwritten).
- **Drop-in configs preferred** — sshd/sysctl/systemd/audit use `.d/` drop-ins
  (remove the file to revert); appends to main files use marked comment blocks.
- **Dry-run everywhere** — `--dry-run` records a plan and executes nothing.
- **Verify after apply** — every module validates its result (`sshd -T`,
  `ss -tlnp` actual listen port, `ufw status`, `augenrules --check`, ...) and
  reports PASS/FAIL; sshd writes are gated by `sshd -t` (and `sshd -T`, including
  `AllowUsers` covering the selected administrators); on failure lhm attempts
  recovery where supported.
- **No secret echo** — webhook errors show only scheme + host, and `--verbose`
  prints `(content hidden: contains a secret)` instead of the alert script (the
  `.bak` copy and its diff are suppressed too).

The repository's root `.gitignore` ignores untracked files under `secrets/`
directories at any depth. It does not protect already-tracked secrets or remove
them from Git history.

## Install

```sh
cd lhm/
uv sync                 # or: uv tool install .  (requires uv, Python 3.15 managed automatically)
uv run lhm --help
```

Root is required for live `apply`, `ssh-confirm`, `ssh-recover`, and `rollback`;
`query`/`check` work unprivileged. For root commands below, `/opt/lhm/bin/lhm` is
an example absolute path to a trusted, root-controlled CLI installed from a
release wheel. A regular `uv sync` or CLI install alone does not provision
either independent worker below.

### Provision the APT security worker

Before running live `apply updates` (including through `apply all`), use a
trusted checkout at a reviewed, committed `HEAD` containing the installer,
worker sources and templates. The installer bundles that commit, not
working-tree edits. Use the same release for the worker and CLI. From `lhm/`,
as an unprivileged user:

```sh
uv sync --locked --managed-python --python 3.15
./scripts/install-apt-security.sh --dry-run
./scripts/install-apt-security.sh
```

Verify the dry-run plan's commit, standalone CPython image and all its symlink
targets before answering `y` in the live installer. Do not modify those inputs
during installation. The first-install script probes a
private, root-controlled copy of the interpreter and worker, then publishes
`/usr/local/libexec/lhm-apt-security` without replacing an existing launcher.
It does not change APT or systemd timers. Live `apply updates` requires a
matching worker and an already active, enabled `apt-daily-upgrade.timer`
that triggers `apt-daily-upgrade.service`. Apply configures the upgrade service
to run the worker and the `apt-daily` service to refresh indexes only. It
refuses conflicting local commands or managed drop-ins rather than overwriting
them. To retire an installed worker, stop automatic upgrades first; the
installer is not an upgrade command.

### Provision the SSH watchdog

Live SSH changes require systemd as PID 1 and a working system bus
(`/run/dbus/system_bus_socket`). The independent recovery worker uses exactly
`/opt/lhm-ssh-rollback/python/bin/python3.15` (standalone CPython with its
stdlib under that prefix) and `/opt/lhm-ssh-rollback/src/lhm` (the same lhm
release as the CLI). The full trees and all ancestors must be root-owned,
not group- or world-writable, and free of symlinks. The worker runs with
`-I -S -B` and imports lhm from this dedicated root-controlled copy, not from
your checkout, venv, user site, or uv runtime.

For a **first install**, start in `lhm/` in a trusted release checkout and run
these commands as an unprivileged user:

```sh
uv sync --locked --managed-python --python 3.15
./scripts/install-ssh-watchdog.sh
```

The script shows the selected CPython image and Git commit, then asks for one
exact `y` before using sudo. `--dry-run` shows that plan without sudo or touching
`/opt`; it still runs uv for discovery. The script copies the full CPython base
installation (not the venv) and only committed lhm sources from the selected
commit. Before confirming, verify the release, the relocatable CPython 3.15
image, and **all** symlink targets in that image: they are copied and used as
root. The CLI source fingerprint checks that the staged worker matches the
CLI, not that Python comes from a trusted source. Do not modify those inputs or
start an SSH transaction during installation.

The installer refuses a pending transaction or an existing destination,
including dangling symlinks. It publishes only after the isolated worker probes
successfully. Publication requires Linux `renameat2(RENAME_NOREPLACE)` support
on the `/opt` filesystem; there is no fallback that can overwrite a destination.
The installer does not change SSH configuration or start services. It is not an
upgrade command: replace the worker and root-controlled CLI only with matching
trusted releases, never while a transaction is pending. LHM rechecks the
worker's protocol (currently v4), state format, and Python source fingerprint
against that CLI before arming. An older or mismatched worker blocks live
hardening, including permissions-only changes, before any SSH files or modes
are changed.

Before redeploying either component, prevent new SSH transactions and verify
as root that `/run/lhm-ssh-rollback/pending.json` is absent. If it exists or
cannot be inspected, stop; never overwrite or delete the marker to proceed.
For a failed transaction, see [Recover a failed SSH transaction](#recover-a-failed-ssh-transaction).
Preserve the previous runtime separately in a root-controlled location before
provisioning the matching replacement.

## Usage

```sh
lhm query system [--public-ip] [--json]
lhm query ssh|firewall|fail2ban|services|ports|sysctl|audit|updates|caddy [--json]
lhm query all [--json]          # all sections, including Caddy; no public IP lookup
lhm check                       # idempotency audit across all 11 areas

lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345] [--ssh-user NAME] [--allow-user NAME]...
lhm ssh-confirm ID              # from a new SSH key login on the target port
lhm ssh-recover ID              # retry a failed SSH recovery; console recommended
lhm apply firewall [--allow PORT/PROTO]...
lhm apply fail2ban [--bantime 8h] [--findtime 30m] [--maxretry 3] [--caddy-maxretry 5]
                  [--caddy | --caddy-direct --caddy-protected-path PATH ... | --caddy-revoke-direct]
lhm apply caddy --site example.com --upstream 127.0.0.1:8080
lhm apply cleanup-services      # interactive: pick services/ports to disable
lhm apply sysctl
lhm apply sandbox [ssh|nginx|fail2ban]...
lhm apply audit | logging
lhm apply alert --webhook URL   # https only
lhm apply backup --target /var/backups/lhm
lhm apply all --webhook URL --target PATH [--ssh-user NAME --key FILE] [--security-only] [--caddy]
                                # ordered run; no ssh-hardening, cleanup-services or Caddy setup
lhm rollback FILE               # restore LHM's newest .bak[.N] (one prompt)

# globals: --dry-run --json --verbose --color auto|always|never
```

`lhm rollback` restores `FILE.bak`, `FILE.bak.1`, … only for known
lhm-managed system paths. It refuses symlinks and user-owned
`authorized_keys` (restore those manually as the account owner). It is not a general
snapshot or restore tool: packages, services and other prior state are not
recovered. For managed Caddy and fail2ban configuration, inspect with `query`
and reapply the intended settings; `rollback` refuses those files. Rollback
requires root, prints the plan, and prompts once on a TTY unless the bypass
is set. A refused confirmation exits **3** with nothing changed.

`query` reports observations, not a pass/fail audit. Unavailable probes may
need root, and exit **0** means the report was produced, not that hardening
is complete. For `check`, read the individual rows: `needs-change` alone
does not produce a nonzero exit; `UNKNOWN` does.

### Network and time

`lhm query system` reports local interface addresses, IPv4/IPv6 default routes,
UTC and local time, timezone and clock synchronization when available. It does
not contact an external IP service by default. `--public-ip` explicitly sends
separate IPv4 and IPv6 HTTPS requests to `api64.ipify.org` via `curl` and exposes
the corresponding egress addresses to that service. It cannot be used with
`--dry-run`. An unavailable lookup is not proof that the address family is disabled.

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

1. `updates` — normal apply refreshes and verifies APT before running the
   host's normal upgrade. Manual `--security-only` and the scheduled
   [worker](#provision-the-apt-security-worker) instead use `apt-get upgrade`
   with a freshly verified, isolated security-only APT view, not the
   `unattended-upgrade` program. Live apply can add `lhm-security.sources` if
   the security pocket is missing and components can be derived from a
   distro-keyring-scoped base source. The scheduled worker requires a
   configured security source and never adds one. Restore a missing archive
   keyring from trusted distro media or packages: `debian-archive-keyring`
   on Debian, `ubuntu-keyring` on Ubuntu.

   Missing bootstrap packages (including `unattended-upgrades` and common
   tools) come from a separate isolated distro base and security view.
   With `--security-only`, that bootstrap rejects any locked dpkg plan that
   would change an already installed package; it does not silently skip
   packages or fall back to a normal upgrade. LHM refuses local unattended
   package blacklists, whitelists or APT pinning rather than ignoring them.
   `query updates` and `check` inspect existing indexes and policy without
   refreshing or upgrading. They may report the private scheduled policy as
   unverified without root; package or service presence does not verify it.
   `lhm rollback` does not undo package changes.
2. `ssh-user` / `ssh-hardening` — create or update an account with a validated
   pubkey (`--sudo` grants sudo),
   then a drop-in (`sshd_config.d/99-lhm.conf`): `Port 22345`,
   `PermitRootLogin no`, `PasswordAuthentication no`, pubkey-only auth, and
   `AuthorizedKeysFile .ssh/authorized_keys`.
   Key-file operations inside the managed account's home run as that account,
   not as root. For `--key FILE`, use a public-key file readable by the invoking
   sudo user. For direct root runs, the source and all its directories must
   be root-owned, free of symlinks and not writable by group or others.
   On `ssh-hardening`, `--ssh-user NAME` selects one existing non-root account
   whose `.ssh` and `authorized_keys` modes can be tightened to `0700` and `0600`.
   It neither creates missing paths nor adds the account to `AllowUsers`.
   Without a verified non-root sudo invoker, a root shell must pass
   `--ssh-user NAME` even for a drop-in-only change. Symlink paths, multiply
   linked `authorized_keys`, and home or key paths writable by group or others
   are refused, not repaired.
   LHM refuses a chmod that would add any permission bit; resolve that case
   manually from the console before retrying.
   Mode changes also require a filesystem that provides durable inode identity.
   For example, `lhm apply ssh-hardening --allow-user ops` adds `ops` to the
   lhm-managed allowlist, retaining all existing names. Before applying a
   change, lhm revalidates keys for every retained and added user after
   confirmation. There is no removal flag. With an existing generated
   `99-lhm.conf`, omitting the flag keeps the established
   list without discovering more users. If the file is absent, lhm uses the
   explicit names or, with no flag, discovers users with valid keys under
   `/home`. lhm refuses to overwrite an unrecognized or manually edited
   `99-lhm.conf`.
   OpenSSH combines separate `AllowUsers` directives additively; lhm neither
   imports names from nor rewrites other SSH configuration files.
   `lhm query ssh` reports the managed allowlist separately from unlisted
   key holders; neither list proves that a user can log in.
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
   `default deny incoming`, `allow outgoing`, enable. If neither SSH socket
   is active and the standalone `sshd -T` fallback succeeds but reports no
   ports, supply a verified port explicitly, for example
   `lhm apply firewall --allow 22/tcp`. An unknown SSH socket state, unverified
   active socket, or failed or invalid fallback blocks UFW even with `--allow`.
   Check systemd and the listeners from the local console before retrying.
   Only `ALLOW`/`ALLOW IN` rules count, never `ALLOW FWD`.
   No IPv6 route or global address does not mean IPv6 is disabled. Live apply
   refuses unknown IPv6 state or a mismatch with UFW's `IPV6` setting; lhm does
   not change either setting. It checks both rule families when IPv6 is enabled.
   If UFW is already active with different defaults, lhm refuses to change
   them because that would restart the firewall.
4. `fail2ban` — installs fail2ban + nftables (only a Recommends upstream!) and
   writes a **`jail.d/99-lhm.local` drop-in** with the sshd jail on port 22345.
   It never touches `/etc/fail2ban/jail.local`: load order is
   `jail.conf` → `jail.d/*.conf` → `jail.local` → `jail.d/*.local`, so the
   drop-in wins over a hand-maintained `jail.local`, which keeps the host's own
   custom jails intact. sshd jail: `mode = aggressive`, `maxretry = 3`,
   `findtime = 30m`, `bantime = 8h` with incrementing bans
   (`bantime.increment`, `factor = 3`, `maxtime = 4w`, `rndtime = 30m`).
   Override the SSH settings with `--maxretry`, `--findtime`, and `--bantime`.
   The increment needs fail2ban's dbfile (packaging default
   `/var/lib/fail2ban/fail2ban.sqlite3`). See [Caddy and fail2ban](#caddy-and-fail2ban)
   for web jails. `cleanup-services` lists listening ports/enabled services
   (protected set excluded) for interactive disable.
5. `sysctl` / `sandbox` — hardened sysctl drop-in (`kptr_restrict`,
   `dmesg_restrict`, `rp_filter`, ...); systemd sandbox drop-ins for a fixed
   whitelist (ssh, nginx, fail2ban) with per-service exceptions and automatic
   rollback if a restart fails.
6. `audit` / `logging` / `alert` / `backup` — auditd rules (immutable `-e 2`),
   persistent journald + logrotate, daily webhook alert (journal errors +
   fail2ban bans) via a root-only 0700 script, daily tar backup of /etc + /home
   with sha256 manifest, 0700/0600 permissions, rotation.

### Caddy and fail2ban

1. Start the loopback backend and point the site's DNS at an IP reachable by
   clients. Deploy Caddy explicitly; both flags are required on every run.

   ```sh
   sudo /opt/lhm/bin/lhm apply caddy --site example.com --upstream 127.0.0.1:8080
   ```

   LHM validates the candidate Caddyfile, refuses unmanaged takeover, and
   checks the local HTTP-to-HTTPS redirect and backend. It does not change UFW.
   Resolve any reported failure before exposing the site; a failed backend
   check can leave Caddy active.
2. Review and confirm a separate firewall run after Caddy is up and any SSH
   hardening transaction is confirmed:

   ```sh
   sudo /opt/lhm/bin/lhm apply firewall
   ```

   A live run proposes `80/tcp` and `443/tcp` automatically only if it verifies
   live routing and listeners for the managed site. If those ports are missing
   from the plan or existing allowances, investigate before proceeding. The
   automatic Caddy plan does not open UDP or loopback upstream ports, or remove
   old rules. Verify HTTP redirection and HTTPS from an external client.

`query caddy` (also in `query all`) shows on-disk managed settings and systemd
status, not live routing, TLS or reachability. `query firewall` shows rules
reported by UFW separately from the Caddy ports eligible for automatic ingress;
the eligible list does not mean those ports are already open. Dry-run does not
probe live Caddy ingress.

The `caddy-lhm-access-*` file jail is opt-in. Use it only if clients connect
directly to Caddy, not through a CDN, reverse proxy or load balancer that
changes the socket peer. Confirm that your app already protects the listed
paths and returns `401` for failed authentication; listing a path does not
add authentication. For example, on an already deployed managed site:

```sh
sudo /opt/lhm/bin/lhm apply fail2ban --caddy-direct \
  --caddy-protected-path /admin/login --caddy-protected-path /api/private
```

Repeat `--caddy-protected-path` for each exact path, with no wildcards or
query string. The jail reads `/var/log/caddy/access.log` and counts only
actual `401` responses on those paths (ignoring the request's query string).
It uses the socket peer IP, not forwarded headers. `--caddy-maxretry` defaults
to 5 for both Caddy modes and must be at least 2 for the file jail. Check the
apply result and verify the jail and ban behavior before relying on it.
`query fail2ban` reports the configured mode and, when available, whether the
named jail is live; it does not prove ban enforcement.

The opt-in is bound to a fingerprint of the verified running Caddy config.
An unverifiable or different runtime blocks new and restored bans. A later
`apply fail2ban` disables stale file-jail configuration; a Caddy apply that
changes the config or starts an inactive service also revokes the file jail.
Before changing ingress topology, revoke the opt-in with
`lhm apply fail2ban --caddy-revoke-direct`. After reconfiguration, repeat
the opt-in with the full path list only if clients still connect directly.

`apply fail2ban --caddy` (also `apply all --caddy`) still selects the legacy
journald jail for `401/403/404/429` on TCP 80/443. It requires Caddy access
logs in journald and does not use the file-jail policy. Existing legacy
jails are not migrated automatically. Do not combine `--caddy` with the
direct opt-in or revocation flags; external Caddy jails are not taken over.

### Session-lockout guards (run order matters)

`apply all` runs 1 → 6 in order and stops at the first FAIL or ABORTED module.
It can provision an SSH user but does not run `ssh-hardening`. For a live SSH
hardening change, use the standalone workflow below and finish it before
running `apply firewall` or `apply sandbox`. If a firewall is already active,
make sure it permits the target SSH port before starting.

1. **Have local or out-of-band console access.** Preview
   `lhm apply ssh-hardening --ssh-user admin --dry-run` (use your account name;
   add `--port` if needed). For a drop-in-only change, keep the existing SSH
   session open and run the same command without `--dry-run` as root using
   the trusted CLI. If the plan includes chmod, run the live apply from a
   Linux console in rescue or emergency mode with `multi-user.target` inactive;
   SSH sessions and PTYs do not qualify. Use the root console shell directly
   if `sudo` allocates a PTY. Quiesce all external key writers, keep the console
   available, and ensure SSH is already listening for the watchdog preflight
   and the fresh login check. Answer the single prompt with `y`; chmod plans
   do not allow the confirmation bypass.
   If you cannot isolate key writers, inspect the ownership and key contents
   from the console, adjust modes manually, and rerun `ssh-hardening --dry-run`.
   For a drop-in or permissions change, LHM arms and verifies a
   **10-minute systemd recovery timer** before writing the drop-in or changing
   modes, and prints the transaction ID. A failed or unknown timer check
   blocks the change. A permissions-only change still requires `ssh-confirm`
   from a fresh key login, even though sshd is not reloaded.
2. From your client, open a new connection as an approved administrator,
   using the real private key and the target port. Disable connection
   multiplexing so this is a fresh login, and verify that the key was used.
   This is a login test, not another CLI prompt:

   ```sh
   ssh -v -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes \
     -i ~/.ssh/admin_ed25519 -p 22345 admin@host
   ```

3. From that new session, substitute the printed ID and use the trusted
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
factor. Verify the target port and key from the client. If an old SSH session
is available, keep it until confirmation succeeds. If the change is not
confirmed within the window, systemd runs recovery even if the apply CLI was
killed. This protection is **same-boot only**; do not reboot while confirmation
is pending.
LHM records the original modes and inode identities, then journals intent
and a completion receipt for each chmod. The initial chmod only removes bits
relative to the verified starting mode; Linux has no atomic compare-and-chmod
against external writers. Recovery can roll back sshd, but
never changes file modes or widens permissions. If a chmod attempt was
journaled, recovery retains the failed marker and reports the affected paths,
identities and old modes for the console operator. Restoring sshd alone may
not restore key login; keep the independent console available.

If arming fails with `unexpected watchdog property: … WorkingDirectory`,
affected versions of `systemd-run` omit the property when given
`--working-directory=/` because `/` is the default. The fix sets
`--property=WorkingDirectory=/` explicitly and still strictly verifies the
property. Before retrying, deploy the CLI and worker from the same commit
containing the fix, following the
[safe replacement instructions](#provision-the-ssh-watchdog).

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

### Recover a failed SSH transaction

If LHM reports a failed transaction (for example, `pending (failed)`), recovery
has not completed and `ssh-confirm` cannot accept the change. This does not
diagnose an account or SSH key problem. Foreground apply can leave the
transaction in `failed` before the timer worker runs, so the service journal
may be empty. Check the original apply output, including stderr, as well as
the service journal.

Stay in the same boot and use a local or out-of-band console: recovery can drop
your SSH connection. Replace `ID` in the examples with the printed transaction
ID and inspect the per-transaction units and journal:

```sh
id=ID
sudo systemctl --system status "lhm-ssh-rollback-$id.timer" "lhm-ssh-rollback-$id.service"
sudo journalctl -b -u "lhm-ssh-rollback-$id.service"
```

An expired transient unit may no longer appear in `systemctl`; check the
journal. You may need to fix the underlying problem before retrying. Stay in the
current boot and leave `pending.json` untouched.

If the failure names an SSH permission change, use a Linux console, virtual
terminal or serial console (not an SSH PTY). Quiesce all writers to the
account's home and key paths. Compare the reported device, inode, owner, group
and birth time against the actual nonsymlink path (for example,
`stat -c 'device=%d inode=%i uid=%u gid=%g birth=%w mode=%a' -- PATH`).
Review the file contents for untrusted keys. For each attempted inode, if its
identity matches and the recorded original mode is still safe, leave it alone
if already at that mode or restore it with the printed `chmod MODE -- PATH`
as the owning account. Do not chmod a replacement or an unattempted file.
`ssh-recover` on the console verifies the restored modes and finishes the
original rollback without chmod. If identity or safety cannot be verified,
stop and keep the marker for manual investigation.

Using the absolute path to your trusted CLI, run:

```sh
sudo /opt/lhm/bin/lhm ssh-recover ID
```

For permission recovery, run the same command without `sudo` from the root
console shell if `sudo` allocates a PTY.

This same-boot command requires root and a TTY, with one exact `y` and no
bypass. It only retries the original recovery for the matching failed
transaction; it cannot accept the failed configuration. If recovery cannot be
verified, the pending marker is retained. If LHM refuses an unsafe drop-in or
backup, investigate from the console; do not change ownership or permissions
just to bypass the refusal.

If the installed CLI lacks `ssh-recover`, independently deploy a trusted,
root-controlled CLI from this release at a separate path and use that path
for the command. It can retry recovery from a compatible v1 marker in the same
boot, even if the marker lacks the SSH session freshness field used for
confirmation. Do not replace the installed CLI or worker, and do not edit or
delete the marker. Once recovery has cleared the marker, deploy the
matching upgraded CLI and worker before the next SSH apply, following the
[safe replacement instructions](#provision-the-ssh-watchdog).

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
| ssh | attempt to restore this run's prior drop-in and listener; never chmod | inspect the journal, restore attempted modes only if safe, and [retry recovery](#recover-a-failed-ssh-transaction) from the console; do not delete transaction state |
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
in the same boot, then check the recovery log and verify the previous
configuration and listener. If chmod was attempted, verify expiry did not
widen modes, complete console recovery, and test a fresh key login. Unit tests
do not exercise real timer expiry.

## Layout

```
src/lhm/cli.py            argparse assembly, exit codes
src/lhm/core/             runner / confirm / backup / files / distro / checks / report
src/lhm/modules/          system, updates, ssh, firewall, fail2ban, caddy, services, sysctl,
                           sandbox, logging, audit, alert, backup
templates/                sshd, sysctl, Caddy, fail2ban (jail and filters),
                           audit rules, journald, logrotate, alert + backup
                           timers/scripts
integration/              Dockerfile, run.sh, scenarios/01-09
DESIGN.md                 authoritative design (safety rules §Safety)
```

## Supported platforms

Debian 12 / Ubuntu 22.04+ (apt backend). The `DistroBackend` seam exists for
other backends; RHEL is unimplemented. The APT backend checks the distro
codename, architecture, sources and signed metadata at runtime. That support
range is not a VM test matrix: the updates scenario in the Ubuntu 24.04
container suite is a dry-run, not a live upgrade or timer test.
