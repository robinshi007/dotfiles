# lhm — Linux Hardening & Management CLI

Status: design confirmed 2026-11-22. Python >= 3.15, stdlib only (argparse, subprocess,
pathlib, shutil, string.Template, json, hashlib, urllib.request). Dev dep: pytest via uv.

## Scope

- Distro: Debian 12 / Ubuntu 22.04+ (systemd, apt, OpenSSH >= 8.2, ufw with nftables
  fallback deferred). Single `DistroBackend` seam, apt-only this phase.
- `query` runs unprivileged; `apply` requires root (refuse otherwise, fail closed).
- All system calls go through `Runner` (subprocess with timeout, check, structured log).

## CLI

```
lhm query system [--public-ip] [--json]
lhm query ssh|firewall|fail2ban|services|ports|sysctl|audit|updates|caddy|all [--json]
lhm check                                    # OK / needs-change / UNKNOWN; cleanup is manual
lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345] [--ssh-user NAME] [--allow-user NAME]...
lhm ssh-confirm ID                           # accept a pending live SSH change
lhm ssh-recover ID                           # retry recovery of a failed SSH transaction
lhm apply firewall [--allow PORT/PROTO]...   # 22345/tcp pre-allowed by default
lhm apply fail2ban [--bantime 8h] [--findtime 30m] [--maxretry 3] [--caddy-maxretry 5]
                  [--caddy | --caddy-direct --caddy-protected-path PATH ... | --caddy-revoke-direct]
lhm apply caddy --site HOSTNAME --upstream LOOPBACK:PORT
lhm apply cleanup-services                   # interactive per-item selection
lhm apply sysctl
lhm apply sandbox [SERVICE]...               # fixed whitelist only
lhm apply audit | logging | alert --webhook URL | backup --target PATH
lhm apply all --webhook URL --target PATH [--ssh-user NAME --key FILE] [--security-only] [--caddy]
                                              # no ssh-hardening, cleanup-services or Caddy setup
lhm rollback FILE                            # restore newest .bak[.N]

Global: --dry-run  --json  --verbose  --color auto|always|never.
No --yes flag: changed modules need
one confirmation each; non-TTY write runs fail closed unless the operation supports
the environment bypass and it is enabled.
```

`query system` reads local network and clock state; it does not perform an
external IP lookup unless `--public-ip` is passed to that target. The opt-in
requests disclose egress addresses to the HTTPS lookup service and are
incompatible with dry-run. Neither `query all` nor `check` uses the lookup.
`query all` includes the read-only Caddy status; `apply all` does not deploy
Caddy. `query caddy` reports disk and systemd state, not verified live routing.
`query firewall` reports UFW-visible rules separately from Caddy auto-ingress
eligibility, and `query fail2ban` separates configured Caddy mode from live
jail status. These reports are not reachability or ban tests. Query success
means a report was produced even if probes were unavailable. `check` exits 1
for `UNKNOWN`, not for `needs-change` alone.

## Execution model

Every apply module = list of Steps: `check() -> plan() -> confirm -> backup ->
execute -> verify()`. Idempotent check first: target state already reached => skip,
no confirmation. Otherwise print the full plan (file diffs, risks) and ask for
one exact `y`. Abort on anything else; completed steps are kept, print a rollback
hint.
For `apply cleanup-services`, selecting units is input to the plan, not confirmation.

`LHM_CONFIRM_BYPASS=1` (env, exact value `1`) skips the single confirmation prompt
where supported for unattended root runs and the integration suite
(`lhm/integration/`). It is not a CLI flag and never bypasses the idempotency
check or the dry-run guarantee. `ssh-confirm`, `ssh-recover`,
`apply cleanup-services` and SSH chmod plans do not honor it.

## Safety rules

1. Backups: copy to a private sibling temp file and publish atomically as
   `f.bak`, `f.bak.1`, `f.bak.2`… without overwriting existing backups.
   `rollback` uses the newest number and atomically replaces the target.
   The CLI accepts only exact managed system-file paths, not aliases or
   symlinks. Restore `authorized_keys` manually as the account owner. Caddy
   and fail2ban configuration require lifecycle-aware reapply, not file rollback.
2. Appends to existing files use marked blocks. Repeated runs compare the body;
   changed content replaces only that block after a backup. Malformed blocks
   are rejected without a write:
   ```
   # ===== lhm 2026-11-22T10:00:00Z ssh-hardening begin =====
   ...content...
   # ===== lhm ssh-hardening end =====
   ```
3. Drop-in preferred over appending (sshd first-match-wins semantics would
   silently ignore tail appends): `/etc/ssh/sshd_config.d/99-lhm.conf`,
   `/etc/sysctl.d/99-lhm.conf`, `/etc/systemd/system/<svc>.service.d/99-lhm-sandbox.conf`,
   `/etc/audit/rules.d/99-lhm.rules`, `/etc/fail2ban/jail.d/99-lhm.local`,
   `/etc/systemd/system/apt-daily-upgrade.service.d/51-lhm.conf`.
   Creating a new drop-in needs no `.bak`; identical content needs no rewrite.
4. SSH anti-lockout order (apply ssh-user -> ssh-hardening): create user, install
   authorized_keys (0700/0600, validate pubkey format first) -> only then write
   drop-in `PermitRootLogin no, PasswordAuthentication no,
   KbdInteractiveAuthentication no, Port 22345` -> `sshd -t` must pass -> gate on
   `sshd -T` effective values (port/root/password) BEFORE any reload: an earlier
   `sshd_config.d/*.conf` (e.g. Ubuntu 50-cloud-init.conf) wins first-match, so a
   mismatch rolls the drop-in back and FAILs naming the conflicting directive.
   Public keys must have a supported type and structurally valid wire fields
   with no trailing data. This is not proof of authentication.
   An active `ssh.socket` or `sshd.socket` can own the listener, so `sshd -T`
   does not establish the live port. Disable that socket and restart
   `ssh|sshd`, otherwise reload the service. When `ss -tlnp` is available,
   check for an SSH-owned listener; an unrelated listener is not a pass.
   A live change requires an observed prior listener and a successful
   post-change listener check. A socket-to-service migration preserves
   whether the listener is configured to come up on reboot.
   The per-admin `sshd -T -C` check requires public-key authentication to
   be enabled and permitted by at least one authentication chain. It also
   requires a single effective `AuthorizedKeysFile` resolving to that
   account's managed key. Ambiguous whitespace or multiple printed paths are not
   treated as evidence. The check evaluates one connection context, not
   every possible source or destination.
   After an attempted candidate write, restore or verify this run's prior
   drop-in, then recover and verify SSH runtime under the old configuration
   even if the CLI never issued a reload. A daemon may have read the
   candidate during an independent restart or socket activation; matching
   listen addresses and ports alone do not prove the old authentication
   configuration is in use. Prepare OpenSSH's privilege separation directory
   (`/run/sshd`) before validating the restored configuration. Recovery reports
   failure explicitly if the prior listener cannot be confirmed. Do not switch
   away from a socket when its original enablement cannot be read.
   SSH apply, confirmation, timed and manual recovery, and CLI rollback of the managed
   SSH drop-in serialize against the same SSH mutation lock. Confirmation and
   recovery recheck the current transaction under lock so a stale ID or a race
   at expiry cannot act on a newer or already resolved transaction. While a
   transaction is pending, refuse a new SSH hardening apply and manual rollback
   of the managed drop-in. The lock does not coordinate out-of-band changes:
   operators must not run `apply firewall` or `apply sandbox` concurrently.
   The `sshd -T` gate also checks that a non-empty effective `AllowUsers`
   includes all the selected administrators. Existing managed names are
   retained, `--allow-user` appends names, and initial discovery runs only
   when there is no managed drop-in and no explicit list. Other OpenSSH
   allowlist directives are not rewritten.

   `--ssh-user` chooses the existing non-root NSS account whose `.ssh` and
   `authorized_keys` modes are tightened to 0700/0600, independently of
   `--allow-user`. Root without a verified non-root sudo invoker must pass
   `--ssh-user NAME`, even for drop-in-only hardening. No missing paths are
   created. A mode change may only remove permission bits. Refuse symlinks,
   incorrect ownership, unsafe write or special bits and multiply linked
   `authorized_keys`. For direct root key imports, the source file and its
   parent directories must be root-owned, symlink-free and not writable by
   group or others.

   For a changed live `apply ssh-hardening`, obtain one confirmation first, then
   arm and verify a 10-minute systemd timer before any drop-in or mode change
   and print the transaction ID. Timer setup failure or unknown state fails closed.
   The timer is independent of the CLI and starts recovery if the transaction
   is still unconfirmed at expiry, even after the CLI is killed. Its scope is
   the current boot only. PID 1 schedules transient
   `lhm-ssh-rollback-<id>.timer` and `lhm-ssh-rollback-<id>.service` units.
   LHM verifies their state and reads the monotonic deadline from systemd via
   `/run/dbus/system_bus_socket`. The volatile transaction journal is
   `/run/lhm-ssh-rollback/pending.json` (root-only, `0700` directory and `0600`
   file).

   Journal the account, durable inode identities (including `statx` birth time)
   and original modes, plus intent and completion evidence for each chmod.
   A chmod plan requires a verified foreground Linux console (not a PTY),
   `rescue.target` or `emergency.target` active and `multi-user.target`
   confirmed inactive. The operator must quiesce external key writers and
   keep that console available. The console and unit state are checked before
   confirmation and again before chmod; confirmation bypass is disabled.
   Permission-only transactions do not reload sshd, but still require a fresh
   login and `ssh-confirm`. Recovery never chmods or widens permissions. After a
   journaled chmod attempt, automatic recovery can restore sshd but retains the
   failed marker and reports the targets for manual review. On an independent
   Linux console, the operator can restore the recorded original modes of
   attempted inodes after verifying identity and safety; `ssh-recover`
   verifies the modes and finishes rollback without chmod.
   Do not modify replacements or unattempted targets.

   The worker invokes `/opt/lhm-ssh-rollback/python/bin/python3.15` with
   `-I -S -B`. It requires standalone CPython 3.15 with its own prefix-local
   stdlib and Python search paths, then adds `/opt/lhm-ssh-rollback/src` to
   import the same release's `lhm` package. Both trees and their ancestors
   must be root-owned, not group- or world-writable, and symlink-free. The
   dedicated root-controlled deployment keeps the worker independent of
   the caller's checkout, project venv, and uv runtime. Path checks protect
   the installed copy, not its provenance: provision only from trusted artifacts
   (see [README](README.md#provision-the-ssh-watchdog)).
   Arming requires matching protocol, schema and source fingerprint. The
   permissions-aware worker uses protocol 4; the journal schema remains v1.

   Have local or out-of-band console access and keep any old SSH session open.
   From a second, non-multiplexed real key login on the target port as an
   approved administrator, run
   `sudo env SSH_CONNECTION="$SSH_CONNECTION" /opt/lhm/bin/lhm ssh-confirm ID`
   with the printed ID and the absolute path to your trusted, root-controlled
   lhm installation. The new login is an operator test, not another CLI prompt.
   `ssh-confirm` requires root via an authorized administrator, a TTY, and one
   exact `y`, with no bypass. It checks the stock OpenSSH process ancestry for
   a transport that started strictly after local verification in this boot. It
   rechecks the transaction, reported target port and local listener before
   accepting. Neither the apply output nor `SSH_CONNECTION` proves the actual
   destination port or that public-key authentication took place.
5. Firewall order: probe the ports sshd listens on NOW (`ss -tlnp`, fallback
   `sshd -T`), allow every current SSH port AND 22345/tcp BEFORE
   `default deny incoming` + `enable`. A server still on port 22 (or `apply all`
   with only ssh-user done) must keep its current port open. When no listener can
   be probed, an explicit `--allow PORT/PROTO` is accepted only if neither
   socket is active and the standalone `sshd -T` fallback succeeds without
   any `Port` entries. Unknown socket state, incomplete active-socket
   evidence or a failed or invalid fallback blocks UFW even with `--allow`.
   Only `ALLOW`/`ALLOW IN` rules satisfy the inbound check: `ALLOW FWD` is not
   an inbound rule. Check IPv6 capability locally, not from routes or globally
   scoped addresses. Unknown capability or unknown UFW IPv6 settings block
   live apply, as does any mismatch between them. For enabled IPv6, verify
   inbound coverage for both address families. If active UFW defaults differ
   from the target, fail rather than restart UFW to change the defaults.
6. Verify after every module (sshd -T grep, ss -tlnp listening port, ufw status
   verbose, sysctl spot checks, systemd-analyze security, augenrules --check,
   fail2ban-client status, plus `fail2ban-client get sshd bantime` and
   `fail2ban-client -d` for `bantime.increment`; unprobeable checks report
   SKIPPED, not FAIL). Any FAIL => non-zero exit + rollback hint. Exit codes:
   0 = all steps OK/SKIPPED/CHANGED, 1 = a step FAILed, 2 = usage error, 3 =
   ABORTED (the user or a non-TTY stdin refused the confirmation: nothing was
   changed, so automation must not read 0 as "hardened"). `apply all` stops at the
   first FAIL (exit 1) or the first ABORTED module (exit 3, naming it).
   A sandbox drop-in whose `systemctl restart` fails is rolled back automatically
    (restore this run's backup, else delete a newly created drop-in) and the
    step FAILs; ssh's
   ProtectHome=read-only keeps `/home/*/.ssh/authorized_keys` readable.
   Automatic recovery is per-module and deliberately narrow — lhm only undoes
   changes it made in this run, never global host state: ssh attempts to restore
   its prior drop-in and listener, never chmods; sandbox rolls its drop-in
   back; **firewall never disables a firewall that was already active**
   (no automatic `ufw disable`, the
   hint is conditional/manual) and **audit never rewrites/replaces pre-existing
    audit rules after a live verification failure** (a load failure can leave
    `99-lhm.rules` on disk; use the manual rollback hint). A failed run may be
    partially applied; earlier modules stay applied.
   Config/listener checks (`sshd -T`, `ss -tlnp`, `ufw status`) validate the local
   configuration only, never that remote key/password login works: keep the proven
   admin session open and test key login from a second session.
   The SSH timer schedules an attempt, not a guarantee of restoration. The
   worker returns exit status `75` for transient I/O (including journal read
   `EIO`), probe failures, pending jobs, and listeners not yet ready. A failed
   recovery-time `sshd -t` (including exit `255`) also defers recovery: that
   exit code does not distinguish invalid syntax from an unavailable prerequisite.
   The transient service uses `Restart=no`, `RestartForceExitStatus=75`,
   `RestartSec=5s`, and `StartLimitIntervalSec=0` to retry only status `75`
   without a start-rate limit.
   Corrupt recovery state or external drift in the managed configuration
   instead retains the pending marker for manual recovery without overwriting
   external changes or triggering a restart loop. The `failed` phase means
   recovery has not completed and the change cannot be confirmed; it does not
   diagnose an account or SSH key problem. Foreground apply can set this phase
   before the timer worker runs, so check the original apply output (including
   stderr) as well as the current boot's journal for `lhm-ssh-rollback-<id>.service`.
   `ssh-recover ID` requires root, a TTY, and one exact `y` with no bypass.
   It retries the original recovery only for the matching failed transaction
   in the same boot. It does not override trust checks or clear the marker if
   recovery cannot be verified. Use the local or out-of-band console; see
   [README](README.md#recover-a-failed-ssh-transaction) for legacy v1 recovery
   without replacing the installed worker or deleting the marker.
7. Secrets: the alert script embeds the webhook URL, so it is installed 0700
    root:root and its `.bak` is no more permissive than 0700; unit files never
    contain the URL. Shell
   template values are single-quoted, so values with `'` or control characters are
   refused, not escaped. Error messages and plans only echo the webhook's scheme +
   host, never its path/query; `--verbose` prints "(content hidden: contains a
   secret)" instead of the script (the `.bak` content and the diff are suppressed
    too). The URL is never passed as argv: alerts only call `systemctl`.
    Non-shell templates likewise reject quotes and control characters in
    substituted values; format-specific inputs still have separate validators.
   Backup target: 0700 dir, `umask 077` (archives 0600), refuse `/`, `/home...`,
   `/etc...` (tar would ingest the growing archive) — checked after resolving
   `//etc` and symlinked parents — and refuse any character outside
   `[A-Za-z0-9/_.-]` (a space would split systemd's `ReadWritePaths=`, `%` is a
   specifier); a tar failure removes the partial archive and exits 1 instead of
   passing verify.
8. Audit immutability is observed, not assumed: an `augenrules --load` failure on
   an identical rules file is a warning only when `auditctl -s` reports `enabled 2`,
   otherwise FAIL. `lhm rollback` is a non-idempotent write: it requires root
   and, unless the bypass is set, one prompt on a TTY. It backs up the current
   file first (a rollback can itself be rolled back).

## Modules (`apply all` order, grouped)

| # | module | summary |
|---|--------|---------|
| 1 | updates | refresh APT and upgrade (`--security-only` uses a verified isolated security view); configure the independent security worker for `apt-daily-upgrade` |
| 2 | ssh | optional `ssh-user` provisioning; `ssh-hardening` is standalone |
| 3 | firewall | allow 22345/tcp and current SSH ports first, default deny incoming / allow outgoing, enable |
| 4 | fail2ban | apt install fail2ban + nftables; `jail.d/99-lhm.local` drop-in (sshd port 22345, systemd backend, aggressive mode, maxretry 3, findtime 30m, incremental bantime starting at 8h); optional Caddy jail; never edit `jail.local` |
| 5 | sysctl+sandbox | sysctl.d template (rp_filter, no icmp redirects accept, kptr_restrict=2, dmesg_restrict, unprivileged_bpf_disabled); sandbox drop-ins for fixed whitelist only (sshd, nginx, fail2ban) with per-service exceptions |
| 6 | logging/audit/alert/backup | journald persistent + logrotate template; auditd + rules.d template + augenrules; alert = systemd timer + script scanning journalctl -p err / fail2ban bans since last run, webhook via urllib, state file; backup = timer + tar template (/etc /home), sha256 manifest, keep N rotate, local dir target |

**Updates:** The APT security check uses the OS codename, native architecture,
distro archive keyring and signed Release metadata. The keyring package is
`debian-archive-keyring` on Debian and `ubuntu-keyring` on Ubuntu. For a managed
source, Debian uses its security archive; Ubuntu uses its security archive or
Ubuntu Ports depending on architecture.
Refuse unsafe source options, failed refreshes and missing or unverified native
indexes. Live apply may add `lhm-security.sources` only when a security source
is absent and it can derive components from a distro-keyring-scoped base source.
The scheduled worker requires an existing scoped source and does not create one.
A missing trust anchor is not bootstrapped.

Normal apply uses the host's APT view for its upgrade. Manual `--security-only`
and scheduled upgrades use `apt-get` with a freshly verified, isolated
security-only view, not `unattended-upgrade`. Bootstrap installation of missing
packages uses a separate distro base plus security view. In security-only mode
its dpkg pre-install hook refuses a locked action plan that would change an
existing package. Fail closed on local unattended blacklists, whitelists or APT
pinning instead of dropping administrator exclusions. Config rollback does not
roll back package changes.

Provision the automatic worker first with `scripts/install-apt-security.sh`
from a trusted, reviewed, committed `HEAD`; follow the
[installer steps](README.md#provision-the-apt-security-worker) to verify the
commit and managed CPython image. The first-install script probes a private
root-controlled runtime with committed sources and templates, then publishes
`/usr/local/libexec/lhm-apt-security` without replacing an existing launcher.
Installation does not change APT or systemd timers. `apply updates` requires a
matching helper and an already enabled, active `apt-daily-upgrade.timer`
triggering `apt-daily-upgrade.service`. Replace only verified stock commands:
`apt-daily` refreshes indexes only, and `apt-daily-upgrade` invokes the helper.
Conflicting local commands or managed drop-ins are refused. Query and check
inspect existing indexes and policy without refreshing or upgrading;
unprivileged inspection may leave the private scheduled policy unverified.

Runtime validation of Debian/Ubuntu release, architecture and archive trust
is not a VM test matrix. The Ubuntu 24.04 container updates scenario tests
dry-run planning, not a live transaction or scheduled execution.

**Caddy:** Start the loopback backend and deploy with explicit
`apply caddy --site HOSTNAME --upstream LOOPBACK:PORT`, which never changes UFW.
The Caddyfile pairs one DNS hostname with a loopback upstream and redirects
that site's HTTP requests to HTTPS on the same hostname. Then use a separate
confirmed `apply firewall` run for `80/tcp` and `443/tcp`; these rules are
automatic only with verified routing and listeners on an active, enabled,
LHM-managed instance. Dry-run does not perform that live probe. The Caddy plan
does not open UDP or upstream ports or remove old rules automatically. Public
access requires DNS pointing to a reachable IP.
Install the distro package with its default service held, refuse unmanaged
config takeover, validate as the service user, and attempt to restore the
previous config if activation fails. A failed loopback backend check can
leave Caddy active. A service status check does not verify public DNS, TLS or
reachability; verify the redirect and HTTPS externally.

**Fail2ban:** Load order is `jail.conf` → `jail.d/*.conf` → `jail.local` →
`jail.d/*.local`, so the lhm drop-in overrides a hand-maintained `jail.local`
without touching it. The SSH jail accepts `--bantime`, `--findtime` and
`--maxretry`. `bantime.increment` needs the dbfile (Debian/Ubuntu default
`/var/lib/fail2ban/fail2ban.sqlite3`, enabled by packaging). The drop-in uses
factor 3, a calculation capped at 4 weeks and 30 minutes of randomization.

The `caddy-lhm-access-*` file jail requires an explicit operator attestation
(`apply fail2ban --caddy-direct` and repeatable `--caddy-protected-path PATH`),
a readable JSON access log and a verified active managed Caddy config. LHM
does not infer direct-client topology or configure authentication. The filter
matches only an actual `401` on an exact listed path, excluding the query
string, and takes the IP from the socket peer. `--caddy-maxretry` defaults to
5 in both modes and must be at least 2 for the file jail. The file jail's
nftables actions cover TCP 80/443 and UDP 443; they do not open UFW ports.

Bind the path list to the running config fingerprint. A mismatch or unreadable
runtime prevents new and restored bans. Reapplying fail2ban disables stale
jail state, and applying changed Caddy config or starting inactive Caddy
revokes the file jail. Before changing ingress topology, use
`--caddy-revoke-direct`; re-attest after reconfiguration only if the topology
and full protected path list are still valid. `--caddy` (also on `apply all`)
selects the legacy journald mode (401/403/404/429), and is mutually exclusive
with direct opt-in and revocation. Existing legacy jails are not migrated
automatically. Do not take over external Caddy jails or filter overrides.
Activation is
`fail2ban-client reload --restart` when the daemon is already active (jails are
restarted in place, the server and its bans stay up) and `enable --now` when it
is not: a plain `systemctl reload` never re-runs the action's `actionstart`, and
when `banaction` resolves to a new action name fail2ban 1.0.2's reload deletes
both the old and the new action, leaving the jail with no action at all — bans
then only reach the DB and the nftables table is never created.

## Templates

`templates/*.tmpl` rendered via string.Template: fail2ban jail and filters,
Caddyfile and install hold, 99-lhm-sysctl.conf, sshd hardening, audit rules,
unattended-upgrades conf, journald, logrotate, alert/backup timer+service+script.

## Code layout

```
lhm/src/lhm/cli.py            # argparse assembly, exit codes
lhm/src/lhm/core/runner.py    # Runner: subprocess wrapper, timeout, log, fake-injectable
lhm/src/lhm/core/confirm.py   # single confirmation, TTY gate
lhm/src/lhm/core/backup.py    # .bak policy, rollback
lhm/src/lhm/core/files.py     # marked-block append, drop-in write, template render
lhm/src/lhm/core/distro.py    # DistroBackend (apt impl)
lhm/src/lhm/core/checks.py    # state probes (idempotency)
lhm/src/lhm/core/report.py    # plan/verify tables, --json
lhm/src/lhm/modules/*.py      # system, updates, ssh, firewall, fail2ban, caddy, services, sysctl, sandbox, logging, audit, alert, backup
lhm/templates/*
lhm/pyproject.toml            # uv, console script lhm, dev group pytest
lhm/tests/*                   # host-management commands use a fake runner
```

## Acceptance

- `pytest` green; tests never invoke real system tools (Runner faked).
- `--dry-run` performs zero writes (tested).
- Non-TTY apply fails closed (tested).
- `LHM_CONFIRM_BYPASS=1` skips only the single prompt where supported; it
  never skips the `ssh-confirm` or `ssh-recover` prompt.
- Backup naming/rotation tested; marked-block append idempotency tested.
- sshd drop-in content validated against `sshd -T` semantics in unit tests.
- `lhm/integration/run.sh` runs the scenarios against real Ubuntu containers
  (`6_audit` degrades to SKIPPED where the kernel refuses audit netlink).
- Real 10-minute timer expiry and SSH recovery are manual checks in a
  disposable systemd VM with console access.
