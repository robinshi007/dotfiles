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
lhm query system|ssh|firewall|fail2ban|services|ports|sysctl|audit|updates [--json]
lhm check                                    # idempotency audit: OK / needs-change
lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345] [--allow-user NAME]...
lhm ssh-confirm ID                           # accept a pending live SSH change
lhm apply firewall [--allow PORT/PROTO]...   # 22345/tcp pre-allowed by default
lhm apply fail2ban [--bantime 8h --findtime 30m --maxretry 3] [--caddy]
lhm apply cleanup-services                   # interactive per-item selection
lhm apply sysctl
lhm apply sandbox [SERVICE]...               # fixed whitelist only
lhm apply audit | logging | alert --webhook URL | backup --target PATH
lhm apply all --webhook URL --target PATH [--ssh-user NAME --key FILE]
                                             # ordered 1..6, no ssh-hardening or cleanup-services
lhm rollback FILE                            # restore newest .bak[.N]

Global: --dry-run  --json  --verbose.  No --yes flag: changed modules need
one confirmation each; non-TTY write runs fail closed unless the operation supports
the environment bypass and it is enabled.
```

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
check or the dry-run guarantee. `ssh-confirm` and `apply cleanup-services` do
not honor it.

## Safety rules

1. Backups: copy to a private sibling temp file and publish atomically as
   `f.bak`, `f.bak.1`, `f.bak.2`… without overwriting existing backups.
   `rollback` uses the newest number and atomically replaces the target.
   The CLI accepts only exact managed system-file paths, not aliases or
   symlinks. Restore `authorized_keys` manually as the account owner.
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
   `/etc/apt/apt.conf.d/51-lhm`. Creating a new drop-in is NOT a "modify existing
   file" op: no .bak needed; overwrite is idempotent (same content => skip).
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
   SSH apply, confirmation, timed recovery and CLI rollback of the managed
   SSH drop-in serialize against the same SSH mutation lock. Confirmation and
   recovery recheck the current transaction under lock so a stale ID or a race
   at expiry cannot act on a newer or already resolved transaction. While a
   transaction is pending, refuse a new SSH hardening apply and manual rollback
   of the managed drop-in. The lock does not coordinate out-of-band changes:
   operators must not run `apply firewall` or `apply sandbox` concurrently.
   The `sshd -T` gate also covers `AllowUsers`: a non-empty effective value must
   contain every admin user that has an authorized key, otherwise reloading would
   lock them out (an empty value means everyone may log in).

   For a changed live `apply ssh-hardening`, obtain one confirmation first, then
   arm and verify a 10-minute systemd timer before changing SSH and print the
   transaction ID. Timer setup failure or unknown timer state fails closed.
   The timer is independent of the CLI and starts recovery if the transaction
   is still unconfirmed at expiry, even after the CLI is killed. Its scope is
   the current boot only. PID 1 schedules transient
   `lhm-ssh-rollback-<id>.timer` and `lhm-ssh-rollback-<id>.service` units.
   LHM verifies their state and reads the monotonic deadline from systemd via
   `/run/dbus/system_bus_socket`. The volatile transaction journal is
   `/run/lhm-ssh-rollback/pending.json` (root-only, `0700` directory and `0600`
   file).

   The worker invokes `/opt/lhm-ssh-rollback/python/bin/python3.15` with
   `-I -S -B`. It requires standalone CPython 3.15 with its own prefix-local
   stdlib and Python search paths, then adds `/opt/lhm-ssh-rollback/src` to
   import the same release's `lhm` package. Both trees and their ancestors
   must be root-owned, not group- or world-writable, and symlink-free. The
   dedicated root-controlled deployment keeps the worker independent of
   the caller's checkout, project venv, and uv runtime. Path checks protect
   the installed copy, not its provenance: provision only from trusted artifacts
   (see [README](README.md#provision-the-ssh-watchdog)).

   Keep the old SSH session open and have local or out-of-band console access.
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
   be probed AND no `--allow` was given, FAIL closed before running any `ufw`
   command (default deny would lock the host out); `--allow PORT/PROTO` is the
    explicit escape hatch when no listener is detected and socket state is
    known. An unknown SSH socket state or incomplete live socket evidence
    blocks UFW changes even with `--allow`. Only `ALLOW`/`ALLOW IN` rules satisfy the inbound
   check: `ALLOW FWD` is a forward rule and must not read as "port allowed".
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
   its prior drop-in and listener; sandbox rolls its drop-in back; **firewall never
   disables a firewall that was already active** (no automatic `ufw disable`, the
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
   external changes or triggering a restart loop. If recovery fails or cannot
   be verified, inspect the journal for
   `lhm-ssh-rollback-<id>.service` and recover from the local console; do not
   delete `pending.json` to clear a refusal.
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

## Modules (apply order = table order)

| # | module | summary |
|---|--------|---------|
| 1 | updates | apt update && upgrade (security-only option); install unattended-upgrades; template to apt.conf.d (security-only autoinstall) |
| 2 | ssh | useradd + sudo group; authorized_keys; sshd drop-in incl Port 22345; sshd -t gate |
| 3 | firewall | ufw allow 22345/tcp first, default deny incoming / allow outgoing, enable |
| 4 | fail2ban | apt install fail2ban + nftables (nftables is only a Recommends of fail2ban; without it bans silently fail); `jail.d/99-lhm.local` drop-in (sshd jail port 22345, backend systemd, mode aggressive, maxretry 3, findtime 30m, bantime 8h with bantime.increment/factor 3/maxtime 4w/rndtime 30m); optional caddy jail (`--caddy`) with the lhm-provided `filter.d/caddy-lhm.conf`; `/etc/fail2ban/jail.local` is never written (it holds the host's own jails and the drop-in wins by load order); cleanup-services: ss -tulpn + enabled units, per-item interactive selection |
| 5 | sysctl+sandbox | sysctl.d template (rp_filter, no icmp redirects accept, kptr_restrict=2, dmesg_restrict, unprivileged_bpf_disabled); sandbox drop-ins for fixed whitelist only (sshd, nginx, fail2ban) with per-service exceptions |
| 6 | audit/log/alert/backup | auditd + rules.d template + augenrules; journald persistent + logrotate template; alert = systemd timer + script scanning journalctl -p err / fail2ban bans since last run, webhook via urllib, state file; backup = timer + tar template (/etc /home), sha256 manifest, keep N rotate, local dir target |

fail2ban load order is `jail.conf` → `jail.d/*.conf` → `jail.local` →
`jail.d/*.local`, so the lhm drop-in overrides a hand-maintained `jail.local`
without touching it. `bantime.increment` needs the dbfile (Debian/Ubuntu default
`/var/lib/fail2ban/fail2ban.sqlite3`, enabled by packaging); the increment
formula is `bantime * (1 << banCount) * bantime.factor` up to `bantime.maxtime`,
so bantime 8h / factor 3 gives 8h, 48h, 4d, 8d, 16d, then 4w. fail2ban ships no
Caddy filter and 1.x has no JSON parsing, so `caddy-lhm` matches the raw JSON
access log by regex (status 401/403/404/429, two patterns because JSON field
order is not guaranteed) and needs Caddy's access log in journald (Caddy's
default `log` output). The caddy jail is off by default: an enabled jail whose
`caddy.service` is missing stops fail2ban from starting. Activation is
`fail2ban-client reload --restart` when the daemon is already active (jails are
restarted in place, the server and its bans stay up) and `enable --now` when it
is not: a plain `systemctl reload` never re-runs the action's `actionstart`, and
when `banaction` resolves to a new action name fail2ban 1.0.2's reload deletes
both the old and the new action, leaving the jail with no action at all — bans
then only reach the DB and the nftables table is never created.

## Templates

`templates/*.tmpl` rendered via string.Template: fail2ban `99-lhm.local` +
`caddy-filter.conf`, 99-lhm-sysctl.conf, sshd hardening, audit rules,
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
lhm/src/lhm/modules/*.py      # updates, ssh, firewall, fail2ban, services, sysctl, sandbox, logging, audit, alert, backup
lhm/templates/*
lhm/pyproject.toml            # uv, console script lhm, dev group pytest
lhm/tests/*                   # host-management commands use a fake runner
```

## Acceptance

- `pytest` green; tests never invoke real system tools (Runner faked).
- `--dry-run` performs zero writes (tested).
- Non-TTY apply fails closed (tested).
- `LHM_CONFIRM_BYPASS=1` skips only the single prompt where supported; it
  never skips the `ssh-confirm` prompt.
- Backup naming/rotation tested; marked-block append idempotency tested.
- sshd drop-in content validated against `sshd -T` semantics in unit tests.
- `lhm/integration/run.sh` runs the scenarios against real Ubuntu containers
  (`6_audit` degrades to SKIPPED where the kernel refuses audit netlink).
- Real 10-minute timer expiry and SSH recovery are manual checks in a
  disposable systemd VM with console access.
