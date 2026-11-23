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
lhm apply ssh-hardening [--port 22345]
lhm apply firewall [--allow PORT/PROTO]...   # 22345/tcp pre-allowed by default
lhm apply fail2ban [--bantime 8h --findtime 30m --maxretry 3] [--caddy]
lhm apply cleanup-services                   # interactive per-item selection
lhm apply sysctl
lhm apply sandbox [SERVICE]...               # fixed whitelist only
lhm apply audit | logging | alert --webhook URL | backup --target PATH
lhm apply all                                # ordered 1..6, stops on FAIL
lhm rollback FILE                            # restore newest .bak[.N]

Global: --dry-run  --json  --verbose.  No --yes flag: non-idempotent ops need
double confirmation; non-TTY write runs fail closed (dry-run only).
```

## Execution model

Every apply module = list of Steps: `check() -> plan() -> confirm x2 -> backup ->
execute -> verify()`. Idempotent check first: target state already reached => skip,
no confirmation. Otherwise print full plan (file diffs, risks), y/N twice. Abort on
anything but `y`; completed steps kept, print rollback hint.

`LHM_CONFIRM_BYPASS=1` (env, exact value `1`) skips the two y/N prompts for
unattended root runs and the integration suite (`lhm/integration/`). It is not a
CLI flag, is documented as test-only, and never bypasses the idempotency check
or the dry-run guarantee.

## Safety rules

1. Backups: before modifying an existing file `cp -a f f.bak`; if `.bak` exists
   write `.bak.1`, `.bak.2`... never overwrite the oldest original. `rollback`
   uses the newest.
2. Appends to existing files use marked blocks; the marker doubles as the
   idempotency key:
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
   Pubkey validation is strict: `type base64 [comment]` with a decodable key blob
   whose wire type matches (not a prefix check); invalid => refuse to disable
   password auth. Debian 12 socket activation: if `ssh.socket` (or `sshd.socket`)
   is active it owns the listener (Port 22), so the drop-in's Port is ignored while
   `sshd -T` still reports 22345. Disable it (`systemctl disable --now ssh.socket`)
   and restart `ssh|sshd` (reload cannot move a socket unit). Verify the ACTUAL
   listening port with `ss -tlnp`, not only `sshd -T`. If both restarts fail,
   recovery is mandatory: re-enable the socket (`systemctl enable --now
   ssh.socket`), confirm it is active and `ss -tlnp` shows a listener again, then
   roll the drop-in back and FAIL. A socket-activated sshd uses the passed fd and
   ignores Port drop-ins, so the socket restores the previous listener even with
   the new drop-in still present. If re-enabling the socket also fails, roll the
   drop-in back, try `systemctl start ssh`, and FAIL with explicit console
   recovery instructions (never leave the host silently without a listener).
   The `sshd -T` gate also covers `AllowUsers`: a non-empty effective value must
   contain every admin user that has an authorized key, otherwise reloading would
   lock them out (an empty value means everyone may log in).
5. Firewall order: probe the ports sshd listens on NOW (`ss -tlnp`, fallback
   `sshd -T`), allow every current SSH port AND 22345/tcp BEFORE
   `default deny incoming` + `enable`. A server still on port 22 (or `apply all`
   with only ssh-user done) must keep its current port open. When no listener can
   be probed AND no `--allow` was given, FAIL closed before running any `ufw`
   command (default deny would lock the host out); `--allow PORT/PROTO` is the
   explicit escape hatch. Only `ALLOW`/`ALLOW IN` rules satisfy the inbound
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
   (restore newest `.bak`, else delete) and the step FAILs; ssh's
   ProtectHome=read-only keeps `/home/*/.ssh/authorized_keys` readable.
7. Secrets: the alert script embeds the webhook URL, so it is installed 0700
   root:root and its `.bak` keeps 0700; unit files never contain the URL. Shell
   template values are single-quoted, so values with `'` or control characters are
   refused, not escaped. Error messages and plans only echo the webhook's scheme +
   host, never its path/query; `--verbose` prints "(content hidden: contains a
   secret)" instead of the script (the `.bak` content and the diff are suppressed
   too). The URL is never passed as argv: alerts only call `systemctl`.
   Backup target: 0700 dir, `umask 077` (archives 0600), refuse `/`, `/home...`,
   `/etc...` (tar would ingest the growing archive) — checked after resolving
   `//etc` and symlinked parents — and refuse any character outside
   `[A-Za-z0-9/_.-]` (a space would split systemd's `ReadWritePaths=`, `%` is a
   specifier); a tar failure removes the partial archive and exits 1 instead of
   passing verify.
8. Audit immutability is observed, not assumed: an `augenrules --load` failure on
   an identical rules file is a warning only when `auditctl -s` reports `enabled 2`,
   otherwise FAIL. `lhm rollback` is a non-idempotent write: root + TTY +
   double-confirm, and it backs up the current file first (a rollback can itself
   be rolled back).

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
lhm/src/lhm/core/confirm.py   # double-confirm, TTY gate
lhm/src/lhm/core/backup.py    # .bak policy, rollback
lhm/src/lhm/core/files.py     # marked-block append, drop-in write, template render
lhm/src/lhm/core/distro.py    # DistroBackend (apt impl)
lhm/src/lhm/core/checks.py    # state probes (idempotency)
lhm/src/lhm/core/report.py    # plan/verify tables, --json
lhm/src/lhm/modules/*.py      # updates, ssh, firewall, fail2ban, services, sysctl, sandbox, logging, audit, alert, backup
lhm/templates/*
lhm/pyproject.toml            # uv, console script lhm, dev group pytest
lhm/tests/*                   # fake runner, no real system calls
```

## Acceptance

- `pytest` green; tests never invoke real system tools (Runner faked).
- `--dry-run` performs zero writes (tested).
- Non-TTY apply fails closed (tested).
- `LHM_CONFIRM_BYPASS=1` skips only the two prompts (tested).
- Backup naming/rotation tested; marked-block append idempotency tested.
- sshd drop-in content validated against `sshd -T` semantics in unit tests.
- `lhm/integration/run.sh` runs the scenarios against real Ubuntu containers
  (`6_audit` degrades to SKIPPED where the kernel refuses audit netlink).
