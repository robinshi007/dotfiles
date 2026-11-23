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
lhm query system|ssh|firewall|services|ports|sysctl|audit|updates [--json]
lhm check                                    # idempotency audit: OK / needs-change
lhm apply updates [--security-only]
lhm apply ssh-user NAME --key FILE [--sudo]
lhm apply ssh-hardening [--port 22345]
lhm apply firewall [--allow PORT/PROTO]...   # 22345/tcp pre-allowed by default
lhm apply fail2ban [--bantime 1h --maxretry 5]
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
   `/etc/audit/rules.d/99-lhm.rules`, `/etc/fail2ban/jail.local`,
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
   listening port with `ss -tlnp`, not only `sshd -T`.
5. Firewall order: probe the ports sshd listens on NOW (`ss -tlnp`, fallback
   `sshd -T`), allow every current SSH port AND 22345/tcp BEFORE
   `default deny incoming` + `enable`. A server still on port 22 (or `apply all`
   with only ssh-user done) must keep its current port open.
6. Verify after every module (sshd -T grep, ss -tlnp listening port, ufw status
   verbose, sysctl spot checks, systemd-analyze security, augenrules --check,
   fail2ban-client status). Any FAIL => non-zero exit + rollback hint.
   A sandbox drop-in whose `systemctl restart` fails is rolled back automatically
   (restore newest `.bak`, else delete) and the step FAILs; ssh's
   ProtectHome=read-only keeps `/home/*/.ssh/authorized_keys` readable.
7. Secrets: the alert script embeds the webhook URL, so it is installed 0700
   root:root and its `.bak` keeps 0700; unit files never contain the URL. Shell
   template values are single-quoted, so values with `'` or control characters are
   refused, not escaped. Backup target: 0700 dir, `umask 077` (archives 0600),
   refuse `/`, `/home...`, `/etc...` (tar would ingest the growing archive); a tar
   failure removes the partial archive and exits 1 instead of passing verify.
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
| 4 | fail2ban | apt install fail2ban + nftables (nftables is only a Recommends of fail2ban; without it bans silently fail); jail.local template (sshd jail port 22345, backend systemd); cleanup-services: ss -tulpn + enabled units, per-item interactive selection |
| 5 | sysctl+sandbox | sysctl.d template (rp_filter, no icmp redirects accept, kptr_restrict=2, dmesg_restrict, unprivileged_bpf_disabled); sandbox drop-ins for fixed whitelist only (sshd, nginx, fail2ban) with per-service exceptions |
| 6 | audit/log/alert/backup | auditd + rules.d template + augenrules; journald persistent + logrotate template; alert = systemd timer + script scanning journalctl -p err / fail2ban bans since last run, webhook via urllib, state file; backup = timer + tar template (/etc /home), sha256 manifest, keep N rotate, local dir target |

## Templates

`templates/*.tmpl` rendered via string.Template. jail.local, 99-lhm-sysctl.conf,
audit rules, unattended-upgrades conf, alert/backup timer+service+script.

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
