# Incident response playbook

Use this if `scripts/stylesmuggler_scan.sh` (or the Python equivalent) reports a hit, or
if you find any of the indicators in [`../iocs/`](../iocs/) by hand.

**Note on patching:** Adobe's official hotfix (VULN-39341 / APSB26-146, CVE-2026-75650)
now exists, and must be applied **alongside** Adobe's separate regular September 2026
update (APSB26-138) — see [`PATCHING.md`](PATCHING.md). Patching stops *new*
exploitation; it does not undo an existing compromise. If you suspect you were already
hit, work through this playbook's evidence-preservation steps before applying the
hotfix on that specific host, so you don't destroy what you'd want to investigate. If
you have no evidence of prior compromise, patch first, then still run the scanner to be
sure.

## First: don't destroy evidence

- **Do not reboot the host.** Some of what you need (the running process, its memory,
  its `/proc/<pid>/exe` link) doesn't survive a reboot.
- **Do not run `composer install` or redeploy over the top before evidence capture.**
  Both can overwrite artifacts you'll want later, and composer reinstall has been
  observed to destroy useful forensic state. This includes applying the official
  hotfix — capture evidence first if you suspect prior compromise.
- **Do not just `kill -9` the process first.** Confirmed persistence re-adds itself
  within a second on at least one host. If you kill it before removing persistence, it
  comes right back and you've lost your chance to observe it cleanly.

## Step 1 — contain

- Isolate the node: restrict outbound traffic, or take it out of the load balancer pool
  while keeping it powered on and reachable for investigation.
- If this is shared hosting, check **every account**, not just the one you suspect — the
  persistence path is under a site user's home directory, not root's.

## Step 2 — capture evidence

For each suspicious `[kworker/...]`, `fc-cache`, or `chronyd`-named process not owned by
root (or that doesn't match the real system binary at the equivalent path):

```bash
# Preserve the in-memory binary — it may differ from the on-disk file
PID=<suspicious pid>
cp /proc/$PID/exe /root/evidence/proc_${PID}_exe.bin
sha256sum /root/evidence/proc_${PID}_exe.bin

# Process metadata
ps -o pid,ppid,user,lstart,cmd -p $PID > /root/evidence/proc_${PID}_meta.txt
ls -la /proc/$PID/cwd /proc/$PID/exe 2>/dev/null >> /root/evidence/proc_${PID}_meta.txt
cat /proc/$PID/status >> /root/evidence/proc_${PID}_meta.txt

# Open sockets for this process — check UDP as well as TCP; the fc-cache/chronyd
# build's C2 rides on UDP/123 disguised as NTP traffic
ss -tnp 2>/dev/null | grep "pid=$PID" > /root/evidence/proc_${PID}_sockets.txt
ss -unp 2>/dev/null | grep "pid=$PID" >> /root/evidence/proc_${PID}_sockets.txt
lsof -nP -p "$PID" > /root/evidence/proc_${PID}_lsof.txt 2>/dev/null
```

**Don't trust a process name alone — including `fc-cache` or `chronyd` matching the
legitimate system utility.** Real kernel workers run as root with PPID 2; real
`fc-cache`/`chronyd` run from `/usr/bin/fc-cache` or `/usr/sbin/chronyd`. Confirm the
actual executable before deciding a match is benign:

```bash
readlink -f /proc/$PID/exe
```

**One confirmed infection showed no external C2 connection at all** — the suspicious
process instead had several established connections to the store's own Redis instance.
If a suspicious PID's socket list shows a local port you don't recognize, identify what
it belongs to before assuming it's benign:

```bash
lsof -nP -iTCP:<PORT>          # what's listening/connected on that port
ss -ltnp | grep ':<PORT>'      # alternative if lsof isn't available
```

If you suspect NTP-shaped C2 traffic on UDP/123 and want to confirm rather than infer,
a short capture can help (adjust interface/timeout, and be mindful this captures live
traffic — treat the capture file as sensitive evidence, same as anything else here):

```bash
sudo timeout 70 tcpdump -ni any -nn 'udp port 123'
```

Legitimate NTP traffic also uses UDP/123 — the process, destination, and pattern all
matter together; don't whitelist a connection solely because the process is named
`chronyd`.

Also preserve:

- The on-disk implant, if present, across **any** of the three known builds:
  `~/.local/share/.gvfsd/gvfsd-user` and its `.lock` files, `/tmp/.kw_*`, `/tmp/.gvfsd_*`;
  `~/.cache/fontconfig/fc-cache` and `/tmp/.fc_*.lock`; `/tmp/.chrony-*/chronyd`.
- The full crontab / cron spool for the affected user:
  `cat /var/spool/cron/crontabs/<user>`. Check for both the every-5-minute pattern and
  the `fc-cache` build's twice-hourly `13,43 * * * *` pattern.
- Any dropped PHP webshells under `pub/media/`, `pub/static/`, or theme directories —
  multiple incident write-ups report these as a secondary persistence mechanism
  alongside the named implant. This specifically includes the **second, unrelated
  attacker's** web shell pattern:
  ```bash
  find pub/media -name '*.php'
  # The specific known path pattern from the second attacker:
  find pub/media/catalog/product/cache -type d -name 'ss_*' 2>/dev/null
  ```
  `pub/media` should never contain executable PHP on a correctly configured Magento
  store — any hit here is significant regardless of whether you've also found the Rust
  implant.
- The `admin_user` database table, for an unexpected/rogue admin account.
- Your Redis configuration and connections, if you use Redis for cache/page-cache/
  sessions:
  ```bash
  grep -nA40 "'cache'" app/etc/env.php
  grep -nA30 "'session'" app/etc/env.php
  # Note the host, port/socket, and database index for cache, page-cache, and session
  # from the output above, then inspect actual connections:
  ss -tpn | grep ':6379'
  ```
- The poisoned log/report files: `var/log/system.log` and any hit under `var/report/`.
- Web server access logs covering the suspected compromise window, ideally including
  the raw `X-TRACE-*` / `X-*` trigger header, the `Store:` header (the second
  attacker's delivery mechanism), and `User-Agent` values. A broader sweep for the
  delivery attempt itself:
  ```bash
  grep -acE 'styles(\[|%5B)|generatorClass|with_resolved|cdnflare' /path/to/access.log
  ```
- If your incident process supports it and the box is important enough: a full memory
  capture before you touch anything further.

Treat all captured evidence as sensitive — it may contain customer PII, payment data, or
session tokens pulled from Redis.

## Step 3 — eradicate, in this order

Order matters. Persistence re-adds itself if you kill the process first.

1. **Remove persistence first:**
   ```bash
   crontab -l -u <user> | grep -v -E 'gvfsd|\.kw_|fc-cache|\.fc_|\.fc-|chronyd|\.chrony-|\.cache_|\.gvfsd-' | crontab -u <user> -
   # Also check the spool file directly — some variants bypass `crontab` entirely
   sudo sed -i '/gvfsd/d;/\.kw_/d;/fc-cache/d;/\.fc_/d;/\.fc-/d;/chronyd/d;/\.chrony-/d' /var/spool/cron/crontabs/<user>
   sudo grep -RniE 'gvfsd|fc-cache|chronyd|\.chrony-|\.cache/fontconfig' /var/spool/cron* /etc/cron* 2>/dev/null
   ```
   **The `chronyd` build has been observed relaunching with no cron entry at all** — an
   empty crontab is not proof this step is done. Also check other persistence
   mechanisms before moving on:
   ```bash
   # User-level systemd timers/services
   systemctl --user list-timers --all 2>/dev/null
   ls -la ~/.config/systemd/user/ 2>/dev/null
   # System cron directories beyond the user's own crontab
   ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
   # PHP-level auto-execution hooks
   grep -rn 'auto_prepend_file\|auto_append_file' .user.ini .htaccess /etc/php*/ 2>/dev/null
   # Unexplained SSH keys or shell-startup additions
   cat ~/.ssh/authorized_keys 2>/dev/null
   grep -nE 'curl|wget|base64|/tmp/\.|gvfsd|kworker|fc-cache|chronyd|\.chrony-' \
     ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.bash_login 2>/dev/null
   ```
2. **Then kill the process(es):**
   ```bash
   sudo kill -9 <pid>
   watch -n 0.5 'ps auxf | grep -iE "kworker|fc-cache|chronyd"'   # confirm it does not respawn, ~60s
   ```
3. **Remove the on-disk binary and locks (check all three known builds and their
   filename variants):**
   ```bash
   rm -rf ~/.local/share/.gvfsd/ ~/.cache/fontconfig/fc-cache
   rm -rf /tmp/.kw_* /tmp/.cache_* /tmp/.gvfsd_* /tmp/.gvfsd-* \
          /tmp/.fc_*.lock /tmp/.fc-*/fc-cache /tmp/fc-cache /tmp/.chrony-*
   ```
4. **Check the crontab again** after a full cron cycle (at least 5–10 minutes, ideally
   longer) — confirmed re-appended entries have been observed even after apparent
   removal.
5. **Remove the second, unrelated attacker's web shell**, if present — this is
   independent of the Rust implant and needs its own cleanup:
   ```bash
   find pub/media -name '*.php' -print
   # Review each hit before deleting — capture a copy for evidence first (Step 2).
   # The specific known pattern:
   find pub/media/catalog/product/cache -path '*/ss_*/sync_*.php' -delete
   # Attackers change filenames — don't restrict future checks to this exact pattern,
   # and also sweep for recently modified PHP anywhere in the codebase:
   find app vendor pub -type f -name '*.php' -newermt '30 days ago' 2>/dev/null
   ```
6. **Clean the poisoned log/report files** (`var/log/system.log`, `var/report/<hash>`)
   only *after* you've captured the copies you want for evidence.
7. **Check the Magento database for persistence or tampering** that the exploited site
   user could have written directly:
   ```sql
   SELECT user_id, username, email, created, logdate, is_active
     FROM admin_user ORDER BY created DESC;                      -- rogue admin accounts
   SELECT integration_id, name, created_at, status FROM integration;
   SELECT * FROM oauth_token ORDER BY created_at DESC LIMIT 20;
   SELECT config_id, scope, scope_id, path, LEFT(value,300) FROM core_config_data
     WHERE value LIKE '%<script%' OR value LIKE '%eval(%'
        OR value LIKE '%atob(%'   OR value LIKE '%fromCharCode%'; -- injected JS
   SELECT identifier, update_time FROM cms_block
     WHERE update_time > NOW() - INTERVAL 30 DAY ORDER BY update_time DESC;
   SELECT identifier, update_time FROM cms_page
     WHERE update_time > NOW() - INTERVAL 30 DAY ORDER BY update_time DESC;
   ```
   None of these queries are StyleSmuggler-specific signatures — they're standard places
   to look for persistence or injected storefront content after any confirmed
   compromise of the Magento application user.

## Step 4 — recover trust

Code execution as the site user means **every secret that user could read is exposed —
not "might be," is.** Treat the whole server as compromised, not just the process you
found. Do this only *after* containment (Step 3) — rotating credentials while the
attacker still has active execution just hands them the new ones too.

- **Flush session storage** entirely, whichever backend you use — this logs out every
  customer and admin, which is the point, since the implant has been observed reading
  session data directly. Identify the exact Redis database first rather than reaching
  for a blanket flush — `FLUSHALL` on a shared Redis instance takes down every other
  application using it too:
  ```bash
  grep -nA40 "'cache'" app/etc/env.php
  grep -nA30 "'session'" app/etc/env.php
  # Note the host, port/socket, and database index for cache, page-cache, and session
  # from the output above, then target that specific database:
  redis-cli -h <HOST> -p <PORT> -n <SESSION_DB> FLUSHDB   # Redis-backed sessions — scoped, not FLUSHALL
  rm -f "$MAGENTO_ROOT"/var/session/sess_*                 # file-backed sessions
  # DELETE FROM session;                                   # DB-backed sessions
  ```
- **Rotate the Magento `crypt/key`** in `app/etc/env.php`. This re-encrypts stored
  secrets (including saved payment tokens), so plan the rotation carefully — don't just
  hand-edit the value on a production store; use Magento's key-rotation tooling or a
  tested community tool, and don't remove the old key outright (Magento needs it during
  re-encryption).
- **Rotate every other credential the site user could read**, at minimum: database
  password, every admin account password (and invalidate existing admin sessions),
  GraphQL integration tokens, OAuth client secrets, payment gateway API credentials,
  other integration credentials in `env.php`, and any SSH or deploy keys reachable by
  that user. This is Adobe's own stated list in its post-hotfix guidance — treat it as
  a minimum, not a ceiling, for what to rotate.
- **Check the `admin_user` table for a rogue account** and remove it; check for dropped
  PHP webshells under `pub/media/`, `pub/static/`, and theme directories — including the
  second, unrelated attacker's specific pattern
  (`pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php`) — not just the
  named backdoor process — stores have been re-compromised after cleanup addressed only
  the files and not a leftover rogue admin account or database trigger.
- Prefer **rebuilding the node from a known-good image / clean deploy** and **restoring
  the database from a point you trust** over hand-cleaning a box that's had
  unauthenticated RCE — especially if you found the in-memory-vs-on-disk hash mismatch
  (evidence the operator can update the implant), or any of the secondary persistence
  above.
- **Apply Adobe's official hotfix (VULN-39341 / APSB26-146, CVE-2026-75650)** — see
  [`PATCHING.md`](PATCHING.md) — *before* bringing the node back into service. If your
  version isn't covered by Adobe's fix, apply the mitigations in
  [`../mitigations/`](../mitigations/) (or a commercial WAF) as a stopgap instead, and
  plan an upgrade. Either way, remember GraphQL-blocking alone does not close the
  confirmed second delivery vector via Magento's customer custom options upload, nor
  the unrelated second attacker's `Store:`-header-based delivery — the official patch
  is the only thing that closes the underlying sink itself.
- If cardholder data may have been accessible, assess PCI-DSS breach notification
  obligations as part of this step, not as an afterthought.
- If your project is stored in Git, use it to spot unauthorized changes before you
  decide the codebase itself is clean:
  ```bash
  git status --short
  git diff --stat
  git ls-files --others --exclude-standard | grep -E '\.(php|phtml)$'   # untracked PHP/PHTML
  ```
  Pay particular attention to anything unexpected under `app/code`, `vendor`, `pub`, and
  `setup`. Don't assume reinstalling `vendor/` alone solves the problem — the implant
  runs as the Unix site user and isn't limited to Magento's own PHP code.

## Step 5 — harden against recurrence

- Configure Redis with `requirepass` and, if you're on Redis 6+, ACLs — scope the site
  user's process to the session database only rather than full access.
- Run the application with a read-only filesystem for the app root, with explicit
  writable volume mounts only where Magento needs them (`var/`, `pub/static/`, etc.) —
  this specifically blocks the observed persistence path into the site user's home
  directory.
- Consider host-level process/behavior monitoring (auditd, an EDR agent) that would
  catch a `[kworker]`-named process owned by a non-root, non-kernel UID — this is exactly
  the kind of masquerade that filename-only checks miss.
- **If you have EDR, auditd, or process-lineage logging that predates today**, run a
  retrospective hunt across the full exploitation window (2026-09-04 onward): any
  PHP-FPM or web server worker process spawning an unexpected shell, `curl`, or other
  unrecognized binary as a child process. Magento's PHP processes have no legitimate
  reason to do this — a hit here catches variants this playbook doesn't yet name.

## Step 6 — report and share

- Submit anonymized IOCs (hashes, C2 addresses, request signatures — with your own
  organization's identifying details stripped) to your ISAC or sharing community.
- Report the underlying vulnerability to [Sansec](https://sansec.io/contact) and to
  **Adobe PSIRT**, not just to internal tooling — this is now tracked as
  **CVE-2026-75650** with an official patch (see [`PATCHING.md`](PATCHING.md)), but
  vendor awareness of new variants (implant disguises, delivery vectors, or the second
  attacker's tooling) still speeds up further guidance.
- If you maintain a fork of this repo, add anything new you learned to `iocs/` with a
  note on how you observed it, dated.
