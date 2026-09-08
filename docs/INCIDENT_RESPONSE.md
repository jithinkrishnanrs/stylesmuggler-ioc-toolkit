# Incident response playbook

Use this if `scripts/stylesmuggler_scan.sh` (or the Python equivalent) reports a hit, or
if you find any of the indicators in [`../iocs/`](../iocs/) by hand.

## First: don't destroy evidence

- **Do not reboot the host.** Some of what you need (the running process, its memory,
  its `/proc/<pid>/exe` link) doesn't survive a reboot.
- **Do not run `composer install` or redeploy over the top before evidence capture.**
  Both can overwrite artifacts you'll want later, and composer reinstall has been
  observed to destroy useful forensic state.
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

# Open sockets for this process
ss -tnp 2>/dev/null | grep "pid=$PID" > /root/evidence/proc_${PID}_sockets.txt
```

Also preserve:

- The on-disk implant, if present, across **any** of the three known builds:
  `~/.local/share/.gvfsd/gvfsd-user` and its `.lock` files, `/tmp/.kw_*`, `/tmp/.gvfsd_*`;
  `~/.cache/fontconfig/fc-cache` and `/tmp/.fc_*.lock`; `/tmp/.chrony-*/chronyd`.
- The full crontab / cron spool for the affected user:
  `cat /var/spool/cron/crontabs/<user>`. Check for both the every-5-minute pattern and
  the `fc-cache` build's twice-hourly `13,43 * * * *` pattern.
- Any dropped PHP webshells under `pub/media/`, `pub/static/`, or theme directories —
  multiple incident write-ups report these as a secondary persistence mechanism
  alongside the named implant.
- The `admin_user` database table, for an unexpected/rogue admin account.
- The poisoned log/report files: `var/log/system.log` and any hit under `var/report/`.
- Web server access logs covering the suspected compromise window, ideally including
  the raw `X-TRACE-*` / `X-*` trigger header and `User-Agent` values.
- If your incident process supports it and the box is important enough: a full memory
  capture before you touch anything further.

Treat all captured evidence as sensitive — it may contain customer PII, payment data, or
session tokens pulled from Redis.

## Step 3 — eradicate, in this order

Order matters. Persistence re-adds itself if you kill the process first.

1. **Remove persistence first:**
   ```bash
   crontab -l -u <user> | grep -v -E 'gvfsd|\.kw_|fc-cache|\.fc_|chronyd|\.chrony-' | crontab -u <user> -
   # Also check the spool file directly — some variants bypass `crontab` entirely
   sudo sed -i '/gvfsd/d;/\.kw_/d;/fc-cache/d;/\.fc_/d;/chronyd/d;/\.chrony-/d' /var/spool/cron/crontabs/<user>
   ```
2. **Then kill the process(es):**
   ```bash
   sudo kill -9 <pid>
   watch -n 0.5 'ps auxf | grep -iE "kworker|fc-cache|chronyd"'   # confirm it does not respawn, ~60s
   ```
3. **Remove the on-disk binary and locks (check all three known builds):**
   ```bash
   rm -rf ~/.local/share/.gvfsd/ ~/.cache/fontconfig/fc-cache
   rm -rf /tmp/.kw_* /tmp/.gvfsd_* /tmp/.fc_*.lock /tmp/.chrony-*
   ```
4. **Check the crontab again** after a full cron cycle (at least 5–10 minutes, ideally
   longer) — confirmed re-appended entries have been observed even after apparent
   removal.
5. **Clean the poisoned log/report files** (`var/log/system.log`, `var/report/<hash>`)
   only *after* you've captured the copies you want for evidence.

## Step 4 — recover trust

Code execution as the site user means **every secret that user could read is exposed —
not "might be," is.** Treat the whole server as compromised, not just the process you
found. Do this only *after* containment (Step 3) — rotating credentials while the
attacker still has active execution just hands them the new ones too.

- **Flush session storage** entirely, whichever backend you use — this logs out every
  customer and admin, which is the point, since the implant has been observed reading
  session data directly:
  ```bash
  redis-cli flushall                         # Redis-backed sessions
  rm -f "$MAGENTO_ROOT"/var/session/sess_*   # file-backed sessions
  # DELETE FROM session;                     # DB-backed sessions
  ```
- **Rotate the Magento `crypt/key`** in `app/etc/env.php`. This re-encrypts stored
  secrets (including saved payment tokens), so plan the rotation carefully — don't just
  hand-edit the value on a production store; use Magento's key-rotation tooling or a
  tested community tool, and don't remove the old key outright (Magento needs it during
  re-encryption).
- **Rotate every other credential the site user could read**, at minimum: database
  password, every admin account password (and invalidate existing admin sessions),
  payment-provider API keys, other integration credentials in `env.php`, API/OAuth
  tokens, and any SSH or deploy keys reachable by that user.
- **Check the `admin_user` table for a rogue account** and remove it; check for dropped
  PHP webshells under `pub/media/`, `pub/static/`, and theme directories, not just the
  named backdoor process — stores have been re-compromised after cleanup addressed only
  the files and not a leftover rogue admin account or database trigger.
- Prefer **rebuilding the node from a known-good image / clean deploy** and **restoring
  the database from a point you trust** over hand-cleaning a box that's had
  unauthenticated RCE — especially if you found the in-memory-vs-on-disk hash mismatch
  (evidence the operator can update the implant), or any of the secondary persistence
  above.
- Apply the mitigations in [`../mitigations/`](../mitigations/) (or a commercial WAF)
  *before* bringing the node back into service, since there is still no official patch —
  and remember GraphQL-blocking alone does not close the confirmed second delivery
  vector via Magento's customer custom options upload.
- If cardholder data may have been accessible, assess PCI-DSS breach notification
  obligations as part of this step, not as an afterthought.

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

## Step 6 — report and share

- Submit anonymized IOCs (hashes, C2 addresses, request signatures — with your own
  organization's identifying details stripped) to your ISAC or sharing community.
- Report the underlying vulnerability to [Sansec](https://sansec.io/contact) and to
  **Adobe PSIRT**, not just to internal tooling — there is still no CVE, and vendor
  awareness of new variants speeds up an eventual patch.
- If you maintain a fork of this repo, add anything new you learned to `iocs/` with a
  note on how you observed it, dated.
