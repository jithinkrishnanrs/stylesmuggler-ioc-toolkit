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

For each suspicious `[kworker/...]`-style process not owned by root:

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

- The on-disk implant, if present: `~/.local/share/.gvfsd/gvfsd-user` and its `.lock`
  files, and anything under `/tmp/.kw_*` / `/tmp/.gvfsd_*`.
- The full crontab / cron spool for the affected user:
  `cat /var/spool/cron/crontabs/<user>`.
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
   crontab -l -u <user> | grep -v -E 'gvfsd|\.kw_' | crontab -u <user> -
   # Also check the spool file directly — some variants bypass `crontab` entirely
   sudo sed -i '/gvfsd/d;/\.kw_/d' /var/spool/cron/crontabs/<user>
   ```
2. **Then kill the process:**
   ```bash
   sudo kill -9 <pid>
   watch -n 0.5 'ps auxf | grep -i kworker'   # confirm it does not respawn, ~60s
   ```
3. **Remove the on-disk binary and locks:**
   ```bash
   rm -rf ~/.local/share/.gvfsd/
   rm -f /tmp/.kw_* /tmp/.gvfsd_*
   ```
4. **Check the crontab again** after a full cron cycle (at least 5–10 minutes, ideally
   longer) — confirmed re-appended entries have been observed even after apparent
   removal.
5. **Clean the poisoned log/report files** (`var/log/system.log`, `var/report/<hash>`)
   only *after* you've captured the copies you want for evidence.

## Step 4 — recover trust

- **Rotate every Magento admin and API credential**, even if you see no direct evidence
  the backdoor was used for anything beyond sitting there. The advisory's own guidance is
  to rotate regardless.
- If Redis was reachable from the implant, **rotate active customer sessions** and treat
  session data as exposed; consider forcing re-authentication.
- Prefer **rebuilding the node from a known-good image / clean deploy** over trying to
  hand-clean a box that's had unauthenticated RCE, especially if you found the
  in-memory-vs-on-disk hash mismatch (evidence the operator can update the implant).
- Apply the mitigations in [`../mitigations/`](../mitigations/) (or a commercial WAF)
  *before* bringing the node back into service, since there is still no official patch.

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
