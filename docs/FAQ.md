# StyleSmuggler FAQ

Quick answers, sourced from Sansec and corroborating incident-response reporting. See
[`VULNERABILITY.md`](VULNERABILITY.md) for the full technical writeup and citations.

### What is StyleSmuggler?

StyleSmuggler is the name Sansec gave to an unauthenticated remote code execution (RCE)
vulnerability in Magento Open Source and Adobe Commerce, disclosed September 5, 2026,
with exploitation confirmed from September 4. An attacker with no account and no
credentials can get PHP running on the store's server. The name refers to the `styles`
property the attack abuses to smuggle attacker-controlled content past Magento's
template-handling safeguards.

### Is StyleSmuggler being actively exploited?

Yes. Sansec confirmed attack traffic starting September 4, 2026 — about a day before
public disclosure — and exploitation has continued since, including a second,
independent delivery vector confirmed September 5-6 and new backdoor variants observed
September 6 and 7.

### Is there a CVE for StyleSmuggler?

**No, not yet.** As of this writing, Adobe has assigned no CVE identifier and published
no security bulletin covering this issue. Adobe Enterprise Support confirmed on
September 7, 2026 that a fix is in progress, with no release date given.

### My store is fully patched / up to date. Am I safe?

**No.** The first confirmed victim was running Magento 2.4.6-p15 with the July and
August 2026 security patches applied and a clean `security:patch-status` result. Sansec
also reproduced the full attack chain on clean installs of 2.4.7, 2.4.8, and 2.4.9 — the
then-current release line. Being up to date does not protect against a flaw with no fix
yet.

### Do I need to be logged in, or have a session, for my store to be at risk?

No. StyleSmuggler is **unauthenticated** — attackers need no credentials, no session,
and no user interaction from a victim to exploit it.

### Which Magento / Adobe Commerce versions are affected?

Sansec reproduced the full chain on Magento Open Source 2.4.7, 2.4.8, and 2.4.9, and
confirmed a real-world victim on 2.4.6-p15. Treat every currently supported Magento Open
Source and Adobe Commerce install — including Adobe Commerce Cloud — as potentially
affected until Adobe says otherwise.

### I moved my session storage off Redis. Am I protected?

**No.** A confirmed second exploitation vector uses a file uploaded through Magento's
customer custom options feature rather than session storage at all — one merchant saw an
attempt fail against database-backed sessions, then succeed eight seconds later via this
second path, from the same operator. Session-storage changes address only one symptom,
not the underlying issue.

### How do I check if I'm compromised?

Run [`../scripts/stylesmuggler_scan.sh`](../scripts/stylesmuggler_scan.sh) or
[`../scripts/stylesmuggler_scan.py`](../scripts/stylesmuggler_scan.py) against your
store. At minimum, manually check:

```bash
crontab -l | grep -iE 'gvfsd|\.kw_|fc-cache|chronyd'
ps -eo pid,user,comm,args | grep -iE 'kworker|fc-cache|chronyd'
grep -ril 'x_trace_' var/report/ var/log/system.log
```

See [`../iocs/`](../iocs/) for the full, current indicator list.

### What does the backdoor look like once it's installed?

A small (~1.9 MB), stripped, statically compiled Rust binary that disguises itself as an
ordinary-looking system process — first `[kworker/u:8:0]` (a kernel worker thread name),
later `fc-cache` (the fontconfig cache utility) and `chronyd` (the NTP daemon). It
persists via cron, written directly to the cron spool file to avoid normal audit
logging. See [`VULNERABILITY.md`](VULNERABILITY.md) for the full comparison table.

### Why didn't my antivirus / VirusTotal catch this?

At the time of disclosure, no security vendor besides Sansec recognized the implant on
VirusTotal. The binary is new, statically compiled, carries no symbols, and its hash
varies build-to-build — the in-memory copy has even been observed differing from the
copy on disk. Checksum-only detection is weak against this implant; behavioral
indicators (process ownership, cron pattern, network shape) are more reliable.

### Why don't I see any suspicious network traffic?

At least one confirmed infection made **zero outbound connections** and instead read
Magento's session data directly out of the store's own local Redis instance — no egress
to alert on. A newer backdoor variant beacons out disguised as ordinary NTP traffic on
UDP port 123, a port most firewalls and egress monitoring treat as harmless. A clean
network capture does not mean a clean host.

### What should I do right now if I don't use a WAF?

Sansec recommends temporarily disabling Magento GraphQL entirely if your storefront and
integrations don't need it. See [`../mitigations/`](../mitigations/) for nginx, Apache,
ModSecurity, and fail2ban configs. This blocks one confirmed delivery path, not
necessarily the customer-custom-options vector — run the compromise scanner regardless.

### What do I do if the scanner finds something?

Don't just delete the process and move on. See
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full, ordered playbook: preserve
evidence, remove persistence before killing the process, then flush sessions, rotate the
Magento encryption key and every credential in `app/etc/env.php`, and check for rogue
admin accounts and dropped webshells before considering the store clean.

### Where can I get the authoritative, up-to-date information?

[sansec.io/research/stylesmuggler-0day](https://sansec.io/research/stylesmuggler-0day)
is the primary, continuously updated source. This repo is a community-built companion
toolkit, not a replacement for it.
