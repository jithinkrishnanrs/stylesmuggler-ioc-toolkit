# StyleSmuggler / CVE-2026-75650 FAQ

Quick answers, sourced from Sansec, Adobe's bulletin, and corroborating
incident-response reporting. See [`VULNERABILITY.md`](VULNERABILITY.md) for the full
technical writeup and citations, and [`PATCHING.md`](PATCHING.md) for patch specifics.

### What is StyleSmuggler?

StyleSmuggler is the name Sansec gave to an unauthenticated remote code execution (RCE)
vulnerability in Magento Open Source and Adobe Commerce, disclosed September 5, 2026,
with exploitation confirmed from September 4. It's now formally tracked as
**CVE-2026-75650** (Adobe bulletin APSB26-146). An attacker with no account and no
credentials can get PHP running on the store's server. The name refers to the `styles`
property the attack abuses to smuggle attacker-controlled content past Magento's
template-handling safeguards.

### Is there a CVE for StyleSmuggler?

**Yes — CVE-2026-75650**, assigned September 7, 2026, alongside Adobe's Security
Bulletin APSB26-146. It's rated CVSS 10.0 (Critical) and Adobe's own highest urgency
tier, Priority 1.

### Is there an official patch?

**Yes, as of September 7, 2026, 20:20 UTC** — Adobe shipped hotfix VULN-39341 with
APSB26-146. See [`PATCHING.md`](PATCHING.md) for how to get and apply it. **Coverage is
not universal**: Magento Open Source below 2.4.6 and Adobe Commerce below 2.4.4 get no
official fix.

### Is StyleSmuggler being actively exploited?

Yes. Sansec confirmed attack traffic starting September 4, 2026 — about a day before
public disclosure — and Adobe's own bulletin confirms exploitation in the wild.
Exploitation continued through disclosure of the official patch, including a second,
completely unrelated attacker found riding the same flaw on September 7.

### My store is fully patched / up to date (before Sept 7). Am I safe?

**No, not until you apply APSB26-146/VULN-39341 specifically.** The first confirmed
victim was running Magento 2.4.6-p15 with the July and August 2026 security patches
applied and a clean `security:patch-status` result. Sansec also reproduced the full
attack chain on clean installs of 2.4.7, 2.4.8, and 2.4.9 — being up to date on
*previous* patches did not protect against this specific flaw. The September 7 hotfix
is what actually closes it, for the versions Adobe covers.

### Do I need to be logged in, or have a session, for my store to be at risk?

No. StyleSmuggler is **unauthenticated** — attackers need no credentials, no session,
and no user interaction from a victim to exploit it. Adobe's CVSS vector confirms this
(`PR:N`, `UI:N`).

### Which Magento / Adobe Commerce versions are affected, and which get a fix?

Sansec reproduced the full chain on Magento Open Source 2.4.7, 2.4.8, and 2.4.9, and
confirmed a real-world victim on 2.4.6-p15. Adobe's official fix covers Adobe Commerce
2.4.4–2.4.9, Adobe Commerce B2B 1.3.3–1.5.3, and Magento Open Source 2.4.6–2.4.9 only.
**If you're on Magento Open Source 2.4.5 or older, or Adobe Commerce below 2.4.4, there
is no official Adobe fix** — see [`PATCHING.md`](PATCHING.md) for your options.

### I moved my session storage off Redis. Am I protected?

**No.** A confirmed second exploitation vector uses a file uploaded through Magento's
customer custom options feature rather than session storage at all — one merchant saw an
attempt fail against database-backed sessions, then succeed eight seconds later via this
second path, from the same operator. Session-storage changes address only one symptom,
not the underlying issue — only the official patch (or full mitigation of every known
delivery path) does that.

### I heard about a "second attacker" — is that a different vulnerability?

No, same vulnerability, different, unrelated operator. Separately from the Rust-implant
campaign, Sansec found another attacker using the exact same StyleSmuggler entry point
to drop a much simpler PHP web shell into Magento's product-image cache
(`pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php`). This operator sends a
reconnaissance probe first — a harmless-looking GraphQL query used as cover, with the
real payload hidden in the `Store:` request header — and exfiltrates its recon data over
DNS rather than in the HTTP response, so it won't show up in ordinary response-based
monitoring. Practical implication: cleaning up the Rust implant does not mean your store
is clean; check for stray PHP under `pub/media` too (`find pub/media -name '*.php'`).

### How do I check if I'm compromised?

Run [`../scripts/stylesmuggler_scan.sh`](../scripts/stylesmuggler_scan.sh) or
[`../scripts/stylesmuggler_scan.py`](../scripts/stylesmuggler_scan.py) against your
store. At minimum, manually check:

```bash
crontab -l | grep -iE 'gvfsd|\.kw_|fc-cache|chronyd'
ps -eo pid,user,comm,args | grep -iE 'kworker|fc-cache|chronyd'
grep -ril 'x_trace_' var/report/ var/log/system.log
find pub/media -name '*.php'
```

See [`../iocs/`](../iocs/) for the full, current indicator list.

### Is there a simple, no-tooling warning sign I should watch for?

Yes — a garbled **"Payment Transaction Failed Reminder"** email in your inbox,
containing raw, unrendered `{{var ...}}` template tags and a customer email address
ending in `.invalid`. This is a side effect of the exploit's detonation stage and is
often the very first visible sign, before anyone thinks to check a log file.

### What does the backdoor look like once it's installed?

A small (~1.9 MB), stripped, statically compiled Rust binary that disguises itself as an
ordinary-looking system process — first `[kworker/u:8:0]` (a kernel worker thread name),
later `fc-cache` v2.1.4 (the fontconfig cache utility) and `chronyd` v2.1.5 (the NTP
daemon, same operator, incremented version). It persists via cron, written directly to
the cron spool file to avoid normal audit logging. See
[`VULNERABILITY.md`](VULNERABILITY.md) for the full comparison table.

### Has the backdoor actually been used to do anything, or does it just sit there?

Sansec states it has not yet seen evidence the Rust implant itself was weaponized
beyond persistence and reconnaissance. Don't take that as reassurance, though — an
unrelated second attacker was independently found dropping a working PHP web shell
through the exact same entry point, and a remotely-updatable backdoor that hasn't shown
its objective yet is not one you can safely ignore.

### Why didn't my antivirus / VirusTotal catch this?

At the time of disclosure, no security vendor besides Sansec recognized the implant on
VirusTotal. The binary is new, statically compiled, carries no symbols, and its hash
varies build-to-build — the in-memory copy has even been observed differing from the
copy on disk. Checksum-only detection is weak against this implant; behavioral
indicators (process ownership, cron pattern, network shape) are more reliable.

### Why don't I see any suspicious network traffic?

At least one confirmed infection made **zero outbound connections** and instead read
Magento's session data directly out of the store's own local Redis instance — no egress
to alert on. The `fc-cache`/`chronyd` variant beacons out disguised as ordinary NTP
traffic on UDP port 123, a port most firewalls and egress monitoring treat as harmless,
and separately makes plain-HTTP calls to public IP-lookup services that look like
routine traffic in isolation. A clean network capture does not mean a clean host.

### What should I do right now?

1. **Apply Adobe's official hotfix (VULN-39341 / APSB26-146)** if your version is
   covered — see [`PATCHING.md`](PATCHING.md). This is now the priority, ahead of any
   interim mitigation.
2. If you can't patch immediately, or you're on a version Adobe doesn't cover, use the
   interim mitigations in [`../mitigations/`](../mitigations/) — GraphQL blocking, plus
   the newer PHP-execution block for `pub/media`/`pub/static` against the second
   attacker's web-shell technique. These reduce exposure; they are not a substitute for
   the patch.
3. **Run the compromise scanner regardless.** Patching stops new exploitation; it does
   not clean an existing backdoor, web shell, or rogue admin account.

### What do I do if the scanner finds something?

Don't just delete the process and move on. See
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full, ordered playbook: preserve
evidence, remove persistence before killing the process, then flush sessions, rotate the
Magento encryption key and every credential in `app/etc/env.php`, and check for rogue
admin accounts and dropped webshells (both the Rust implant's and the unrelated second
attacker's) before considering the store clean.

### Where can I get the authoritative, up-to-date information?

[sansec.io/research/stylesmuggler-0day](https://sansec.io/research/stylesmuggler-0day)
and [Adobe's APSB26-146 bulletin](https://helpx.adobe.com/security/products/magento/apsb26-146.html)
are the primary, continuously updated sources. This repo is a community-built companion
toolkit, not a replacement for either.
