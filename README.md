# StyleSmuggler IOC Toolkit

**Magento zero-day · Adobe Commerce zero-day · unauthenticated RCE · Magento malware ·
Magento backdoor removal · Magento 2.4.9 vulnerability · Rust implant · GraphQL styles
injection**

Community indicators-of-compromise, a compromise scanner, and interim mitigation rules
for **StyleSmuggler** — the unauthenticated, unpatched Magento Open Source / Adobe Commerce
RCE zero-day disclosed by [Sansec](https://sansec.io/research/stylesmuggler-0day) on
**September 5, 2026**, with in-the-wild exploitation confirmed from **September 4, 2026**.
If you searched for "StyleSmuggler IOC", "Magento fc-cache malware", "Magento chronyd
backdoor", "gvfsd-user Magento", "Adobe Commerce 0-day September 2026", or "Magento
GraphQL styles RCE", this is the repo you want.

> **This is a defensive toolkit only.** It contains detection signatures, a compromise
> scanner, and hardening/blocking rules built from published, first-hand incident reports.
> It does **not** contain exploit code, a proof-of-concept trigger, or anything that
> generates the attack payload. If you are looking for that, you are in the wrong repo —
> go patch and hunt instead.

## Status as of this writing (2026-09-07)

| | |
|---|---|
| Vulnerability | StyleSmuggler (unofficial name, coined by Sansec) |
| Vendor | Adobe (Magento Open Source, Adobe Commerce) |
| CVE | **None assigned yet** |
| Official patch | **None shipped yet.** Adobe Enterprise Support confirmed on **Sept 7, 2026** that a fix is in progress. Adobe's next scheduled Commerce bulletin is Sept 8, 2026 — not confirmed to be StyleSmuggler's fix. |
| Authentication required | **None** — unauthenticated |
| Affected versions | All current versions, reproduced by Sansec on clean Magento Open Source 2.4.7, 2.4.8, 2.4.9; first confirmed victim ran 2.4.6-p15 fully patched |
| Exploitation | Active since 2026-09-04 22:20 UTC; second attacker/vector confirmed Sept 5-6 |
| Known backdoor variants | `[kworker/u:8:0]` (Sept 4) → `fc-cache` (Sept 6) → `chronyd` (Sept 7) — same operator, same agent ID across the last two |
| Known delivery vectors | GraphQL `styles[]` parameter; invalid store code logged to `var/log/system.log`; **file uploaded via Magento's customer custom options** (confirmed second vector — moving sessions off Redis does NOT stop this one) |
| Impact | Remote code execution → persistent Rust-based backdoor, Redis session harvesting, credential/secret exposure via `app/etc/env.php` |

**This information changes fast.** Cross-check against the primary source before acting:
[sansec.io/research/stylesmuggler-0day](https://sansec.io/research/stylesmuggler-0day). See
[`docs/TIMELINE.md`](docs/TIMELINE.md) for a running log and cite your sources when you
update anything here.

## What StyleSmuggler actually is

Magento's own GraphQL `styles` parameter and its dependency-injection based file scanning
are abused as a two-stage, file-based deferred-execution primitive rather than a single
obvious injection point:

1. **Poison.** Attacker-controlled data reaches a Magento-generated log or report file
   (`var/log/system.log` via an invalid store code that Magento logs verbatim, or
   `var/report/<hash>`), smuggled in through the GraphQL `styles[]` parameter or a mutated
   request header.
2. **Detonate.** The attacker triggers Magento's standard **"Payment Transaction Failed
   Reminder"** email. Rendering that email walks a code path that lets Magento's own
   DI/code scanner `include()` the poisoned file, running the attacker's PHP. You do not
   need to open the email — rendering it server-side is enough — and the chain can fire
   even when mail delivery itself fails.

Sansec's Sept 6-7 updates confirmed a **second, independent exploitation path**: even
stores that moved session storage off Redis and onto the database (a mitigation some
merchants tried) were still compromised — the same operator's second attempt succeeded
seconds later using a file uploaded through Magento's **customer custom options** feature
instead. Moving session storage is not a fix by itself.

The backdoor itself has also evolved: the original `[kworker/u:8:0]`-masquerading Rust
implant (Sept 4) was followed by an `fc-cache`-masquerading build (Sept 6) that beacons
out disguised as NTP traffic, and then a `chronyd`-masquerading redeploy of the **same
implant, same agent ID** (Sept 7) — evidence the attacker is actively iterating to evade
whatever detection you publish. See [`docs/FAQ.md`](docs/FAQ.md) for quick answers and
[`docs/VULNERABILITY.md`](docs/VULNERABILITY.md) for the full technical writeup and
sourcing, and [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) for what to do if
the scanner finds something.

## Quick start — am I compromised?

```bash
git clone https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit.git
cd stylesmuggler-ioc-toolkit
sudo bash scripts/stylesmuggler_scan.sh --magento-root /var/www/html
```

Or the Python version for structured (JSON/SARIF-ish) output, e.g. for feeding a SIEM:

```bash
sudo python3 scripts/stylesmuggler_scan.py --magento-root /var/www/html --json report.json
```

Both scripts are **read-only by default** — they detect and report, they don't kill
processes or delete files unless you pass `--remediate`, because premature cleanup
destroys forensic evidence (see the incident response doc).

## What the scanner checks

- Known **filesystem persistence** artifacts across all three observed backdoor builds:
  - `[kworker/u:8:0]` build: `~/.local/share/.gvfsd/gvfsd-user`, its lock files, `/tmp/.kw_*`, `/tmp/.gvfsd_*`
  - `fc-cache` build (Sept 6): `~/.cache/fontconfig/fc-cache`, `/tmp/.fc_<8hex>.lock`
  - `chronyd` build (Sept 7): `/tmp/.chrony-<8hex>/chronyd`
- The **self-restoring crontab** entries the implant writes directly to the cron spool —
  every 5 minutes for the `gvfsd-user` build, twice an hour (`13,43 * * * *`) for `fc-cache`
- A **masquerading process** named `[kworker/u:8:0]`, `fc-cache`, or `chronyd` that is
  *not* owned by root (or, for `fc-cache`/`chronyd`, doesn't match the real system binary)
- **SHA-256** of on-disk binaries *and* of the live `/proc/<pid>/exe` image (the two can
  differ — the implant has been observed updating itself in memory)
- **Poisoned log/report files** (`var/log/system.log`, `var/report/`) for injected PHP
  and for the two known trigger-header shapes (`X-TRACE-<10hex>` and `X-<12hex>`)
- **Proof-of-execution response markers** (`MG<20hex>::...::/MG<20hex>`) left behind in
  logs when the payload actually ran
- Established connections to the **published C2/download hosts** — including the
  `fc-cache`/`chronyd` build's NTP-*shaped* beaconing to `ntp.timesync.to:123/UDP` (and
  fallbacks `ntp.synctime.to`, `ntp.syncstime.to`), which carries a chunked MessagePack
  record (agent ID, hostname, username, OS/memory/disk info, root status, implant
  version) inside what looks like ordinary NTP traffic on port 123
- Anomalous local Redis connection counts (session-harvesting has been observed entirely
  over `127.0.0.1:6379`, with **zero outbound C2 traffic** — a quiet network is not a
  clean one) — and note that **moving sessions off Redis alone does not close the second,
  file-upload-based exploitation vector**

Full indicator list with sourcing: [`iocs/`](iocs/).

## Mitigation while there is no patch

There is no official fix yet. Until there is:

1. Put a WAF in front of the store (commercial or the sample rules in
   [`mitigations/`](mitigations/) as a stopgap).
2. If your storefront/integrations don't need it, **block public access to GraphQL**
   entirely — see [`mitigations/nginx_block_graphql_styles.conf`](mitigations/nginx_block_graphql_styles.conf)
   and [`mitigations/apache_block_graphql_styles.conf`](mitigations/apache_block_graphql_styles.conf).
   If you *do* need GraphQL, those files also include a narrower rule that only blocks
   requests carrying a `styles` argument.
3. Add the [fail2ban filter](mitigations/fail2ban_stylesmuggler.conf) and/or
   [ModSecurity rules](mitigations/modsecurity_stylesmuggler.conf) to catch the trigger
   header and response-marker shapes even if the exact bytes change again (they already
   have once — see the changelog in `iocs/`).
4. Run the scanner **today**, before you patch — patching doesn't clean an already-dropped
   backdoor.
5. If the scanner finds anything, treat the host as fully compromised, not just
   "backdoor present." Code execution as the site user exposes everything that user can
   read, starting with `app/etc/env.php`. At minimum, after containment: flush session
   storage (Redis and/or DB), rotate the Magento `crypt/key`, all admin passwords (and
   invalidate existing admin sessions), the database password, every payment-provider
   API key and other integration credential in `env.php`, and any SSH/deploy keys the
   site user could read. Also check the `admin_user` table for a rogue account and
   `pub/media/` / `pub/static/` / theme directories for dropped webshells before you
   consider a store clean. Full ordered steps: [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).

None of this is a substitute for an official Adobe patch once one ships. Track it and
apply it — Adobe Enterprise Support confirmed on Sept 7, 2026 that a fix is in progress,
but no release date or CVE exists yet.

## Repo layout

```
docs/                    Vulnerability writeup, timeline, FAQ, IR playbook
iocs/                    Hashes, IPs, domains, file paths, YARA, Suricata/IDS rules
scripts/                 stylesmuggler_scan.sh / .py, crontab cleanup helper
mitigations/             nginx / Apache / ModSecurity / fail2ban rules
```

## Frequently searched terms

Magento zero-day 2026, Adobe Commerce zero-day, StyleSmuggler CVE, Magento GraphQL
vulnerability, Magento styles parameter RCE, gvfsd-user malware, fc-cache Magento
backdoor, chronyd Magento malware, Magento kworker process malware, Magento Redis
session hijack, Magento unauthenticated RCE September 2026, Magento 2.4.9 exploit,
Adobe Commerce backdoor removal, eComscan StyleSmuggler, Sansec Shield StyleSmuggler.

## Sourcing and provenance

Every indicator in this repo traces back to a cited, published source — primarily the
Sansec advisory (updated through 2026-09-07) and community incident-response write-ups
from responders who handled live infections. See the citation at the bottom of each
file in `iocs/`.
**Do not** treat anything here as exhaustive or final — this is an active, developing
incident with no CVE and no vendor patch yet. IOCs (especially the trigger header and
user-agent strings) have already changed once within 24 hours of disclosure; expect them
to change again. Match shapes and behavior, not just literal strings, wherever the
scripts let you.

## Contributing

Seen a variant, a new hash, a new source address, or a false positive? Open an issue or
PR with what you observed and how you observed it. Please:
- Redact your own organization's identifying details before sharing.
- Don't post exploit payloads or working trigger requests here — indicators and
  detection logic only.
- Report the underlying vulnerability itself to [Sansec](https://sansec.io/contact) and
  Adobe PSIRT, not to this repo.

## License

MIT for the code in this repo (see [`LICENSE`](LICENSE)). Indicator data is provided
"as is" for defensive use, with sourcing noted throughout.

## Disclaimer

This is unofficial, community-built defensive tooling, not an Adobe or Sansec product,
and is not affiliated with either. It is provided without warranty. There is currently
no CVE identifier and no official vendor patch for this issue — check
[Adobe's security bulletins](https://helpx.adobe.com/security/products/magento.html)
before assuming any release addresses it.
