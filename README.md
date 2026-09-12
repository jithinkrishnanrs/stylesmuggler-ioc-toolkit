# StyleSmuggler IOC Toolkit — CVE-2026-75650

**Magento zero-day · Adobe Commerce zero-day · CVE-2026-75650 · APSB26-146 ·
VULN-39341 · unauthenticated RCE · Magento malware · Magento backdoor removal ·
Magento 2.4.9 vulnerability · Rust implant · GraphQL styles injection · PHP web shell**

Community indicators-of-compromise, a compromise scanner, and mitigation/patching
guidance for **StyleSmuggler** (**CVE-2026-75650**) — the unauthenticated Magento Open
Source / Adobe Commerce RCE disclosed by [Sansec](https://sansec.io/research/stylesmuggler-0day)
on **September 5, 2026**, with in-the-wild exploitation confirmed from
**September 4, 2026**. Adobe published an official fix, **APSB26-146**, on
**September 7, 2026**. If you searched for "StyleSmuggler IOC", "CVE-2026-75650",
"APSB26-146", "VULN-39341", "Magento fc-cache malware", "Magento chronyd backdoor",
"gvfsd-user Magento", or "Magento GraphQL styles RCE", this is the repo you want.

> **This is a defensive toolkit only.** It contains detection signatures, a compromise
> scanner, and hardening/blocking rules built from published, first-hand incident reports.
> It does **not** contain exploit code, a proof-of-concept trigger, or anything that
> generates the attack payload. If you are looking for that, you are in the wrong repo —
> go patch and hunt instead.

## Status as of this writing (2026-09-10)

| | |
|---|---|
| Vulnerability | StyleSmuggler (Sansec's name) — **CVE-2026-75650** |
| Vendor | Adobe (Magento Open Source, Adobe Commerce) |
| CVE | **CVE-2026-75650**, assigned 2026-09-07 |
| Adobe bulletin | **APSB26-146**, published 2026-09-07 20:20 UTC, **Priority 1** (highest) |
| Also required | **APSB26-138** (Adobe's regular September 2026 Commerce update, isolated patch `249-2026-09-001-CE`, released 2026-09-08). Adobe states VULN-39341 must be applied **in addition to** this, not instead of it. |
| CVSS | **10.0** (3.1 and 4.0) — Critical |
| CWE | CWE-1336, Improper Neutralization of Special Elements Used in a Template Engine |
| **CISA KEV** | **Added to CISA's Known Exploited Vulnerabilities catalog 2026-09-08.** Federal civilian executive branch (FCEB) remediation deadline: **2026-09-11**. Not just a Magento-community problem — this is now a federally-tracked, actively-exploited RCE. |
| Official patch | **Shipped.** Hotfix `VULN-39341`. **Coverage is not universal** — see the table below. |
| Authentication required | **None** — unauthenticated |
| Affected versions | Reproduced by Sansec on clean Magento Open Source 2.4.7, 2.4.8, 2.4.9; first confirmed victim ran 2.4.6-p15 fully patched (on prior patches) |
| Exploitation | Active since 2026-09-04 22:20 UTC; continued through patch release; a second, unrelated attacker joined 2026-09-07. Third-party WAF telemetry (Imperva) reports observed targets skew retail (~39.5%), lifestyle (~19.5%), and healthcare (~17.9%) — a snapshot of one vendor's visibility, not a claim about the full population of vulnerable stores. |
| Known Rust-implant variants | `[kworker/u:8:0]` (Sept 4) → `fc-cache` v2.1.4 (Sept 6) → `chronyd` v2.1.5 (Sept 7) — same operator, same agent ID, versions incrementing |
| Second, unrelated attacker | PHP web shell in `pub/media/catalog/product/cache/`, preceded by a DNS-exfiltrating recon probe — independent of the Rust implant, confirmed 2026-09-07 |
| Known delivery vectors | GraphQL `styles[]` parameter; invalid store code logged to `var/log/system.log`; file uploaded via Magento's customer custom options; the unrelated second attacker's `Store:`-header injection |
| Impact | Remote code execution → persistent Rust-based backdoor, independent PHP web shell, Redis session harvesting, credential/secret exposure via `app/etc/env.php` |

### Adobe's official patch coverage — check this before assuming you're safe

| Product | Covered by APSB26-146 | No official fix |
|---|---|---|
| Adobe Commerce (incl. B2B, Cloud) | 2.4.4 – 2.4.9 | below 2.4.4 |
| Adobe Commerce B2B | 1.3.3 – 1.5.3 | below 1.3.3 |
| Magento Open Source | **2.4.6 – 2.4.9 only** | 2.4.5 and below |

If you're on an older, unsupported version, Adobe is not shipping you a fix even though
you're just as exploitable. See [`docs/PATCHING.md`](docs/PATCHING.md) for your options
— including a note for **Mage-OS** users, who have a dedicated emergency release
(3.5.0) rather than Adobe's Commerce-specific hotfix package.

**This information changes fast.** Cross-check against the primary sources before
acting: [Sansec's advisory](https://sansec.io/research/stylesmuggler-0day) and
[Adobe's bulletin](https://helpx.adobe.com/security/products/magento/apsb26-146.html).
See [`docs/TIMELINE.md`](docs/TIMELINE.md) for a running log and cite your sources when
you update anything here.

## What StyleSmuggler actually is

Magento's own GraphQL `styles` parameter and its dependency-injection based file scanning
are abused as a two-stage, file-based deferred-execution primitive rather than a single
obvious injection point:

1. **Poison.** Attacker-controlled data reaches a Magento-generated log or report file
   (`var/log/system.log` via an invalid store code that Magento logs verbatim, or
   `var/report/<hash>`), smuggled in through the GraphQL `styles[]` parameter, a
   mutated request header, or (for the second, unrelated attacker below) the `Store:`
   header.
2. **Detonate.** The attacker triggers Magento's standard **"Payment Transaction Failed
   Reminder"** email. Rendering that email (Magento's `getProcessedTemplate` path) walks
   a code path that lets Magento's own DI/code scanner `include()` the poisoned file,
   running the attacker's PHP. You do not need to open the email — rendering it
   server-side is enough — and the chain can fire even when mail delivery itself fails.

An **easy, no-tooling early warning sign**: a garbled "Payment Transaction Failed
Reminder" email in your inbox with raw, unrendered `{{var ...}}` tags and a customer
address ending in `.invalid`. This is often the *first* visible sign, before anyone
checks a log.

Sansec's updates confirmed a **second, independent exploitation path** for the same
Rust-implant campaign: even stores that moved session storage off Redis and onto the
database were still compromised — the same operator's second attempt succeeded seconds
later using a file uploaded through Magento's **customer custom options** feature
instead. Moving session storage is not a fix by itself.

**Separately, on September 7, Sansec found a completely unrelated attacker** using the
exact same StyleSmuggler entry point for a much simpler payload: a PHP web shell dropped
into Magento's own product-image cache
(`pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php`), preceded by a
reconnaissance probe that hides its payload in the `Store:` HTTP header and exfiltrates
its findings over DNS rather than an HTTP response. This is "off-the-shelf tooling," per
Sansec — not a sustained campaign — but it means a single vulnerable host can carry
**two unrelated intrusions through one flaw**. Cleaning up the Rust implant does not
mean your store is clean.

The Rust implant itself has also evolved: the original `[kworker/u:8:0]`-masquerading
build (Sept 4) was followed by an `fc-cache`-masquerading build v2.1.4 (Sept 6) that
beacons out disguised as NTP traffic, and then a `chronyd`-masquerading redeploy v2.1.5
(Sept 7) of the **same implant, same agent ID** — evidence the attacker is actively
iterating to evade whatever detection you publish. Sansec states it hasn't yet seen
evidence this implant was weaponized beyond persistence/recon — don't read that as
reassurance given the unrelated attacker's working web shell on the same access path.

See [`docs/FAQ.md`](docs/FAQ.md) for quick answers,
[`docs/VULNERABILITY.md`](docs/VULNERABILITY.md) for the full technical writeup and
sourcing, [`docs/PATCHING.md`](docs/PATCHING.md) for applying Adobe's official fix, and
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) for what to do if the scanner
finds something.

## Quick start

**1. Patch, if your version is covered:**

```bash
# See docs/PATCHING.md for the full process — this is not a one-liner, it requires
# Adobe repo credentials and your project's patch-management tooling.
```

**2. Scan for existing compromise regardless of patch status** — patching stops new
exploitation, it doesn't clean an existing backdoor or web shell:

```bash
git clone https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit.git
cd stylesmuggler-ioc-toolkit
sudo bash scripts/stylesmuggler_scan.sh --magento-root /var/www/html
```

Or the Python version for structured (JSON) output, e.g. for feeding a SIEM:

```bash
sudo python3 scripts/stylesmuggler_scan.py --magento-root /var/www/html --json report.json
```

Both scripts are **read-only by default** — they detect and report, they don't kill
processes or delete files unless you pass `--remediate`, because premature cleanup
destroys forensic evidence (see [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md)).

## What the scanner checks

- Known **filesystem persistence** artifacts across all three observed Rust-implant builds:
  - `[kworker/u:8:0]` build: `~/.local/share/.gvfsd/gvfsd-user`, its lock files, `/tmp/.kw_*`, `/tmp/.gvfsd_*`
  - `fc-cache` build v2.1.4 (Sept 6): `~/.cache/fontconfig/fc-cache`, `/tmp/.fc_<8hex>.lock`
  - `chronyd` build v2.1.5 (Sept 7): `/tmp/.chrony-<8hex>/chronyd`
- The **self-restoring crontab** entries the implant writes directly to the cron spool —
  every 5 minutes for the `gvfsd-user` build, twice an hour (`13,43 * * * *`) for `fc-cache`
- A **masquerading process** named `[kworker/u:8:0]`, `fc-cache`, or `chronyd` that is
  *not* owned by root (or, for `fc-cache`/`chronyd`, doesn't match the real system binary)
- **SHA-256** of on-disk binaries *and* of the live `/proc/<pid>/exe` image (the two can
  differ — the implant has been observed updating itself in memory)
- **Poisoned log/report files** (`var/log/system.log`, `var/report/`) for injected PHP,
  the two known trigger-header shapes (`X-TRACE-<10hex>` and `X-<12hex>`), and the
  **second, unrelated attacker's** campaign markers (`ss5_`/`ss6_<hex>`) and DNS-canary
  domain (`oast.site`)
- **Proof-of-execution response markers** (`MG<20hex>::...::/MG<20hex>`) left behind in
  logs when the payload actually ran
- **PHP files under `pub/media`** — which should never contain executable PHP on a
  correctly configured Magento store — matching the second attacker's web-shell drop
  pattern
- Established connections to the **published C2/download hosts** — including the
  `fc-cache`/`chronyd` build's NTP-*shaped* beaconing to `ntp.timesync.to:123/UDP` (and
  fallbacks), and its plain-HTTP calls to public IP-lookup services
- Anomalous local Redis connection counts (session-harvesting has been observed entirely
  over `127.0.0.1:6379`, with **zero outbound C2 traffic** — a quiet network is not a
  clean one) — and note that **moving sessions off Redis alone does not close the second,
  file-upload-based exploitation vector**

Full indicator list with sourcing: [`iocs/`](iocs/).

## Patching and mitigation

1. **Apply Adobe's official hotfix (VULN-39341 / APSB26-146)** if your version is
   covered — see [`docs/PATCHING.md`](docs/PATCHING.md) for identifiers, where to get
   it, and how to apply it. This is now the priority, ahead of the interim mitigations
   below.
2. **If you can't patch immediately, or your version isn't covered**, use the interim
   mitigations in [`mitigations/`](mitigations/):
   - Block or rate-limit GraphQL's `styles[]` delivery path
     ([nginx](mitigations/nginx_block_graphql_styles.conf) /
     [Apache](mitigations/apache_block_graphql_styles.conf) /
     [Cloudflare WAF](mitigations/cloudflare_waf_rules.md) if you're behind Cloudflare)
   - Block PHP execution under `pub/media`/`pub/static`
     ([nginx](mitigations/nginx_block_php_execution_media.conf) /
     [Apache](mitigations/apache_block_php_execution_media.conf)) — targeted defense
     against the second, unrelated attacker's web-shell technique
   - [ModSecurity rules](mitigations/modsecurity_stylesmuggler.conf) for POST-body
     inspection and [fail2ban](mitigations/fail2ban_stylesmuggler.conf) as a reactive
     backstop
   - [`disable_functions` hardening](mitigations/php_disable_functions.md) (blocking
     `proc_open` and related functions) as additional defense-in-depth against dropper
     execution, independent of the delivery vector — test on staging first
   - See [`mitigations/README.md`](mitigations/README.md) for scope limitations —
     none of these close the customer-custom-options vector or the second attacker's
     `Store:`-header delivery.
3. **Run the compromise scanner regardless of patch/mitigation status.** Patching and
   mitigating stop *new* exploitation; neither cleans an already-dropped backdoor or
   web shell.
4. **If the scanner finds anything, treat the host as fully compromised**, not just
   "backdoor present." Code execution as the site user exposes everything that user can
   read, starting with `app/etc/env.php`. At minimum, after containment: flush session
   storage (Redis and/or DB), rotate the Magento `crypt/key`, all admin passwords (and
   invalidate existing admin sessions), the database password, every payment-provider
   API key and other integration credential in `env.php`, and any SSH/deploy keys the
   site user could read. Also check the `admin_user` table for a rogue account and
   `pub/media/` / `pub/static/` / theme directories for dropped webshells — both the
   Rust implant's and the unrelated second attacker's — before you consider a store
   clean. Full ordered steps: [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).

## Repo layout

```
docs/                    Vulnerability writeup, timeline, FAQ, patching guide, IR playbook
iocs/                    Hashes, IPs, domains, file paths, YARA, Suricata/IDS rules
scripts/                 stylesmuggler_scan.sh / .py, crontab cleanup helper
mitigations/             nginx / Apache / ModSecurity / fail2ban rules
```

## Frequently searched terms

CVE-2026-75650, APSB26-146, APSB26-138, VULN-39341, CISA KEV StyleSmuggler, Magento
zero-day 2026, Adobe Commerce zero-day, StyleSmuggler patch, Mage-OS 3.5.0 security
release, Magento GraphQL vulnerability, Magento styles parameter RCE, Magento directive
signing vulnerability, gvfsd-user malware, fc-cache Magento backdoor, chronyd Magento
malware, Magento kworker process malware, Magento Redis session hijack, Magento
unauthenticated RCE September 2026, Magento 2.4.9 exploit, Adobe Commerce backdoor
removal, Magento
pub/media web
shell, eComscan StyleSmuggler, Sansec Shield StyleSmuggler.

## Sourcing and provenance

Every indicator in this repo traces back to a cited, published source — primarily
Sansec's advisory (updated through at least 2026-09-07 20:50 UTC), Adobe's APSB26-146
bulletin, and community incident-response write-ups from responders who handled live
infections. See the citation at the bottom of each file in `iocs/`.

**Do not** treat anything here as exhaustive or final. IOCs (trigger headers,
user-agent strings, implant disguises, and now a second attacker's campaign markers)
have already changed multiple times within days of disclosure; expect them to change
again. Match shapes and behavior, not just literal strings, wherever the scripts let you.

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
and is not affiliated with either. It is provided without warranty. Adobe's official
patch (APSB26-146) has been released, but coverage is limited to specific product
versions — check [Adobe's security bulletin](https://helpx.adobe.com/security/products/magento/apsb26-146.html)
directly before assuming your installation is covered or fixed.
