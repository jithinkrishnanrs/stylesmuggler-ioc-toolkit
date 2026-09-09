# Changelog

All notable changes to this toolkit are recorded here. This started as an active,
unpatched 0-day incident repo; Adobe has since shipped an official fix (see below), but
expect continued updates as compromise cleanup, secondary-attacker activity, and patch
adoption play out.

## [Unreleased]
- Watching for: further variants of the second, unrelated web-shell attacker; any
  additional implant version bumps beyond `fc-cache` 2.1.4 / `chronyd` 2.1.5; official
  Adobe patch coverage for versions below the currently supported floor.

## 2026-09-07 (evening) — Adobe ships CVE-2026-75650 / APSB26-146, second attacker found
This is the big one: Adobe assigned a CVE, published a Priority 1 bulletin, and shipped
an official hotfix — and Sansec separately identified a **second, unrelated attacker**
also exploiting StyleSmuggler.

- **CVE-2026-75650 assigned. Adobe Security Bulletin APSB26-146 published 2026-09-07 at
  20:20 UTC**, Priority 1 (Adobe's highest), CVSS 3.1/4.0 **10.0**, CWE-1336 (Improper
  Neutralization of Special Elements Used in a Template Engine). Official hotfix
  **VULN-39341** now available from Adobe. See new `docs/PATCHING.md`.
- Coverage is not universal: Adobe Commerce 2.4.4–2.4.9 and B2B 1.3.3–1.5.3 are covered;
  **Magento Open Source below 2.4.6 gets no official fix.** Reflected in the README
  status table and `docs/PATCHING.md`.
- **A second, unrelated attacker** was found exploiting the same StyleSmuggler entry
  point to drop a PHP web shell at
  `pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php` — independent of the
  Rust implant operator, "off-the-shelf tooling" per Sansec, not a fleet operation. This
  actor sends a **reconnaissance probe first**: a cover GraphQL query with the actual
  payload smuggled in the `Store:` request header, exfiltrating recon data (OS/kernel
  string, PHP user, cwd, `pub/media` writability) via chunked DNS labels to an
  out-of-band canary domain rather than reading an HTTP response. Full technical
  breakdown in `docs/VULNERABILITY.md`; detection added to `iocs/`, both scanners, and a
  new pair of PHP-execution-blocking mitigation configs.
- New **early-warning indicator**: a garbled "Payment Transaction Failed Reminder"
  email containing raw `{{var ...}}` template tags and a customer address ending in
  `.invalid` is often the first visible sign of exploitation, before any log-based
  indicator — added to the README and `iocs/`.
- Identified the specific vulnerable sink file, `setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php`,
  and the rendering entry point, `getProcessedTemplate` — useful for confirming whether
  the official patch has actually been applied to a given install.
- Implant version numbers confirmed: `fc-cache` build is v2.1.4, `chronyd` build is
  v2.1.5 (same agent ID, incremented version — same operator).
- New fc-cache/chronyd network indicator: outbound plain-HTTP calls to public
  IP-lookup services (`api4.ipify.org`, `ipv4.icanhazip.com`, `ipv4.ident.me`,
  `ipinfo.io`) with a truncated User-Agent — added as an informational check, since
  these services are legitimate but a Magento backend calling them is not normal.
- Expanded access-log detection keywords beyond `styles[`: `generatorClass`,
  `with_resolved`, and the malware-download domain fragment `cdnflare` all appear in
  corroborating community grep patterns — added to `iocs/file_paths.txt` and both
  scanners.
- `docs/INCIDENT_RESPONSE.md`: added specific `app/etc/env.php` Redis-configuration
  inspection commands (cache DB, page-cache DB, session DB) and the `pub/media` PHP
  sweep as explicit steps.
- New `docs/PATCHING.md`: official hotfix identifiers, where to get it, affected-version
  coverage table, and pointers to community delivery tooling for applying it.
- New mitigation files blocking PHP execution under `pub/media`/`pub/static` (nginx +
  Apache) — targeted defense against the second attacker's web-shell technique,
  independent of the GraphQL-blocking rules.
- Sansec states it has not yet seen evidence the Rust implant itself was weaponized
  beyond persistence/reconnaissance — noted in `docs/VULNERABILITY.md` as a nuance, not
  reassurance: a web shell was found on the same access path from an unrelated actor.

## 2026-09-06/07 — second exploitation vector, two new backdoor variants
- Sansec's advisory updated to confirm a **second, independent delivery vector**: a file
  uploaded via Magento's customer custom options feature, confirmed to succeed even when
  session storage is moved off Redis. GraphQL-blocking mitigations alone do not close
  this path — updated `README.md`, `docs/VULNERABILITY.md`, and `iocs/file_paths.txt`.
- Added detection for two new backdoor builds: **`fc-cache`** (first seen 2026-09-06,
  copies to `~/.cache/fontconfig/fc-cache`, cron persistence twice/hour, beacons over
  NTP-shaped UDP/123) and **`chronyd`** (first seen 2026-09-07, `/tmp/.chrony-<8hex>/chronyd`,
  same agent ID as the `fc-cache` build — same operator, new disguise).
- `scripts/stylesmuggler_scan.sh` and `.py`: filesystem, cron, and process checks now
  cover all three known builds; process masquerade check for `fc-cache`/`chronyd` verifies
  the real executable path and owning user, not just the process name; network check adds
  the NTP-shaped C2 domains and a second malware-download IP.
- `iocs/hashes.sha256`: added 3 hashes for the `fc-cache`/`chronyd` build.
- `iocs/domains.txt`, `iocs/ips.txt`: added `ntp.timesync.to` (+2 fallbacks) and
  `209.141.43.95`.
- `iocs/yara/stylesmuggler.yar`, `iocs/suricata/stylesmuggler.rules`: updated with new
  hashes, strings, and network rules for the newer build; fixed advisory reference URL
  to the canonical `sansec.io/research/stylesmuggler-0day`.
- New `docs/FAQ.md` — quick, sourced answers for common questions.
- `docs/INCIDENT_RESPONSE.md`: expanded credential-rotation guidance (flush sessions,
  rotate `app/etc/env.php` crypt/key and all credentials, check for rogue `admin_user`
  entries and dropped webshells under `pub/media/`/`pub/static/`/theme directories)
  sourced from community cleanup guides, not just the original advisory.

## 2026-09-06 — initial release
- Initial toolkit built from the Sansec advisory (published 2026-09-05) and community
  incident-response reporting on two independently confirmed live infections plus one
  targeted-but-unsuccessful attempt, all dated 2026-09-05.
- `scripts/stylesmuggler_scan.sh` and `scripts/stylesmuggler_scan.py`: filesystem,
  cron, process, hash (on-disk + in-memory), poisoned-log, and network checks.
- `scripts/clean_crontab.sh`: dry-run-by-default, ordered cron remediation helper.
- `iocs/`: hashes (3, including the observed in-memory-vs-on-disk mismatch), domains,
  IPs (with source-address classification — bulk/infra vs. residential proxy pool),
  file paths, YARA rule, Suricata/IDS rules.
- `mitigations/`: nginx, Apache, ModSecurity, and fail2ban interim rules for blocking
  or rate-limiting the GraphQL `styles[]` delivery vector while there was no patch.
- `docs/`: vulnerability technical summary, timeline, incident-response playbook.

### Known limitations at this release (superseded — see 2026-09-07 entry above)
- No CVE existed yet at this point; that changed with APSB26-146/CVE-2026-75650.
- The trigger-header format changed once within 24 hours of disclosure
  (`X-TRACE-<10hex>` → `X-<12hex>`); treat all literal-string signatures in this repo as
  likely to need updating again, and prefer the shape-based / behavioral checks over
  any single string match.
- Network-based detection (Suricata rules, fail2ban) cannot catch infections that make
  no outbound C2 connection at all — at least one confirmed case harvested Magento
  session data entirely over local Redis with zero external traffic. Always pair
  network rules with the host-based scanner.
