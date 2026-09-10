# Changelog

All notable changes to this toolkit are recorded here. This started as an active,
unpatched 0-day incident repo; Adobe has since shipped an official fix (see below), but
expect continued updates as compromise cleanup, secondary-attacker activity, and patch
adoption play out.

## [Unreleased]
- Watching for: further variants of the second, unrelated web-shell attacker; any
  additional implant version bumps beyond `fc-cache` 2.1.4 / `chronyd` 2.1.5; expanded
  Adobe patch coverage for versions below the currently supported floor; whether the
  community root-cause (directive-signing) framing and Adobe's own fix converge on the
  same description over time.

## 2026-09-09 — root cause detail, Mage-OS coverage, more community patch options
Corroborating community coverage (patch write-ups, changelogs, and package registries
dated 2026-09-05 through 2026-09-08) added detail not present in Sansec's advisory
itself:

- Added a more precise **root-cause explanation**: a community patch effort frames the
  underlying flaw as Magento's directive-signing mechanism failing to restrict signing
  to explicitly **deferred** directives (like `inlinecss`, which handles the
  `style`/`styles` properties the vulnerability is named after) — letting an
  improperly-resolved directive through validation it should have failed. Added to
  `docs/VULNERABILITY.md` alongside the existing DI-scanner-sink framing; both describe
  real, independently patchable points in the same chain, and Adobe's own hotfix
  remains the authoritative fix.
- **Mage-OS users have a dedicated path**: Mage-OS shipped version **3.5.0** as an
  emergency security release porting the StyleSmuggler hotfix with added hardening,
  bundling the equivalent of APSB26-138, and fixing four unrelated bugs. Documented in
  `docs/PATCHING.md` and noted in the README.
- Corrected and expanded the community-patch-options section in `docs/PATCHING.md`:
  distinguished **wrappers around Adobe's official patch** from **independent interim
  stopgap modules** (which predate and are superseded by the official hotfix), and
  added specific named options and what each one actually does/doesn't cover:
  Scandiweb's reported 41-patch backport set for Magento 2.2.0–2.4.3-p3; BigBridge's
  root-cause "deferred directives" patch for 2.4.5–2.4.9; and Graycore's
  `magento2-style-smuggler-patch`, whose own documentation is explicit that it is
  hardening only, not a fix, and that a vulnerable store may already be compromised.
- Added a **retrospective threat-hunting** recommendation to `docs/VULNERABILITY.md`
  and `docs/INCIDENT_RESPONSE.md`: for anyone with EDR/auditd/process-lineage logging
  predating disclosure, hunt across the full exploitation window (2026-09-04 onward)
  for any PHP-FPM/web-server-worker process spawning an unexpected shell or binary as a
  child — this catches variants not named anywhere else in this repo.
- Reinforced the credential-rotation list in `docs/PATCHING.md` and
  `docs/INCIDENT_RESPONSE.md` to explicitly name GraphQL integration tokens and OAuth
  client secrets alongside the items already listed, matching Adobe's own post-hotfix
  guidance as reported.
- Fixed a stale line in `docs/INCIDENT_RESPONSE.md` that still said "there is still no
  CVE" after the CVE had already been assigned in an earlier update.

## 2026-09-08 — APSB26-138 requirement, additional filename variants, deeper IR guidance
Corroborating community write-ups (published 2026-09-07/08) added detail beyond
Sansec's advisory that materially changes what a thorough check/cleanup looks like:

- **Adobe's regular September 2026 Commerce update, APSB26-138, was released
  2026-09-08.** Adobe's own guidance is that hotfix VULN-39341 must be applied **in
  addition to** APSB26-138, not instead of it. Reflected in `README.md` and
  `docs/PATCHING.md`.
- Additional observed filename variants for the Rust implant: `/tmp/.gvfsd-*` (hyphen),
  `/tmp/.cache_*`, `/tmp/.fc-<8hex>/fc-cache` (hyphenated subdirectory), and
  `/tmp/fc-cache` (dropped directly in `/tmp`, no subdirectory). Added to
  `iocs/file_paths.txt` and both scanners, tested against planted indicators.
- Confirmed `chronyd` build cron schedule: `57,27 * * * *` (twice hourly, different
  offset from the `fc-cache` build's `13,43 * * * *`). Also confirmed: the `chronyd`
  build has been observed **relaunching with no cron entry at all** — an empty
  crontab is not proof of a clean host. Both scanners now also check systemd user
  timers, PHP `auto_prepend_file`/`auto_append_file` hooks, and a
  `crontab command not allowed` log indicator as additional persistence signals.
- `docs/INCIDENT_RESPONSE.md` significantly expanded: UDP-socket capture and
  `lsof`-based Redis-port discovery for process evidence (one confirmed infection
  showed no external C2 connection, only local Redis traffic); a full database
  forensics pass (`admin_user`, `integration`, `oauth_token`, `core_config_data`,
  `cms_block`/`cms_page`); SSH `authorized_keys` and shell-startup-file checks;
  git-based unauthorized-change detection; scoped `redis-cli ... FLUSHDB` guidance in
  place of a blanket `FLUSHALL` that would affect other applications on a shared
  Redis instance.
- `docs/PATCHING.md`: corrected the interim community-patch description (it modifies
  three of Magento's DI code scanners, not one) and added recommended post-patch
  sequencing (maintenance mode → suspend cron → run IR playbook → rotate credentials
  → resume service).
- Housekeeping: repository git history was reset to a single clean commit so no
  removed/superseded file (including an earlier, since-deleted publishing-instructions
  file) remains recoverable from history. Nothing in this repository is addressed to
  any AI assistant or tool — all guidance is written for the person operating the
  store.

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
