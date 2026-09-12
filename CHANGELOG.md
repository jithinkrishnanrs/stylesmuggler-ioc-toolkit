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
  same description over time. Sansec's advisory page modified timestamp is confirmed
  through 2026-09-10 13:20 UTC as of this writing, but specific new content beyond the
  2026-09-09 update has not yet been distinguished — re-check the primary source.

## 2026-09-10 — CISA KEV listing, disable_functions hardening, corrected patch package info
- **CVE-2026-75650 added to CISA's Known Exploited Vulnerabilities (KEV) catalog on
  2026-09-08**, with a **2026-09-11** remediation deadline for U.S. federal civilian
  executive branch agencies under Binding Operational Directive 22-01. Added
  prominently to the README status table, `docs/PATCHING.md`, `docs/VULNERABILITY.md`,
  and `docs/TIMELINE.md` — this is independent, third-party (government) confirmation
  of active, consequential exploitation, not just Sansec's and Adobe's own word.
- Adobe's September isolated patch identifier confirmed: **`249-2026-09-001-CE`**
  (APSB26-138). Added alongside existing references.
- **Corrected the Disrex package description** in `docs/PATCHING.md`: it's
  `disrex/stylesmuggler-adobe-patches`, a self-contained Composer plugin (not
  requiring `cweagans/composer-patches`) that auto-detects Magento Open Source vs.
  Mage-OS and applies Adobe's official patch to either — not the separate
  "adobe-patches"/"adobe-patches-mageos" split described in an earlier version of this
  doc.
- Expanded the Mage-OS section with the specific upgrade command, an explicit note
  that upgrading alone doesn't replace compromise assessment (Mage-OS's own guidance),
  and a compatibility caution about ACL/template-policy changes in 3.5.0's hardening.
- New mitigation: [`mitigations/php_disable_functions.md`](mitigations/php_disable_functions.md)
  — disabling `proc_open` and related PHP functions as defense-in-depth against
  dropper execution, per public StyleSmuggler mitigation guidance. Includes a
  pre-deployment codebase scan and staging-first guidance, since this can break
  legitimate functionality if applied carelessly.
- Broadened the credential-rotation lists in `docs/PATCHING.md` and
  `docs/INCIDENT_RESPONSE.md` to explicitly name privileged service-account
  credentials and non-payment third-party API keys (shipping, tax, etc.), per
  corroborating incident-response coverage beyond Adobe's own baseline list.
- Added Imperva WAF telemetry (sector breakdown of observed exploitation targets:
  retail, lifestyle, healthcare) to `docs/VULNERABILITY.md` as context, explicitly
  framed as one vendor's visibility rather than a complete picture.

## 2026-09-09 (later) — Sansec IOC update: new hashes, new C2/attacker IPs, web-shell auth header
Sansec's advisory was itself revised again (page modified timestamp 2026-09-09
12:11 UTC), and a corroborating community write-up captured the added content in full
— this update is sourced from the primary advisory's own additions, not just secondary
commentary:

- **New hashes**: a 7th SHA-256 for a `chronyd` variant, and — for the first time — a
  published hash for the **second, unrelated attacker's PHP web-shell dropper**
  (previously only identified by path pattern and campaign markers). Added to
  `iocs/hashes.sha256` and a new dedicated YARA rule
  (`StyleSmuggler_SecondAttacker_Dropper_Hash`).
- **New network infrastructure**: a second, IP-based C2 endpoint
  (`185.157.160.251:123`, UDP/NTP-shaped, alongside the existing `ntp.timesync.to`
  domain family) and **four additional confirmed attacker source IPs**
  (182.182.152.48, 76.31.99.207, 209.73.130.148, 77.239.124.107). Added to
  `iocs/ips.txt` and `iocs/suricata/stylesmuggler.rules`; both scanners now check the
  new C2 IP over UDP in addition to the existing TCP checks.
- **The second attacker's web shell is authentication-gated**: it only responds to
  requests carrying a specific header/value (`X-Cache-Token: <hash>`); without it,
  requests return a generic 404. Published purely as a detection signature — a hit in
  your access logs means the shell was likely *invoked*, not just targeted. Added to
  `iocs/file_paths.txt`, both scanners' log-content checks, the YARA rule, and a new
  Suricata rule flagging it as priority 1 (confirmed invocation, not just an attempt).
- **Exact campaign-marker pair published**: `ss5_457cfa2fb7` (dropper) /
  `ss6_457cfa2fb7_` (recon probe) — added as literal-match checks alongside the
  existing shape-based regex in `iocs/`, both scanners, and the YARA/Suricata rules.
- **Redis non-default-port lesson**: at least one confirmed investigation found Redis
  running on a non-default port (21113, not 6379) — broadened guidance throughout
  (`iocs/file_paths.txt`, `docs/INCIDENT_RESPONSE.md`, both scanners) to read the
  actual host/port out of `app/etc/env.php`'s cache/session blocks rather than
  hardcoding 6379.
- Broadened the `pub/media` web-shell filesystem sweep in both scanners and
  `iocs/file_paths.txt` from a literal `*.php` glob to `*.ph*`, catching `.phtml`/
  `.phar` variants.
- `docs/PATCHING.md`: added concrete patch-application commands (`patch -p1`/`-p2`,
  Quality Patches Tool syntax, a Cloud `m2-hotfixes` workflow note, and a
  `vendor/bin/magento-patches status` verification command), plus curl-based
  edge/WAF-rule verification steps and an explicit caution against
  `bin/magento module:disable Magento_GraphQl` as a substitute mitigation.
- New `mitigations/cloudflare_waf_rules.md`: Cloudflare WAF custom-rule expressions
  for GraphQL blocking, `styles`-argument-scoped blocking, and PHP-execution blocking
  under `pub/media`/`pub/static`, for stores that front Magento with Cloudflare —
  referenced from `mitigations/README.md` and the top-level README.

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
