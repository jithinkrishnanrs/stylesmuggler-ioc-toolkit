# Changelog

All notable changes to this toolkit are recorded here. This is an active-incident repo
for a vulnerability with no CVE and no vendor patch yet — expect frequent updates.

## [Unreleased]
- Watching for: CVE assignment, official Adobe patch, and any further trigger-header /
  UA / hash / process-masquerade variants beyond the three implant disguises observed
  so far (`gvfsd-user` → `fc-cache` → `chronyd`).

## 2026-09-07 — second exploitation vector, two new backdoor variants
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
- New `docs/FAQ.md` — quick, sourced answers for common questions (CVE status, patch
  status, "am I safe if patched", the Redis-migration-doesn't-help finding, etc.).
- `docs/INCIDENT_RESPONSE.md`: expanded credential-rotation guidance (flush sessions,
  rotate `app/etc/env.php` crypt/key and all credentials, check for rogue `admin_user`
  entries and dropped webshells under `pub/media/`/`pub/static/`/theme directories)
  sourced from community cleanup guides, not just the original advisory.
- Removed `docs/PUBLISHING.md` (repo-specific publishing instructions, no longer needed
  now that the repo is live at
  [github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit](https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit)).
- Adobe Enterprise Support confirmed Sept 7 that a fix is in progress (no date, no CVE
  yet) — reflected in the status table.

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
  or rate-limiting the GraphQL `styles[]` delivery vector while there is no patch.
- `docs/`: vulnerability technical summary, timeline, incident-response playbook.

### Known limitations at this release
- No CVE exists yet; all version/impact claims trace to Sansec's advisory and named
  community responders, not to an authoritative vendor bulletin.
- The trigger-header format has already changed once within 24 hours of disclosure
  (`X-TRACE-<10hex>` → `X-<12hex>`); treat all literal-string signatures in this repo as
  likely to need updating again, and prefer the shape-based / behavioral checks over
  any single string match.
- Network-based detection (Suricata rules, fail2ban) cannot catch infections that make
  no outbound C2 connection at all — at least one confirmed case harvested Magento
  session data entirely over local Redis with zero external traffic. Always pair
  network rules with the host-based scanner.
