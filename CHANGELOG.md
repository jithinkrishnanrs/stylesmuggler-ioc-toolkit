# Changelog

All notable changes to this toolkit are recorded here. This is an active-incident repo
for a vulnerability with no CVE and no vendor patch yet — expect frequent updates.

## [Unreleased]
- Watching for: CVE assignment, official Adobe patch, and any further trigger-header /
  UA / hash variants beyond the two waves already observed on 2026-09-05.

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
