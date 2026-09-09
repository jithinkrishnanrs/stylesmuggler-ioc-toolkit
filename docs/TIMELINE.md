# Timeline

All times as reported by the cited sources; treat UTC/local labeling as approximate
where the source didn't specify.

| Date / time | Event |
|---|---|
| 2026-09-04, 22:20 UTC | First confirmed StyleSmuggler exploitation, worldwide (per Sansec). |
| 2026-09-04, 23:10 UTC | eComscan flags the implant on unrelated stores (~50 min after first confirmed exploitation). |
| 2026-09-04, 22:40 UTC | Sansec identifies the campaign. |
| 2026-09-05 | Sansec reproduces the full unauthenticated chain on clean Magento Open Source 2.4.7, 2.4.8, and 2.4.9. |
| 2026-09-05, 07:15 UTC | Sansec Shield begins blocking StyleSmuggler exploitation attempts for its customers. |
| 2026-09-05 | Second, independent live infection confirmed by community incident responders; a third store targeted but not successfully exploited. |
| 2026-09-05 | Sansec publishes the "StyleSmuggler" advisory as a developing investigation. |
| 2026-09-05, afternoon (~17:08 CEST) | Second exploitation wave observed, predominantly from a single new source IP; attacker trigger-header format changes (`X-TRACE-<10hex>` → `X-<12hex>`), user-agent version changes (`python-requests 2.15.0` → `python-requests/2.32.4`). |
| 2026-09-05 | Sansec ships eComscan 1.9.7 with signatures for the implant. |
| 2026-09-05/06 | A second, independent exploitation vector confirmed: a merchant's session-storage mitigation (moving off Redis) was bypassed 8 seconds later by the same operator using a file uploaded via Magento's customer custom options feature. |
| 2026-09-06 | Multiple security outlets (The Hacker News and others) republish/summarize the advisory. Adobe has issued no CVE, patch, or official workaround as of this date. |
| 2026-09-06 | Implant renames itself to `fc-cache`, version 2.1.4; NTP-shaped UDP/123 C2 (`ntp.timesync.to` + fallbacks) identified. |
| 2026-09-07 | A second, unrelated attacker observed dropping a PHP web shell via the same StyleSmuggler entry point — independent of the Rust implant operator. |
| 2026-09-07, 17:30 UTC | The same unrelated actor probes a 2.4.7-p10 store for `pub/media` write access (the "recon probe," exfiltrating over DNS to an `oast.site` canary domain). |
| 2026-09-07 | Implant renames itself to `chronyd`, version 2.1.5 — same agent ID as the `fc-cache` build, redeployed. |
| 2026-09-07, 20:20 UTC | **Adobe publishes Security Bulletin APSB26-146 and hotfix VULN-39341 for CVE-2026-75650.** Priority 1, CVSS 10.0. Official fix now available (with limited version coverage — see `PATCHING.md`). |
| 2026-09-07, 20:50 UTC | Sansec's advisory last confirmed updated as of this writing, reflecting the CVE assignment and second-attacker findings. |

## How to keep this current

If you're maintaining a fork of this repo during the ongoing patch-adoption/cleanup
period:
- Add new rows with a source link for each entry.
- Note explicitly when an IOC (hash, header format, UA string, source IP, campaign
  marker) supersedes or adds to a previous one — don't silently overwrite; the shape
  has already changed multiple times and at least two unrelated attackers are clearly
  iterating.
- Track patch-adoption milestones too: whether Adobe extends official coverage to older
  versions, whether new exploitation waves target unpatched stores post-disclosure, and
  whether the second, unrelated attacker's tooling evolves.
