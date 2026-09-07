# Timeline

All times as reported by the cited sources; treat UTC/local labeling as approximate
where the source didn't specify.

| Date | Event |
|---|---|
| 2026-09-04, ~22:20 UTC | First confirmed exploitation observed (per Sansec). |
| 2026-09-04, 22:40 UTC | Sansec identifies the campaign. |
| 2026-09-05, early morning | Sansec Shield rules go live for its customers. |
| 2026-09-05 | Second, independent live infection confirmed by community incident responders; a third store targeted but not successfully exploited. |
| 2026-09-05 | Sansec publishes the "StyleSmuggler" advisory as a developing investigation. |
| 2026-09-05, afternoon (~17:08 CEST) | Second exploitation wave observed, predominantly from a single new source IP; attacker trigger-header format changes (`X-TRACE-<10hex>` → `X-<12hex>`), user-agent version changes (`python-requests 2.15.0` → `python-requests/2.32.4`). |
| 2026-09-05 | Sansec ships eComscan 1.9.7 with signatures for the implant. |
| 2026-09-06 | Multiple security outlets (The Hacker News and others) republish/summarize the advisory. Adobe has issued no CVE, patch, or official workaround as of this date. |
| 2026-09-08 (scheduled, not confirmed) | Adobe's next regularly scheduled Commerce security bulletin. Not confirmed to address StyleSmuggler. |

## How to keep this current

If you're maintaining a fork of this repo during the live incident:
- Add new rows with a source link for each entry.
- Note explicitly when an IOC (hash, header format, UA string, source IP) supersedes or
  adds to a previous one — don't silently overwrite; the shape has already changed once
  and attackers are clearly iterating.
- Once Adobe assigns a CVE and ships a patch, update `README.md`'s status table and add
  a "Patched" milestone here with the version and bulletin link.
