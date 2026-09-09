# Indicators of compromise

| File | Contents |
|---|---|
| [`hashes.sha256`](hashes.sha256) | SHA-256 of the Rust implant across all three known builds (`gvfsd-user`, `fc-cache` v2.1.4, `chronyd` v2.1.5) — 6 hashes total, including an in-memory variant that differs from the on-disk sample |
| [`domains.txt`](domains.txt) | C2 / malware-download / exfiltration domains, including the NTP-shaped `fc-cache`/`chronyd` build C2, IP-lookup-service call-outs, and the second attacker's DNS-exfil canary (`oast.site`) |
| [`ips.txt`](ips.txt) | C2/download IPs, confirmed attacker source addresses, and a residential-proxy pool list (do not blanket-block the latter) |
| [`file_paths.txt`](file_paths.txt) | Filesystem persistence, cron entries, process masquerade (all 3 Rust-implant builds), poisoned-log locations, request/response signatures, both delivery vectors, the vulnerable sink file, the early-warning email pattern, and the second attacker's web-shell path/campaign markers |
| [`yara/stylesmuggler.yar`](yara/stylesmuggler.yar) | YARA rules: known hashes (all builds), string heuristics, response-marker regex, second-attacker web-shell/campaign-marker rule |
| [`suricata/stylesmuggler.rules`](suricata/stylesmuggler.rules) | Network IDS rules for C2 traffic (including NTP-shaped UDP/123), exploit request shapes, and the second attacker's DNS-exfil/recon-probe patterns |

All of the above are consumed automatically by `../scripts/stylesmuggler_scan.sh` and
`../scripts/stylesmuggler_scan.py` where applicable (hashes, cron/process patterns,
poisoned-log markers, and the `pub/media` web-shell sweep).

## Provenance

Compiled from Sansec's advisory (published 2026-09-05, updated through at least
2026-09-07 20:50 UTC), Adobe's Security Bulletin APSB26-146, and community
incident-response reporting on independently confirmed live infections. See
`../docs/VULNERABILITY.md` for full sourcing and caveats.

## Status: CVE-2026-75650, official patch shipped, but this data will still go stale

Adobe assigned **CVE-2026-75650** and shipped an official hotfix (**VULN-39341** /
**APSB26-146**) on 2026-09-07 — see `../docs/PATCHING.md`. That closes the underlying
vulnerability for covered versions, but does **not** invalidate these indicators:
patching stops new exploitation, it doesn't clean an existing backdoor or web shell,
and stores on uncovered versions remain exploitable. The attacker(s) have already
changed the trigger-header format, implant disguise, and delivery vector multiple times
within days of disclosure — including a second, entirely unrelated attacker joining on
day 3. Treat every literal string here — hashes, headers, domains, UAs, campaign
markers — as a snapshot, not a ceiling. Where the scripts in `../scripts/` let you match
a *shape* (regex) instead of a literal value, they do; prefer that when writing your own
detections against this data too.

If you find a variant not listed here, please open an issue or PR — see the
Contributing section in the top-level README.
