# Indicators of compromise

| File | Contents |
|---|---|
| [`hashes.sha256`](hashes.sha256) | SHA-256 of the implant binary across all three known builds (`gvfsd-user`, `fc-cache`/`chronyd`) — 6 hashes total, including an in-memory variant that differs from the on-disk sample |
| [`domains.txt`](domains.txt) | C2 / malware-download domains, including the NTP-shaped `fc-cache`/`chronyd` build C2 |
| [`ips.txt`](ips.txt) | C2/download IPs, confirmed attacker source addresses, and a residential-proxy pool list (do not blanket-block the latter) |
| [`file_paths.txt`](file_paths.txt) | Filesystem persistence, cron entries, process masquerade (all 3 builds), poisoned-log locations, request/response signatures, second delivery vector, secondary/post-exploitation indicators |
| [`yara/stylesmuggler.yar`](yara/stylesmuggler.yar) | YARA rules: known hashes (all builds), string heuristics, response-marker regex |
| [`suricata/stylesmuggler.rules`](suricata/stylesmuggler.rules) | Network IDS rules for C2 traffic (including NTP-shaped UDP/123) and exploit request shapes |

All of the above are consumed automatically by `../scripts/stylesmuggler_scan.sh` and
`../scripts/stylesmuggler_scan.py` where applicable (currently: `hashes.sha256`).

## Provenance

Compiled from the Sansec advisory (published 2026-09-05, updated since) and community
incident-response reporting on independently confirmed live infections the same day.
See `../docs/VULNERABILITY.md` for full sourcing and caveats.

## This data will go stale

There is no CVE and no vendor patch yet, and the attacker has already changed the
trigger-header format once within 24 hours of disclosure. Treat every literal string
here — hashes, headers, domains, UAs — as a snapshot, not a ceiling. Where the scripts
in `../scripts/` let you match a *shape* (regex) instead of a literal value, they do;
prefer that when writing your own detections against this data too.

If you find a variant not listed here, please open an issue or PR — see the
Contributing section in the top-level README.
