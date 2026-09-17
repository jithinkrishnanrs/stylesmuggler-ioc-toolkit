# Indicators of compromise

| File | Contents |
|---|---|
| [`hashes.sha256`](hashes.sha256) | SHA-256 of the Rust implant across all three known builds (`gvfsd-user`, `fc-cache` v2.1.4, `chronyd` v2.1.5) — 7 hashes, including an in-memory variant that differs from the on-disk sample — plus the second attacker's PHP web-shell dropper hash |
| [`domains.txt`](domains.txt) | C2 / malware-download / exfiltration domains, including the NTP-shaped `fc-cache`/`chronyd` build C2, IP-lookup-service call-outs, and the second attacker's DNS-exfil canary (`oast.site`) |
| [`ips.txt`](ips.txt) | C2/download IPs (TCP and the newer UDP/123 IP-based C2), 7 confirmed attacker source addresses, and a residential-proxy pool list (do not blanket-block the latter) |
| [`file_paths.txt`](file_paths.txt) | Filesystem persistence (including newer filename variants and non-default persistence like systemd timers/PHP auto-prepend hooks), cron entries and schedules, process masquerade (all 3 Rust-implant builds), poisoned-log locations, request/response signatures, all confirmed delivery/detonation vectors, the vulnerable sink file, the early-warning email pattern, database forensic queries, the second attacker's web-shell path/auth-gate header/exact campaign markers, and the third toolkit's framework-file tampering signature |
| [`yara/stylesmuggler.yar`](yara/stylesmuggler.yar) | YARA rules: known hashes (all builds, all three campaigns), string heuristics, response-marker regex (both the hex-shaped and fixed-string `MG`-prefixed families), second-attacker web-shell/auth-header/campaign-marker rule, third-toolkit framework-RFI rule |
| [`suricata/stylesmuggler.rules`](suricata/stylesmuggler.rules) | Network IDS rules for C2 traffic (TCP and NTP-shaped UDP/123), exploit request shapes, the second attacker's DNS-exfil/recon-probe/web-shell-invocation patterns, the execution-without-email chain's markers/parameter, and the third toolkit's gating cookie |
| [`hunting/`](hunting/) | Behavioral, EDR/SIEM-based retrospective hunting artifacts (Velociraptor VQL, a Sigma rule) — for finding variants this repo's literal-string indicators don't name yet |

All of the above are consumed automatically by `../scripts/stylesmuggler_scan.sh` and
`../scripts/stylesmuggler_scan.py` where applicable (hashes, cron/process patterns,
poisoned-log markers including exact campaign markers, both marker families, and the
web-shell auth header, the `pub/media` web-shell sweep, and the third toolkit's
framework-file and transient-artefact checks). The `hunting/` artifacts are used with
external tooling (Velociraptor, a Sigma-compatible SIEM/EDR) rather than these scripts.

## Provenance

Compiled from Sansec's advisory (published 2026-09-05, continuously updated; page
modified timestamp confirmed through at least 2026-09-16 06:42 UTC), Adobe's Security
Bulletins APSB26-146 and APSB26-138, and community incident-response reporting on
independently confirmed live infections. See `../docs/VULNERABILITY.md` for full
sourcing and caveats.

## Status: CVE-2026-75650, official patch shipped, but this data will still go stale

Adobe assigned **CVE-2026-75650** and shipped an official hotfix (**VULN-39341** /
**APSB26-146**, plus the separately-required **APSB26-138**) on 2026-09-07/08 — see
`../docs/PATCHING.md`. That closes the underlying vulnerability for covered versions,
but does **not** invalidate these indicators: patching stops new exploitation, it
doesn't clean an existing backdoor or web shell, and stores on uncovered versions
remain exploitable. **At least three independent toolkits are now confirmed exploiting
this same entry point** — the Rust implant, an unrelated PHP web-shell attacker, and
(as of 2026-09-14) a third toolkit that tampers with a core vendor file directly — and
a second, email-independent detonation chain has also been confirmed. The attacker(s)
have already changed the trigger-header format, implant disguise, delivery vector, and
network infrastructure multiple times within days of disclosure. Treat every literal
string here — hashes, headers, domains, IPs, UAs, campaign markers, cookie names — as a
snapshot, not a ceiling. Where the scripts in `../scripts/` let you match a *shape*
(regex) instead of a literal value, they do; prefer that when writing your own
detections against this data too.

If you find a variant not listed here, please open an issue or PR — see the
Contributing section in the top-level README.
