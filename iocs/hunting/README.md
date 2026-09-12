# Retrospective threat hunting artifacts

For hunting across a fleet, or back through logs/telemetry that predate when you first
ran the compromise scanner. Exploitation began roughly 24 hours before public
disclosure (2026-09-04 22:20 UTC) — a clean scanner result today doesn't rule out
compromise earlier in that window if artifacts have since been cleaned up or a variant
this repo doesn't name yet was used.

| File | Use with |
|---|---|
| [`velociraptor_hunt.vql`](velociraptor_hunt.vql) | [Velociraptor](https://docs.velociraptor.app/) — retrospective filesystem/process/cron hunt across a fleet |
| [`sigma_shell_spawn.yml`](sigma_shell_spawn.yml) | Any Sigma-compatible SIEM/EDR — detects a web server or PHP-FPM process spawning a shell, downloader, or encoder, a durable behavioral signal independent of this specific CVE's named indicators |

Both are read-only detection artifacts — they query/alert, they don't remediate. See
[`../../docs/INCIDENT_RESPONSE.md`](../../docs/INCIDENT_RESPONSE.md) for what to do
with a hit.

## Why behavioral hunting matters here specifically

StyleSmuggler's Rust implant has already cycled through three process-masquerade names
(`[kworker/u:8:0]` → `fc-cache` → `chronyd`) within days of disclosure, and a second,
unrelated attacker joined using entirely different tooling (a PHP web shell) through
the same entry point. Literal-string/hash-based detection — most of what's in
[`../`](../) — will always lag whatever the attacker renames things to next. A
behavioral signal like "a PHP-adjacent process spawned a shell" doesn't care what the
next disguise is named.
