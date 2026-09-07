# StyleSmuggler IOC Toolkit

Community indicators-of-compromise, a compromise scanner, and interim mitigation rules
for **StyleSmuggler** — the unauthenticated, unpatched Magento Open Source / Adobe Commerce
RCE zero-day disclosed by [Sansec](https://sansec.io/research/stylesmuggler) on
**September 5, 2026**, with in-the-wild exploitation confirmed from **September 4, 2026**.

> **This is a defensive toolkit only.** It contains detection signatures, a compromise
> scanner, and hardening/blocking rules built from published, first-hand incident reports.
> It does **not** contain exploit code, a proof-of-concept trigger, or anything that
> generates the attack payload. If you are looking for that, you are in the wrong repo —
> go patch and hunt instead.

## Status as of this writing

| | |
|---|---|
| Vulnerability | StyleSmuggler (unofficial name, coined by Sansec) |
| Vendor | Adobe (Magento Open Source, Adobe Commerce) |
| CVE | **None assigned yet** |
| Official patch | **None yet** — Adobe's next scheduled Commerce bulletin is Sept 8, 2026 (not confirmed to address this) |
| Authentication required | **None** — unauthenticated |
| Affected versions | All current versions, reproduced by Sansec on clean Magento Open Source 2.4.7, 2.4.8, 2.4.9; first confirmed victim ran 2.4.6-p15 fully patched |
| Exploitation | Active since 2026-09-04 22:20 UTC |
| Impact | Remote code execution → persistent Rust-based backdoor, Redis session harvesting |

**This information changes fast.** Cross-check against the primary source before acting:
[sansec.io/research/stylesmuggler](https://sansec.io/research/stylesmuggler). See
[`docs/TIMELINE.md`](docs/TIMELINE.md) for a running log and cite your sources when you
update anything here.

## What StyleSmuggler actually is

Magento's own GraphQL `styles` parameter and its dependency-injection based file scanning
are abused as a two-stage, file-based deferred-execution primitive rather than a single
obvious injection point:

1. **Poison.** Attacker-controlled data reaches a Magento-generated log or report file
   (`var/log/system.log` via an invalid store code that Magento logs verbatim, or
   `var/report/<hash>`), smuggled in through the GraphQL `styles[]` parameter or a mutated
   request header.
2. **Detonate.** The attacker triggers Magento's standard **"Payment Transaction Failed
   Reminder"** email. Rendering that email walks a code path that lets Magento's own
   DI/code scanner `include()` the poisoned file, running the attacker's PHP. You do not
   need to open the email — rendering it server-side is enough — and the chain can fire
   even when mail delivery itself fails.

See [`docs/VULNERABILITY.md`](docs/VULNERABILITY.md) for the full technical writeup and
sourcing, and [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) for what to do if
the scanner finds something.

## Quick start — am I compromised?

```bash
git clone https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit.git
cd stylesmuggler-ioc-toolkit
sudo bash scripts/stylesmuggler_scan.sh --magento-root /var/www/html
```

Or the Python version for structured (JSON/SARIF-ish) output, e.g. for feeding a SIEM:

```bash
sudo python3 scripts/stylesmuggler_scan.py --magento-root /var/www/html --json report.json
```

Both scripts are **read-only by default** — they detect and report, they don't kill
processes or delete files unless you pass `--remediate`, because premature cleanup
destroys forensic evidence (see the incident response doc).

## What the scanner checks

- Known **filesystem persistence** artifacts (`~/.local/share/.gvfsd/gvfsd-user`, lock
  files, `/tmp/.kw_*`, `/tmp/.gvfsd_*`)
- The **self-restoring crontab** entries the implant writes directly to the cron spool
- A **masquerading process** named `[kworker/u:8:0]` that is *not* owned by root
- **SHA-256** of on-disk binaries *and* of the live `/proc/<pid>/exe` image (the two can
  differ — the implant has been observed updating itself in memory)
- **Poisoned log/report files** (`var/log/system.log`, `var/report/`) for injected PHP
  and for the two known trigger-header shapes (`X-TRACE-<10hex>` and `X-<12hex>`)
- **Proof-of-execution response markers** (`MG<20hex>::...::/MG<20hex>`) left behind in
  logs when the payload actually ran
- Established connections to the **published C2/download hosts**, and anomalous local
  Redis connection counts (session-harvesting has been observed entirely over
  `127.0.0.1:6379`, with **zero outbound C2 traffic** — a quiet network is not a clean one)

Full indicator list with sourcing: [`iocs/`](iocs/).

## Mitigation while there is no patch

There is no official fix yet. Until there is:

1. Put a WAF in front of the store (commercial or the sample rules in
   [`mitigations/`](mitigations/) as a stopgap).
2. If your storefront/integrations don't need it, **block public access to GraphQL**
   entirely — see [`mitigations/nginx_block_graphql_styles.conf`](mitigations/nginx_block_graphql_styles.conf)
   and [`mitigations/apache_block_graphql_styles.conf`](mitigations/apache_block_graphql_styles.conf).
   If you *do* need GraphQL, those files also include a narrower rule that only blocks
   requests carrying a `styles` argument.
3. Add the [fail2ban filter](mitigations/fail2ban_stylesmuggler.conf) and/or
   [ModSecurity rules](mitigations/modsecurity_stylesmuggler.conf) to catch the trigger
   header and response-marker shapes even if the exact bytes change again (they already
   have once — see the changelog in `iocs/`).
4. Run the scanner **today**, before you patch — patching doesn't clean an already-dropped
   backdoor.
5. Rotate all Magento admin/API credentials if the scanner finds anything, even if you
   see no evidence the backdoor was used.

None of this is a substitute for an official Adobe patch once one ships. Track it and
apply it.

## Repo layout

```
docs/                    Vulnerability writeup, timeline, IR playbook
iocs/                    Hashes, IPs, domains, file paths, YARA, Suricata/IDS rules
scripts/                 stylesmuggler_scan.sh / .py, crontab cleanup helper
mitigations/             nginx / Apache / ModSecurity / fail2ban rules
```

## Sourcing and provenance

Every indicator in this repo traces back to a cited, published source — primarily the
Sansec advisory and community incident-response write-ups from responders who handled
live infections on 2026-09-05. See the citation at the bottom of each file in `iocs/`.
**Do not** treat anything here as exhaustive or final — this is an active, developing
incident with no CVE and no vendor patch yet. IOCs (especially the trigger header and
user-agent strings) have already changed once within 24 hours of disclosure; expect them
to change again. Match shapes and behavior, not just literal strings, wherever the
scripts let you.

## Contributing

Seen a variant, a new hash, a new source address, or a false positive? Open an issue or
PR with what you observed and how you observed it. Please:
- Redact your own organization's identifying details before sharing.
- Don't post exploit payloads or working trigger requests here — indicators and
  detection logic only.
- Report the underlying vulnerability itself to [Sansec](https://sansec.io/contact) and
  Adobe PSIRT, not to this repo.

## License

MIT for the code in this repo (see [`LICENSE`](LICENSE)). Indicator data is provided
"as is" for defensive use, with sourcing noted throughout.

## Disclaimer

This is unofficial, community-built defensive tooling, not an Adobe or Sansec product,
and is not affiliated with either. It is provided without warranty. There is currently
no CVE identifier and no official vendor patch for this issue — check
[Adobe's security bulletins](https://helpx.adobe.com/security/products/magento.html)
before assuming any release addresses it.
