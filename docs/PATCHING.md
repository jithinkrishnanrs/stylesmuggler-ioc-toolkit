# Patching CVE-2026-75650 (StyleSmuggler)

Adobe published an official fix on **2026-09-07 at 20:20 UTC**. If you haven't applied
it yet, this is now your top priority — ahead of the interim mitigations in
[`../mitigations/`](../mitigations/), which were only ever a stopgap for the period
before a real fix existed.

> **You also need Adobe's regular September 2026 update.** Adobe released its scheduled
> monthly Commerce security update, **APSB26-138**, on **2026-09-08** — separately from
> the StyleSmuggler hotfix. Adobe's own guidance is that **VULN-39341 must be applied in
> addition to APSB26-138**, not instead of it. Applying only one of the two leaves you
> exposed. Check both bulletins and apply both.

## Identifiers

| | |
|---|---|
| CVE | CVE-2026-75650 |
| Adobe bulletin (StyleSmuggler-specific) | [APSB26-146](https://helpx.adobe.com/security/products/magento/apsb26-146.html) |
| Adobe's regular September 2026 update | **APSB26-138** (released 2026-09-08) — apply this **in addition to** VULN-39341, not instead of it |
| Adobe priority | **Priority 1** (highest — Adobe's guidance is to patch immediately) |
| CVSS 3.1 / 4.0 | **10.0** (Critical) |
| CWE | CWE-1336, Improper Neutralization of Special Elements Used in a Template Engine |
| Internal Adobe reference | VULN-39341 |
| Exploitation status | Confirmed active exploitation in the wild (Adobe's own assessment) |
| Adobe knowledge base | [Commerce APSB26-146 announcement](https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146) |
| Hotfix package | `VULN-39341-composer-patches.zip` |

## Which versions actually get an official fix

**Coverage is not universal — read this before assuming you're covered.**

| Product | Adobe's hotfix covers | No official fix |
|---|---|---|
| Adobe Commerce (incl. B2B, Cloud) | 2.4.4 – 2.4.9 | below 2.4.4 |
| Adobe Commerce B2B | 1.3.3 – 1.5.3 | below 1.3.3 |
| Magento Open Source | **2.4.6 – 2.4.9 only** | 2.4.5 and below |

If your store runs Magento Open Source 2.4.5 or older, **Adobe is not shipping you a
fix**, even though you are just as exploitable as a supported install. Options:

1. Upgrade to a supported version (2.4.6+) — the durable fix, but not instant.
2. Apply the interim mitigations in [`../mitigations/`](../mitigations/) as a stopgap
   while you plan an upgrade — these reduce exposure but do not close the vulnerability.
3. Reported third-party unofficial backports for older EOL lines, per public coverage
   as of this writing (verify current availability yourself, and treat all of the
   caveats below as applying to each):
   - **Scandiweb** has reportedly published **41 version-specific backport patches**
     covering Magento **2.2.0 through 2.4.3-p3**, together with credential-rotation
     guidance.
   - **BigBridge** published a differently-scoped **root-cause** community patch (see
     "Root cause, more precisely" in [`VULNERABILITY.md`](VULNERABILITY.md)) with
     ready-to-apply patches for **2.4.5–2.4.9**, installable via
     `cweagans/composer-patches`.
   - **Graycore**'s `magento2-style-smuggler-patch` module hardens three specific
     points in the chain (the email template `{{block}}` directive, the grid row URL
     generator factory, and Web API fatal-error report escaping) — its own
     documentation is explicit that this is **hardening, not a fix**, and that other
     paths through the vulnerability remain open.
   This repo does **not** redistribute or endorse any specific third-party patch —
   evaluate the source, test thoroughly on staging, and understand you're trusting an
   unofficial reconstruction of a fix for a CVSS 10.0 RCE. Search for current options
   rather than relying on any name or link here going stale.

### If you run Mage-OS

Mage-OS shipped **version 3.5.0** as an emergency security release that ports the
StyleSmuggler hotfix with additional hardening, bundles the equivalent of Adobe's
September APSB26-138 update, and fixes four unrelated bugs. If you're on Mage-OS,
upgrading to 3.5.0 (or later) is very likely your most direct path rather than trying
to apply Adobe's Commerce-specific hotfix package by hand — verify against Mage-OS's
own release notes before assuming version-number parity with what's described here.

## Getting the official hotfix (Adobe Commerce / Magento Open Source)

1. The patch is distributed through Adobe's Magento package repository at
   `repo.magento.com`, as `VULN-39341-composer-patches.zip`. This requires valid Adobe
   Commerce marketplace/repo credentials to download.
2. Adobe's knowledge base article (linked above) documents "How to apply a composer
   patch provided by Adobe" — follow that process. The patch file inside the zip is
   typically named something like `VULN-39341_Hotfix_COMPOSER.patch`.
3. Applying it is normally done via the **Quality Patches Tool** (Adobe's supported
   mechanism for hotfixes) or `cweagans/composer-patches`, depending on how your project
   is set up. If you don't already have one of these tools wired into your Magento
   project, set that up first — it's also how you'll receive future hotfixes faster.

### Typical application steps (standard, non-Cloud project)

Adjust paths/tooling to your actual project layout — this is a common pattern, not a
guarantee it matches yours exactly:

```bash
# 1. Download from repo.magento.com (requires authentication) and inspect first
unzip -l VULN-39341-composer-patches.zip

# 2a. If using Quality Patches Tool:
vendor/bin/magento-patches apply VULN-39341

# 2b. If using cweagans/composer-patches, extract the .patch file and apply directly:
patch -p1 --dry-run < VULN-39341_Hotfix_COMPOSER.patch   # dry run first
patch -p1 < VULN-39341_Hotfix_COMPOSER.patch              # then apply
# (some patch files are rooted one level differently — try -p2 if -p1 rejects cleanly
# applicable hunks; always dry-run before applying for real)

# 3. Recompile/redeploy as your project normally requires after a code change
bin/magento setup:di:compile
bin/magento setup:static-content:deploy -f
bin/magento cache:flush
```

### Adobe Commerce on Cloud infrastructure

Cloud projects typically apply hotfixes through the `.magento/m2-hotfixes` (or
equivalent) directory in your Cloud repository rather than a raw `patch` invocation —
follow Adobe Commerce Cloud's documented hotfix workflow for your project template
rather than the generic steps above, since Cloud deployments have their own build/
deploy pipeline that a manually-applied patch can conflict with.

### Community delivery packages for the official patch

Because Adobe ships VULN-39341 as raw patch files rooted at the Magento project (not as
a normal per-package Composer patch), it doesn't apply cleanly through
`cweagans/composer-patches` out of the box for every project layout. Community members
have published Composer-installable wrapper packages that repackage Adobe's *official*
patch content for easier application — evaluate any such package the same way you
would any third-party dependency: check who publishes it, pin the version, and verify
the resulting diff matches what Adobe's own KB describes before trusting it in
production. This repo does not vouch for any specific third-party package; search for
current options rather than relying on any name here going stale, since new packages
have already appeared and changed within days of the original disclosure.

## Interim application-layer guard modules (pre-official-patch stopgaps)

Separately from wrappers around Adobe's own patch, several independent community
modules were published as **stopgaps before the official fix existed** — install one
only if you cannot yet apply VULN-39341/APSB26-138, and remove it afterward:

- A **Disrex Group** interim application-layer guard module was published as a
  Magento 2 module intended to be removed once Adobe ships a fix — i.e. treat it as
  superseded now that VULN-39341 exists.
- **Graycore**'s `magento2-style-smuggler-patch` (noted above) is explicitly documented
  by its author as hardening only, "not a fix," with other paths through the
  vulnerability remaining open — its own README states a vulnerable store may already
  be compromised and that mitigating the entry point does not remove an existing
  backdoor.

Every one of these interim modules predates, and is superseded by, Adobe's official
hotfix. If you installed one during the gap before Sept 7, plan to remove it as part of
applying the official patch, the same way you would revert a hand-rolled interim patch
(see below).

## If you had an interim/community containment patch installed

Some responders shipped their own stopgap code changes before Adobe's official fix
existed. One documented community mitigation (from the Disrex Group) modifies **three
of Magento's DI code scanners**, including
`setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php`, so they only execute
from the PHP CLI (i.e. during a normal `setup:di:compile` run) rather than also being
reachable through the web-facing render path StyleSmuggler abuses. Other responders
instead patched the failed-payment email handler and the logging layer directly. Verify
which approach (if any) is present on a given host:

```bash
grep -c 'StyleSmuggler mitigation' \
  setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
```

**These interim patches are superseded by Adobe's official hotfix.** If you applied
one, plan to revert it before or as part of applying VULN-39341 (and APSB26-138),
rather than stacking an unofficial patch under an official one — test the transition on
staging. Re-enable the failed-payment email once you've confirmed the official patch is
in place and verified, if you disabled it as part of an interim patch.

## Verifying the patch is actually applied

The vulnerable code lives in Magento's dependency-injection code scanner, specifically
`setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php`. If your interim
mitigation tooling left a marker comment behind, you can check for it (adjust the
string to whatever your specific tooling used):

```bash
grep -c 'StyleSmuggler mitigation' \
  setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
```

If you applied the official hotfix through the Quality Patches Tool, ask it directly
whether VULN-39341 is applied rather than inferring from file contents:

```bash
vendor/bin/magento-patches status | grep -i '39341\|Status'
```

If you're using a WAF/edge rule (see [`../mitigations/`](../mitigations/)) as your
current mitigation while you finish rolling out the official patch, confirm it's
actually live from outside your network:

```bash
curl -I https://your-store.example.com/graphql
# Expect a 403 (or your configured block response) if you're blocking GraphQL

curl -I https://your-store.example.com/
# Expect a normal 200 — confirms the rule didn't also block your storefront
```

More generally: after applying the official hotfix, re-run the compromise scanner
([`../scripts/stylesmuggler_scan.sh`](../scripts/stylesmuggler_scan.sh) or `.py`) and
confirm your patch management tooling (Quality Patches Tool / composer-patches) reports
VULN-39341 as applied. Then exercise the vulnerable path in a controlled way on
staging — trigger a test "failed payment" email and confirm it renders normally rather
than executing anything unexpected — before considering the fix verified in production.

**Avoid `bin/magento module:disable Magento_GraphQl --force` as a substitute for any
of this.** It's more disruptive than an edge/origin block (it can break admin or build
tooling that depends on the module being present) and doesn't get you anything a
properly verified WAF rule or the official patch doesn't already achieve.

## Patching does not clean an existing compromise

If your store was exploited before you patch, applying the hotfix stops *new*
exploitation — it does not remove a backdoor, web shell, or rogue admin account that's
already there. Run the compromise scanner and follow
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) **regardless of whether or when you
patch.** Patch first if you're not yet compromised (or don't know); if you find
evidence of compromise, follow the incident-response evidence-preservation steps before
you start changing things, including before applying the hotfix on that specific host.

## Recommended sequencing after applying the hotfix

Once VULN-39341 (and APSB26-138) are applied and verified:

1. Enable maintenance mode.
2. Suspend cron jobs (`bin/magento cron:disable` or equivalent for your setup) so no
   in-flight cron process reintroduces something you're about to clean up.
3. Run the full incident-response evidence/cleanup process if you found any indicator
   — see [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).
4. **Rotate every secret the site user could have read** — do this after containment,
   not before, since rotating while an attacker still has active execution just exposes
   the new credentials too. Per Adobe's own post-hotfix guidance, this explicitly
   includes: administrator passwords, GraphQL integration tokens, OAuth client secrets,
   payment gateway API credentials, database credentials, SSH keys, and any other API
   keys stored in the application. See Step 4 of
   [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full list and specific
   commands (including the Magento `crypt/key` in `app/etc/env.php`).
5. Re-enable cron and take the store out of maintenance mode once you've verified the
   host is clean.
