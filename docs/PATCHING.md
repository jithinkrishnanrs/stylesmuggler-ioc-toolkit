# Patching CVE-2026-75650 (StyleSmuggler)

Adobe published an official fix on **2026-09-07 at 20:20 UTC**. If you haven't applied
it yet, this is now your top priority — ahead of the interim mitigations in
[`../mitigations/`](../mitigations/), which were only ever a stopgap for the period
before a real fix existed.

## Identifiers

| | |
|---|---|
| CVE | CVE-2026-75650 |
| Adobe bulletin | [APSB26-146](https://helpx.adobe.com/security/products/magento/apsb26-146.html) |
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
3. Some third parties (e.g. scandiweb, per public reporting) have built unofficial
   backports covering older EOL lines (reportedly as far back as 2.2.0). This repo does
   **not** redistribute or endorse any specific third-party patch — evaluate the
   source, test thoroughly on staging, and understand you're trusting an unofficial
   reconstruction of a fix for a CVSS 10.0 RCE. Search for current options rather than
   relying on any link here going stale.

## Getting the official hotfix

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

### Community delivery packages

Because Adobe ships VULN-39341 as raw patch files rooted at the Magento project (not as
a normal per-package Composer patch), it doesn't apply cleanly through
`cweagans/composer-patches` out of the box for every project layout. Community members
(notably the Disrex Group) have published Composer-installable wrapper packages that
repackage Adobe's *official* patch content for easier application:

- `disrex/stylesmuggler-adobe-patches` — for standard Magento 2.4.9-line projects.
- `disrex/stylesmuggler-adobe-patches-mageos` — for Mage-OS projects on the equivalent
  release line.

These packages carry Adobe's own patch content (not MIT-licensed — the wrapper tooling
is, the patch itself isn't), applied via `cweagans/composer-patches`. If you use one,
treat it the same as any third-party dependency: check who publishes it, pin the
version, and verify the resulting diff matches what Adobe's own KB describes before
trusting it in production. This repo does not vouch for any specific third-party
package beyond noting it exists and is a commonly cited option in the response
community as of this writing.

## If you had an interim/community containment patch installed

Some responders shipped their own stopgap code changes before Adobe's official fix
existed — commonly touching two things:

- `PaymentFailuresService::handle()`, returning before rendering (disabling the
  failed-payment email entirely as a side effect, while the interim patch was in place).
- The logging handler that writes `var/log/system.log`, adding escaping for PHP open
  tags on the formatted line so a poisoned log file can't be `include()`d as PHP even
  if the DI scanner reaches it.

**These interim patches are superseded by Adobe's official hotfix.** If you applied
one, plan to revert it before or as part of applying VULN-39341, rather than stacking
an unofficial patch under an official one — test the transition on staging. Re-enable
the failed-payment email once you've confirmed the official patch is in place and
verified (see below), if you disabled it as part of an interim patch.

## Verifying the patch is actually applied

The vulnerable code lives in Magento's dependency-injection code scanner, specifically
`setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php`. If your interim
mitigation tooling left a marker comment behind, you can check for it (adjust the
string to whatever your specific tooling used):

```bash
grep -c 'StyleSmuggler mitigation' \
  setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
```

More generally: after applying the official hotfix, re-run the compromise scanner
([`../scripts/stylesmuggler_scan.sh`](../scripts/stylesmuggler_scan.sh) or `.py`) and
confirm your patch management tooling (Quality Patches Tool / composer-patches) reports
VULN-39341 as applied. Then exercise the vulnerable path in a controlled way on
staging — trigger a test "failed payment" email and confirm it renders normally rather
than executing anything unexpected — before considering the fix verified in production.

## Patching does not clean an existing compromise

If your store was exploited before you patch, applying the hotfix stops *new*
exploitation — it does not remove a backdoor, web shell, or rogue admin account that's
already there. Run the compromise scanner and follow
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) **regardless of whether or when you
patch.** Patch first if you're not yet compromised (or don't know); if you find
evidence of compromise, follow the incident-response evidence-preservation steps before
you start changing things, including before applying the hotfix on that specific host.
