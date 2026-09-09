# Interim and defense-in-depth mitigations

**Adobe shipped an official patch (VULN-39341 / APSB26-146, CVE-2026-75650) on
2026-09-07.** If your Magento/Adobe Commerce version is covered (see
[`../docs/PATCHING.md`](../docs/PATCHING.md)), applying that patch is now your
priority — everything in this directory is either a stopgap for versions Adobe doesn't
cover, a bridge for the time before you can patch, or ongoing defense-in-depth against
the second, unrelated web-shell attacker described below.

| File | Covers |
|---|---|
| [`nginx_block_graphql_styles.conf`](nginx_block_graphql_styles.conf) | Block/rate-limit `/graphql`, block known UA — the main Rust-implant campaign's primary delivery path |
| [`apache_block_graphql_styles.conf`](apache_block_graphql_styles.conf) | Same, for Apache/mod_rewrite |
| [`nginx_block_php_execution_media.conf`](nginx_block_php_execution_media.conf) | Block PHP execution under `pub/media`/`pub/static` — defense against the second, unrelated attacker's web-shell technique |
| [`apache_block_php_execution_media.conf`](apache_block_php_execution_media.conf) | Same, for Apache |
| [`modsecurity_stylesmuggler.conf`](modsecurity_stylesmuggler.conf) | POST-body inspection for `styles[]`, trigger headers, response marker |
| [`fail2ban_stylesmuggler.conf`](fail2ban_stylesmuggler.conf) | Reactive IP banning on exploit-shaped access-log lines |

## Important scope limitations

**None of these configs close the vulnerability itself — only Adobe's official patch
does that.** They reduce specific attack surface:

- The GraphQL-blocking rules cover the `styles[]` / log-poisoning delivery path for the
  main Rust-implant campaign. They do **not** cover the confirmed second, independent
  delivery vector for that same campaign — a file uploaded through Magento's
  **customer custom options** feature, which succeeded even against a target that had
  moved session storage off Redis. No specific vulnerable endpoint/parameter for that
  vector has been publicly confirmed as of this writing.
- They also do **not** cover the second, *unrelated* attacker's delivery mechanism
  (payload smuggled in the `Store:` HTTP header) — only the PHP-execution-blocking
  rules address that attacker, and only by neutralizing where their dropped web shell
  could run, not by stopping the drop itself.
- The PHP-execution-blocking rules are good general Magento hardening independent of
  this specific incident — `pub/media`, `pub/static`, `var`, and `generated` should
  never need to execute PHP on a correctly configured store.

**Do not treat deploying these configs as "patched."** Run the compromise scanner in
[`../scripts/`](../scripts/) regardless of whether you've applied these mitigations,
and watch [Sansec's advisory](https://sansec.io/research/stylesmuggler-0day) and
[Adobe's bulletin](https://helpx.adobe.com/security/products/magento/apsb26-146.html)
for further updates.

## Recommended order

1. **Apply Adobe's official hotfix** if your version is covered — see
   [`../docs/PATCHING.md`](../docs/PATCHING.md). This is the actual fix; everything
   below is a stopgap or supplementary hardening.
2. If you can't patch immediately, or your version isn't covered, deploy a real WAF if
   you have one (commercial or Sansec Shield) — it will adapt to new variants faster
   than static config files in a repo like this one.
3. Otherwise, apply the nginx/Apache GraphQL-blocking config for your web server, plus
   the PHP-execution-blocking config (worth keeping even after patching, as general
   hardening), plus ModSecurity if available for POST-body inspection.
4. Add the fail2ban filter as a reactive backstop.
5. **Run the compromise scanner before and after** applying mitigations or patching —
   none of this cleans an existing backdoor or web shell; see
   [`../docs/INCIDENT_RESPONSE.md`](../docs/INCIDENT_RESPONSE.md).
6. Once you've applied the official patch and verified it (see
   [`../docs/PATCHING.md`](../docs/PATCHING.md)), you can retire the GraphQL-blocking
   stopgap if it's interfering with legitimate use — but consider keeping the
   PHP-execution block in `pub/media`/`pub/static` permanently, since it's sound
   hardening regardless of this specific CVE.
