# Interim mitigations

| File | Covers |
|---|---|
| [`nginx_block_graphql_styles.conf`](nginx_block_graphql_styles.conf) | Block/rate-limit `/graphql`, block known UA |
| [`apache_block_graphql_styles.conf`](apache_block_graphql_styles.conf) | Same, for Apache/mod_rewrite |
| [`modsecurity_stylesmuggler.conf`](modsecurity_stylesmuggler.conf) | POST-body inspection for `styles[]`, trigger headers, response marker |
| [`fail2ban_stylesmuggler.conf`](fail2ban_stylesmuggler.conf) | Reactive IP banning on exploit-shaped access-log lines |

## Important scope limitation

**These mitigations only cover the GraphQL `styles[]` / log-poisoning delivery path.**
Sansec's advisory (updated 2026-09-05/06) confirmed a **second, independent
exploitation vector**: a file uploaded through Magento's **customer custom options**
feature, which succeeded against a target even after that store had moved session
storage off Redis. None of the configs in this directory address that second vector,
because no specific vulnerable endpoint/parameter for it has been publicly confirmed as
of this writing.

**Do not treat deploying these configs as "patched."** They reduce the attack surface
for one known path. Run the compromise scanner in [`../scripts/`](../scripts/)
regardless of whether you've applied these mitigations, and watch
[sansec.io/research/stylesmuggler-0day](https://sansec.io/research/stylesmuggler-0day)
for updates on the second vector's exact mechanics.

## Recommended order

1. Deploy a real WAF if you have one (commercial or Sansec Shield) — it will adapt to
   new variants faster than static config files in a repo like this one.
2. If not, apply the nginx/Apache config for your web server, plus ModSecurity if
   available for POST-body inspection.
3. Add the fail2ban filter as a reactive backstop.
4. Run the compromise scanner **before and after** applying mitigations — mitigations
   block new exploitation, they don't clean an existing backdoor.
5. Track Adobe's bulletins for an official patch and remove these stopgaps once one
   ships and is applied, since hand-maintained WAF rules drift out of date.
