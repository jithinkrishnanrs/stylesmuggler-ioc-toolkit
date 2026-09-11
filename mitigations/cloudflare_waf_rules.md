# StyleSmuggler / CVE-2026-75650 mitigation — Cloudflare WAF

If your store sits behind Cloudflare, a WAF custom rule is often faster to deploy than
an origin-server config change, and doesn't require a deploy/restart of your web server.

## Option A: block GraphQL entirely (if you don't need it publicly)

In the Cloudflare dashboard: **Security → WAF → Custom rules → Create rule**.

- **Field:** URI Path
- **Expression:** `http.request.uri.path eq "/graphql"`
- **Action:** Block

Equivalent expression if you'd rather write it directly:

```
(http.request.uri.path eq "/graphql")
```

## Option B: narrower rule — block only requests carrying a `styles` argument

If you need GraphQL for legitimate integrations, scope the block to the known delivery
vector instead of the whole endpoint:

```
(http.request.uri.path eq "/graphql" and http.request.uri.query contains "styles")
```

This only covers the query-string form of the `styles[]` delivery vector. Cloudflare's
rules engine has limited visibility into POST body content on standard plans — for
reliable POST-body inspection, pair this with the [ModSecurity rules](modsecurity_stylesmuggler.conf)
at your origin, or a Cloudflare plan tier that supports body inspection if you have one.

## Option C: block PHP-family files under pub/media / pub/static

Defense in depth against the second, unrelated attacker's web-shell technique (see
[`README.md`](../README.md#what-stylesmuggler-actually-is) and
[`../docs/VULNERABILITY.md`](../docs/VULNERABILITY.md)):

```
(http.request.uri.path matches "^/(pub/media|pub/static)/.*\.(php|phtml|phar)$")
```

Action: **Block**.

## Verifying a rule took effect

After publishing any of the above, confirm from outside your network:

```bash
curl -I https://your-store.example.com/graphql
# Expect a 403 (or your chosen block response) if you used Option A

curl -I https://your-store.example.com/
# Expect a normal 200 — confirm the rule didn't also block your storefront
```

## Scope limitation

Same caveat as the origin-server configs in this directory: none of this closes the
underlying vulnerability — only [Adobe's official patch](../docs/PATCHING.md) does
that. These rules reduce specific attack surface and are not a substitute for it, and
none of them address the confirmed second delivery vector for the main Rust-implant
campaign (a file uploaded via Magento's customer custom options feature) or the second,
unrelated attacker's `Store:`-header-based delivery.

## What not to do

Don't reach for `bin/magento module:disable Magento_GraphQl --force` as a mitigation.
Disabling the GraphQL module outright is more disruptive than blocking the endpoint at
the edge (it can break admin/build tooling that depends on the module being present)
and isn't more effective than the WAF/origin rules above, which achieve the same
practical outcome — blocking public access — without touching the application's module
graph.
