# StyleSmuggler / CVE-2026-75650 mitigation — PHP `disable_functions` hardening

This is DEFENSE IN DEPTH, not a fix for the vulnerability itself — see
[`../docs/PATCHING.md`](../docs/PATCHING.md) for the actual patch. The idea: even if an
attacker manages to get PHP code executing through the StyleSmuggler chain (or any
other route), restricting which PHP functions can spawn external processes limits what
that code can actually do — specifically, it can make it harder for a dropper to shell
out and write/execute a separate binary like the Rust implant, or for a web shell to run
arbitrary system commands.

## What to disable

Add to your `php.ini` (or the equivalent PHP-FPM pool config), then restart PHP-FPM:

```ini
disable_functions = proc_open,proc_close,proc_get_status,proc_nice,proc_terminate,shell_exec,exec,system,passthru,popen
```

`proc_open` specifically has been called out in public StyleSmuggler mitigation
guidance as a function worth disabling to block dropper execution. The rest of the
list (`shell_exec`, `exec`, `system`, `passthru`, `popen`, and the other `proc_*`
functions) are standard, broadly-recommended companions to `proc_open` in general PHP
hardening guides — disable them together rather than `proc_open` alone, since an
attacker with code execution can usually reach an equivalent function if only one is
blocked.

## Before you deploy this

**Test on staging first.** Some legitimate Magento functionality — certain deployment
tooling, image-processing libraries that shell out to ImageMagick/GraphicsMagick, some
payment or shipping integrations, and various third-party extensions — may depend on
one or more of these functions. Search your codebase before assuming it's safe to
disable all of them:

```bash
grep -rn 'proc_open\|shell_exec\|passthru\|popen(' app/code vendor --include='*.php' \
  | grep -v '/test/' | grep -v vendor/magento
```

Review any hits (especially outside Magento's own core `vendor/magento` packages,
which generally don't need these) before deploying the restriction to production. If
something legitimate needs one of these functions, either exclude just that function
from the disabled list, or scope the restriction to specific PHP-FPM pools if your
setup uses more than one (e.g., disable it for the pool serving the public storefront,
allow it for a pool used only by CLI/cron/deploy processes that genuinely need it).

## Verifying it's in effect

```bash
php -i | grep disable_functions
# or, for a specific FPM pool:
php-fpm -tt 2>&1 | grep disable_functions
```

## Scope limitation

This does not stop the vulnerability from being triggered, and does not stop a web
shell from doing damage using only PHP-native functionality (reading/writing files,
querying the database, etc. — none of which require `proc_open`). It specifically
targets one *technique* — shelling out to run or write a separate binary — used by
(at least) the Rust-implant dropper described in
[`../docs/VULNERABILITY.md`](../docs/VULNERABILITY.md). Pair this with the other
mitigations in this directory and, most importantly, with
[Adobe's official patch](../docs/PATCHING.md).
