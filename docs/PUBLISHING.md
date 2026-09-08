# Publishing this as a GitHub repo

This toolkit is a plain local directory with git already initialized (see below). To
put it on GitHub:

```bash
cd stylesmuggler-ioc-toolkit

# If you downloaded this as a zip rather than getting it with git history already,
# initialize it first:
git init
git add .
git commit -m "Initial StyleSmuggler IOC toolkit"

# Create the repo on GitHub (requires the gh CLI and prior `gh auth login`):
gh repo create stylesmuggler-ioc-toolkit --public --source=. --remote=origin --push

# ...or without gh: create an empty repo at github.com/new named
# "stylesmuggler-ioc-toolkit", then:
git remote add origin git@github.com:<your-username>/stylesmuggler-ioc-toolkit.git
git branch -M main
git push -u origin main
```

## Suggested repo settings once it's up

- **Topics/tags:** `magento`, `adobe-commerce`, `stylesmuggler`, `ioc`, `incident-response`,
  `security`, `0day`
- **About:** "Community IOC toolkit and compromise scanner for StyleSmuggler, the
  unpatched Magento/Adobe Commerce RCE 0-day (Sansec, Sept 2026)."
- Enable **Issues** so others can report new variants/false positives (see
  Contributing in the top-level README).
- Consider a `SECURITY.md` pointing researchers to Sansec and Adobe PSIRT for the
  underlying vulnerability, and to your own issue tracker only for toolkit bugs.
- Pin `docs/TIMELINE.md` and `iocs/README.md` updates to the top of your README's
  status table as the incident develops — this is explicitly a living document while
  there's no CVE or patch.
