#!/usr/bin/env bash
#
# clean_crontab.sh — StyleSmuggler persistence cleanup, ONE STEP of the incident
# response process. Do NOT run this until you've:
#   1. Captured evidence (docs/INCIDENT_RESPONSE.md, step 2)
#   2. Confirmed you're ready to eradicate in order: persistence -> process -> binary
#
# This script ONLY touches cron. It does not kill processes or delete the implant
# binary — do that immediately after, per the playbook, then re-run this script again
# after a full cron cycle to confirm the entry doesn't re-appear.
#
# Usage:
#   sudo bash clean_crontab.sh <username> [--apply]
#
# Without --apply, this only shows what it WOULD remove (dry run, default and safe).

set -euo pipefail

USER_TO_CLEAN="${1:-}"
APPLY=0
[[ "${2:-}" == "--apply" ]] && APPLY=1

if [[ -z "$USER_TO_CLEAN" ]]; then
  echo "Usage: sudo bash clean_crontab.sh <username> [--apply]" >&2
  exit 2
fi

if [[ $EUID -ne 0 ]]; then
  echo "This must be run as root to read/write another user's crontab spool." >&2
  exit 2
fi

SPOOL="/var/spool/cron/crontabs/$USER_TO_CLEAN"
if [[ ! -f "$SPOOL" ]]; then
  echo "No crontab spool file found for user '$USER_TO_CLEAN' at $SPOOL"
  exit 0
fi

PATTERN='gvfsd|\.kw_'
MATCHES=$(grep -cE "$PATTERN" "$SPOOL" || true)

if [[ "$MATCHES" -eq 0 ]]; then
  echo "No StyleSmuggler-pattern cron entries found in $SPOOL."
  exit 0
fi

echo "Found $MATCHES matching line(s) in $SPOOL:"
grep -nE "$PATTERN" "$SPOOL" || true
echo

if [[ $APPLY -eq 0 ]]; then
  echo "Dry run only — no changes made. Re-run with --apply to remove these lines."
  echo "Reminder: this implant has been observed writing directly to the spool file and"
  echo "re-appending itself within ~1 second if the process/binary aren't cleaned first."
  echo "Follow docs/INCIDENT_RESPONSE.md's order: persistence -> process -> binary -> re-check."
  exit 1
fi

BACKUP="${SPOOL}.stylesmuggler-backup.$(date +%s)"
cp "$SPOOL" "$BACKUP"
echo "Backed up original spool file to $BACKUP"

grep -vE "$PATTERN" "$SPOOL" > "${SPOOL}.tmp" && mv "${SPOOL}.tmp" "$SPOOL"
chmod 600 "$SPOOL"
chown "$USER_TO_CLEAN":crontab "$SPOOL" 2>/dev/null || true

echo "Removed matching lines from $SPOOL."
echo
echo "NEXT STEPS (do not skip):"
echo "  1. Kill the [kworker/u:8:0]-masquerading process now, if you haven't already."
echo "  2. Remove ~/.local/share/.gvfsd/ and /tmp/.kw_* / /tmp/.gvfsd_* for this user."
echo "  3. Re-run this script (without --apply) after a full cron cycle (5-10+ min) to"
echo "     confirm the entry has not been re-added."
