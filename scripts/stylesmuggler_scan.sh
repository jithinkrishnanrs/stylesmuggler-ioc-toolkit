#!/usr/bin/env bash
#
# stylesmuggler_scan.sh — read-only compromise scanner for StyleSmuggler / CVE-2026-75650,
# the Magento / Adobe Commerce RCE (Adobe bulletin APSB26-146, hotfix VULN-39341).
#
# IMPORTANT: applying Adobe's official patch (see docs/PATCHING.md) stops NEW
# exploitation but does not clean an existing compromise. Run this scanner regardless
# of whether you've patched yet.
#
# This script DETECTS ONLY by default. It does not kill processes, remove files, or
# touch cron unless you pass --remediate, because premature cleanup destroys forensic
# evidence (see docs/INCIDENT_RESPONSE.md). Run it as root, or as a user that can read
# every account's home directory and crontab on the box — the implant lives under the
# Magento/site user's home, not root's, and not necessarily the account you're logged
# in as on shared hosting.
#
# This scanner checks for BOTH known campaigns: the Rust-based implant
# (gvfsd-user/fc-cache/chronyd) and the second, unrelated PHP web-shell attacker
# confirmed 2026-09-07. They are independent — clearing one does not mean the other
# isn't present too.
#
# Sources for every check below: docs/VULNERABILITY.md and iocs/. This is a defensive
# tool built from published incident reports — it does not exploit anything.
#
# Usage:
#   sudo bash stylesmuggler_scan.sh [--magento-root /var/www/html] [--home-dir /home/*]
#                                    [--remediate] [--quiet]
#
# Exit codes:
#   0  clean — no indicators found
#   1  suspicious — one or more indicators found, needs human review
#   2  script error (bad args, missing tools, etc.)

set -u
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Defaults / args
# ---------------------------------------------------------------------------
MAGENTO_ROOT=""
HOME_GLOB="/home/*"
REMEDIATE=0
QUIET=0
FINDINGS=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOC_DIR="$(cd "$SCRIPT_DIR/../iocs" 2>/dev/null && pwd || true)"
REPORT_LINES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --magento-root) MAGENTO_ROOT="$2"; shift 2 ;;
    --home-dir)     HOME_GLOB="$2"; shift 2 ;;
    --remediate)    REMEDIATE=1; shift ;;
    --quiet)        QUIET=1; shift ;;
    -h|--help)
      grep '^#' "$0" | sed -n '2,30p' | sed 's/^#//'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

log()  { [[ $QUIET -eq 0 ]] && echo -e "$@"; }
hit()  { FINDINGS=$((FINDINGS+1)); REPORT_LINES+=("$1"); log "  \e[31m[HIT]\e[0m $1"; }
info() { log "  \e[36m[info]\e[0m $1"; }
ok()   { log "  \e[32m[ok]\e[0m $1"; }
section() { log "\n\e[1m== $1 ==\e[0m"; }

if [[ $EUID -ne 0 ]]; then
  log "\e[33mWarning:\e[0m not running as root. Some checks (other users' home dirs, other users' crontabs, /proc/<pid>/exe for processes you don't own) will be incomplete.\n"
fi

log "\e[1mStyleSmuggler / CVE-2026-75650 compromise scanner\e[0m"
log "Built from: Sansec advisory (2026-09-05, updated through 2026-09-07) + Adobe APSB26-146 + community IR."
log "Reference:  https://sansec.io/research/stylesmuggler-0day  |  https://helpx.adobe.com/security/products/magento/apsb26-146.html"
log "Official patch (VULN-39341) exists as of 2026-09-07 — see docs/PATCHING.md. Patching does not clean an existing compromise."
log "This is DETECTION ONLY unless --remediate is passed. See docs/INCIDENT_RESPONSE.md.\n"

# ---------------------------------------------------------------------------
# 1. Filesystem persistence artefacts
# ---------------------------------------------------------------------------
section "Filesystem persistence"

shopt -s nullglob
CANDIDATE_HOMES=($HOME_GLOB /root)
for h in "${CANDIDATE_HOMES[@]}"; do
  [[ -d "$h" ]] || continue

  # gvfsd-user build (first seen 2026-09-04)
  if [[ -e "$h/.local/share/.gvfsd/gvfsd-user" ]]; then
    hit "Implant binary present (gvfsd-user build): $h/.local/share/.gvfsd/gvfsd-user"
  fi
  for lock in "$h"/.local/share/.gvfsd/.gvfsd_*.lock; do
    [[ -e "$lock" ]] && hit "Implant lock file (gvfsd-user build): $lock"
  done

  # fc-cache build (first seen 2026-09-06)
  if [[ -e "$h/.cache/fontconfig/fc-cache" ]]; then
    hit "Implant binary present (fc-cache build): $h/.cache/fontconfig/fc-cache — verify against your distro's real fc-cache path/hash before assuming compromise"
  fi
done

for lock in /tmp/.gvfsd_*.lock; do
  [[ -e "$lock" ]] && hit "Implant lock file (second location, gvfsd-user build): $lock"
done
for kw in /tmp/.kw_*; do
  [[ -e "$kw" ]] && hit "Implant artefact (gvfsd-user build): $kw"
done
for lock in /tmp/.fc_*.lock; do
  [[ -e "$lock" ]] && hit "Implant lock file (fc-cache build): $lock"
done
for chrony in /tmp/.chrony-*; do
  [[ -e "$chrony/chronyd" ]] && hit "Implant binary present (chronyd build): $chrony/chronyd"
done

if [[ $FINDINGS -eq 0 ]]; then
  ok "No known persistence file paths found under checked home directories or /tmp (checked gvfsd-user, fc-cache, and chronyd build locations)."
fi

# ---------------------------------------------------------------------------
# 2. Cron persistence (checks crontab AND the spool file directly — the implant
#    has been observed writing the spool file directly, bypassing `crontab` and the
#    REPLACE audit line that normally generates)
# ---------------------------------------------------------------------------
section "Cron persistence"

CRON_PATTERN='gvfsd|\.kw_|fc-cache|\.fc_|chronyd|\.chrony-'

check_crontab_output() {
  local label="$1" content="$2"
  if echo "$content" | grep -qE "$CRON_PATTERN"; then
    local count
    count=$(echo "$content" | grep -cE "$CRON_PATTERN")
    hit "Malicious cron entry in $label ($count matching line(s)) — see docs/INCIDENT_RESPONSE.md before removing, it self-restores if the process/binary aren't cleaned first"
  fi
}

if command -v crontab >/dev/null 2>&1; then
  if [[ $EUID -eq 0 ]] && [[ -d /var/spool/cron/crontabs ]]; then
    for spool in /var/spool/cron/crontabs/*; do
      [[ -f "$spool" ]] || continue
      user="$(basename "$spool")"
      check_crontab_output "spool file for $user" "$(cat "$spool" 2>/dev/null)"
    done
  else
    check_crontab_output "current user's crontab" "$(crontab -l 2>/dev/null)"
  fi
else
  info "crontab command not found — skipping cron check"
fi

if [[ $FINDINGS -eq 0 ]] || ! printf '%s\n' "${REPORT_LINES[@]}" | grep -q "cron"; then
  :
fi

# ---------------------------------------------------------------------------
# 3. Masquerading process — [kworker/u:8:0], fc-cache, or chronyd that looks wrong
#    (the names alone are legitimate system process/utility names; ownership and/or
#    the real executable path is the tell)
# ---------------------------------------------------------------------------
section "Process masquerade ([kworker/u:8:0], fc-cache, or chronyd)"

SUSPECT_PIDS=()

# --- [kworker/u:8:0]: flag if owned by non-root ---
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  puser=$(awk '{print $1}' <<<"$line")
  ppid=$(awk '{print $2}' <<<"$line")
  pcmd=$(cut -d' ' -f3- <<<"$line")
  if [[ "$puser" != "root" ]]; then
    hit "Process '$pcmd' (PID $ppid) matches known masquerade name but is owned by non-root user '$puser'"
    SUSPECT_PIDS+=("$ppid")
  else
    info "Found $pcmd (PID $ppid) but owned by root — likely a genuine kernel thread, not flagged"
  fi
done < <(ps -eo user:32,pid,comm,args 2>/dev/null | awk '$0 ~ /kworker\/u:8:0/ {print $1, $2, $3, $0}' | awk '{ $1=$1; print $1" "$2" "substr($0, index($0,$4)) }')

# --- fc-cache / chronyd: these are NOT normally long-running daemons owned by a web
# site user. Flag any persistent process by these names whose /proc/<pid>/exe does not
# resolve under a standard system binary directory (/usr, /sbin, /bin, /lib), or that
# is owned by a typical web/app user rather than root/a dedicated system account.
for pname in fc-cache chronyd; do
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    puser=$(awk '{print $1}' <<<"$line")
    ppid=$(awk '{print $2}' <<<"$line")
    pcmd=$(cut -d' ' -f3- <<<"$line")
    real_exe=""
    [[ -r "/proc/$ppid/exe" ]] && real_exe=$(readlink -f "/proc/$ppid/exe" 2>/dev/null)
    if [[ -n "$real_exe" && ! "$real_exe" =~ ^/(usr|sbin|bin|lib) ]]; then
      hit "Process '$pcmd' (PID $ppid, user '$puser') named '$pname' but running from non-system path: $real_exe — matches fc-cache/chronyd build masquerade"
      SUSPECT_PIDS+=("$ppid")
    elif [[ "$puser" != "root" && "$puser" != "chrony" && "$puser" != "_chrony" && "$puser" != "systemd-timesync" ]]; then
      hit "Process '$pcmd' (PID $ppid) named '$pname' owned by unexpected user '$puser' (not root or a standard time-sync/fontconfig account)"
      SUSPECT_PIDS+=("$ppid")
    else
      info "Found $pcmd (PID $ppid) owned by '$puser', exe resolves under a system path — likely genuine, not flagged"
    fi
  done < <(ps -eo user:32,pid,comm,args 2>/dev/null | awk -v p="$pname" '$3 == p {print $1, $2, $3, $0}' | awk '{ $1=$1; print $1" "$2" "substr($0, index($0,$4)) }')
done

if [[ ${#SUSPECT_PIDS[@]} -eq 0 ]]; then
  ok "No suspicious [kworker/u:8:0], fc-cache, or chronyd processes found."
fi

# ---------------------------------------------------------------------------
# 4. Hash checks — on-disk AND in-memory (/proc/<pid>/exe), since observed campaigns
#    have updated the implant in memory such that it differs from the file on disk.
# ---------------------------------------------------------------------------
section "Hash verification"

HASH_FILE="$IOC_DIR/hashes.sha256"
KNOWN_HASHES=()
if [[ -f "$HASH_FILE" ]]; then
  while IFS= read -r h; do
    [[ "$h" =~ ^[0-9a-f]{64}$ ]] && KNOWN_HASHES+=("$h")
  done < <(grep -oE '^[0-9a-f]{64}' "$HASH_FILE" 2>/dev/null)
else
  info "hashes.sha256 not found at $HASH_FILE — skipping hash comparison, checking presence only"
fi

hash_matches_known() {
  local hash="$1"
  for k in "${KNOWN_HASHES[@]}"; do
    [[ "$hash" == "$k" ]] && return 0
  done
  return 1
}

for h in "${CANDIDATE_HOMES[@]}"; do
  bin="$h/.local/share/.gvfsd/gvfsd-user"
  if [[ -f "$bin" ]] && command -v sha256sum >/dev/null 2>&1; then
    diskhash=$(sha256sum "$bin" 2>/dev/null | awk '{print $1}')
    if hash_matches_known "$diskhash"; then
      hit "On-disk binary $bin matches a known StyleSmuggler hash: $diskhash"
    else
      hit "On-disk binary $bin present but hash NOT in known list ($diskhash) — could be a new/updated variant, treat as suspicious"
    fi
  fi
done

for pid in "${SUSPECT_PIDS[@]}"; do
  if [[ -r "/proc/$pid/exe" ]] && command -v sha256sum >/dev/null 2>&1; then
    tmp="/tmp/.stylesmuggler_scan_${pid}.bin"
    if cp "/proc/$pid/exe" "$tmp" 2>/dev/null; then
      memhash=$(sha256sum "$tmp" | awk '{print $1}')
      rm -f "$tmp"
      if hash_matches_known "$memhash"; then
        hit "In-memory image of PID $pid matches known StyleSmuggler hash: $memhash"
      else
        hit "In-memory image of PID $pid does NOT match known hashes ($memhash) — possible updated/new implant build, do not dismiss"
      fi
    else
      info "Could not copy /proc/$pid/exe for PID $pid (permission denied?) — try running as root"
    fi
  fi
done

# ---------------------------------------------------------------------------
# 5. Poisoned log/report files — check BOTH locations, and BOTH header shapes
# ---------------------------------------------------------------------------
section "Poisoned log/report files"

if [[ -n "$MAGENTO_ROOT" && -d "$MAGENTO_ROOT" ]]; then
  TARGETS=("$MAGENTO_ROOT/var/log/system.log" "$MAGENTO_ROOT/var/report")
  for t in "${TARGETS[@]}"; do
    [[ -e "$t" ]] || continue
    # PHP tags landing where they shouldn't
    if grep -rlE '<\?php|<\?=' "$t" 2>/dev/null | grep -q .; then
      hit "Possible PHP injection found in $t — inspect manually before deleting (see docs/INCIDENT_RESPONSE.md)"
    fi
    # Both trigger header families
    if grep -rlE 'X[_-](TRACE[_-])?[0-9A-Fa-f]{10,12}' "$t" 2>/dev/null | grep -q .; then
      hit "Trigger-header artefact found in $t (matches either X-TRACE-<hex> or X-<hex> family)"
    fi
    # Response/execution marker
    if grep -rlE 'MG[0-9a-f]{16,}::' "$t" 2>/dev/null | grep -q .; then
      hit "Execution-proof marker (MG<hex>::...) found in $t — this indicates the payload RAN, not just that it was sent"
    fi
    # Second, unrelated attacker's campaign markers and DNS-exfil canary domain
    if grep -rlE 'ss[56]_[0-9a-f]{10}' "$t" 2>/dev/null | grep -q .; then
      hit "Second-attacker campaign marker (ss5_<hex>/ss6_<hex>) found in $t — this is a SEPARATE, unrelated attacker from the Rust implant; check pub/media for its web shell too"
    fi
    if grep -rlF 'oast.site' "$t" 2>/dev/null | grep -q .; then
      hit "Reference to oast.site (DNS-exfiltration canary domain) found in $t — matches the second attacker's recon-probe pattern"
    fi
  done
  if [[ $FINDINGS -eq 0 ]]; then
    ok "No injected PHP, trigger headers, execution markers, or second-attacker campaign markers found in var/log/system.log or var/report."
  fi

  # Second, unrelated attacker's web shell: pub/media should NEVER contain executable
  # PHP on a correctly configured Magento install.
  if [[ -d "$MAGENTO_ROOT/pub/media" ]]; then
    mapfile -t PHP_IN_MEDIA < <(find "$MAGENTO_ROOT/pub/media" -name '*.php' 2>/dev/null)
    if [[ ${#PHP_IN_MEDIA[@]} -gt 0 ]]; then
      for f in "${PHP_IN_MEDIA[@]}"; do
        hit "PHP file found under pub/media (should never contain executable PHP): $f — matches the second, unrelated attacker's web-shell technique"
      done
    else
      ok "No PHP files found under pub/media."
    fi
  else
    info "pub/media not found under --magento-root — skipping web-shell path check"
  fi
else
  info "No --magento-root given (or path doesn't exist) — skipping log/report content scan and pub/media web-shell check. Re-run with --magento-root /path/to/magento"
fi

# ---------------------------------------------------------------------------
# 6. Network anomalies — published C2 (TCP), NTP-shaped C2 (UDP/123, fc-cache/chronyd
#    build), AND local Redis connection burst (at least one confirmed infection made
#    ZERO outbound connections and instead harvested sessions over 127.0.0.1:6379 —
#    absence of C2 traffic is not evidence of a clean host)
# ---------------------------------------------------------------------------
section "Network"

if command -v ss >/dev/null 2>&1; then
  C2_IPS=("99.84.67.186" "209.141.43.95")
  for ip in "${C2_IPS[@]}"; do
    if ss -tn 2>/dev/null | grep -q "$ip"; then
      hit "Active connection to known C2/download address $ip"
    fi
  done

  # fc-cache/chronyd build beacons over UDP/123 disguised as NTP — check for resolved
  # connections to the known C2 domains if getent/dig is available, since ss won't show
  # a domain name directly.
  NTP_C2_DOMAINS=("ntp.timesync.to" "ntp.synctime.to" "ntp.syncstime.to")
  if command -v getent >/dev/null 2>&1; then
    for d in "${NTP_C2_DOMAINS[@]}"; do
      resolved=$(getent hosts "$d" 2>/dev/null | awk '{print $1}')
      if [[ -n "$resolved" ]] && ss -un 2>/dev/null | grep -q "$resolved"; then
        hit "Active UDP connection to resolved IP of known NTP-shaped C2 domain $d ($resolved)"
      fi
    done
  fi
  udp123_count=$(ss -un 2>/dev/null | grep -c ':123 ')
  if [[ "$udp123_count" -gt 0 ]]; then
    info "Found $udp123_count active UDP/123 (NTP) socket(s) — verify these point at your real NTP servers, not the C2 domains in iocs/domains.txt. The fc-cache/chronyd build's beacon looks like NTP traffic to casual inspection."
  fi

  REDIS_CONNS=$(ss -tn 2>/dev/null | grep -c '127\.0\.0\.1:6379')
  if [[ "$REDIS_CONNS" -gt 10 ]]; then
    hit "Unusually high number of local Redis connections ($REDIS_CONNS to 127.0.0.1:6379) — matches the session-harvesting pattern observed in a StyleSmuggler infection with NO outbound C2 traffic"
  else
    info "Local Redis connection count: $REDIS_CONNS (not flagged; adjust threshold for your normal baseline)"
  fi
else
  info "'ss' not found — skipping live network check. Consider checking your firewall/proxy logs against iocs/ips.txt and iocs/domains.txt instead."
fi

log "\n\e[33mReminder:\e[0m at least one confirmed infection made no outbound network traffic at all, and a newer build's beaconing is deliberately shaped to look like ordinary NTP traffic on UDP/123. A clean network check alone does NOT mean the host is clean — trust the filesystem/process/cron/hash checks above at least as much."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Summary"

if [[ $FINDINGS -eq 0 ]]; then
  log "\e[32mNo StyleSmuggler indicators found.\e[0m This does not guarantee the host is clean — this is one point-in-time scan against currently published indicators for a still-developing incident. Re-run periodically and keep this repo updated."
  exit 0
else
  log "\e[31m$FINDINGS indicator(s) found.\e[0m Do NOT assume the worst-case single indicator is the full picture — review docs/INCIDENT_RESPONSE.md before killing processes or deleting files."
  if [[ $REMEDIATE -eq 1 ]]; then
    log "\n\e[33m--remediate was passed but automatic remediation is intentionally NOT implemented in this script.\e[0m"
    log "Evidence destruction from automated cleanup is a real risk (see docs/INCIDENT_RESPONSE.md)."
    log "Follow the manual, ordered steps in that document: persistence -> process -> binary -> re-check cron."
  fi
  exit 1
fi
