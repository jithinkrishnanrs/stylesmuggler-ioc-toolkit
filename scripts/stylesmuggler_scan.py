#!/usr/bin/env python3
"""
stylesmuggler_scan.py — read-only compromise scanner for the StyleSmuggler
Magento / Adobe Commerce 0-day (Sansec advisory, 2026-09-05).

Same checks as scripts/stylesmuggler_scan.sh, structured for machine-readable output
(JSON) so it can feed a SIEM or ticketing pipeline. Detection only — no remediation.
See docs/INCIDENT_RESPONSE.md before acting on any finding.

Usage:
    sudo python3 stylesmuggler_scan.py --magento-root /var/www/html
    sudo python3 stylesmuggler_scan.py --magento-root /var/www/html --json report.json
    sudo python3 stylesmuggler_scan.py --home-dir /home --home-dir /srv/users

Exit codes: 0 clean, 1 suspicious, 2 error.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
IOC_DIR = SCRIPT_DIR.parent / "iocs"

TRIGGER_HEADER_RE = re.compile(r"X[_-](TRACE[_-])?[0-9A-Fa-f]{10,12}")
RESPONSE_MARKER_RE = re.compile(r"MG[0-9a-f]{16,}::")
PHP_TAG_RE = re.compile(r"<\?php|<\?=")
C2_IPS = ["99.84.67.186", "209.141.43.95"]
NTP_C2_DOMAINS = ["ntp.timesync.to", "ntp.synctime.to", "ntp.syncstime.to"]
CRON_PATTERN = re.compile(r"gvfsd|\.kw_|fc-cache|\.fc_|chronyd|\.chrony-")
SYSTEM_PATH_PREFIXES = ("/usr", "/sbin", "/bin", "/lib")
STANDARD_TIME_USERS = {"root", "chrony", "_chrony", "systemd-timesync"}


@dataclass
class Finding:
    category: str
    severity: str  # "hit" | "info"
    detail: str


@dataclass
class ScanReport:
    findings: list = field(default_factory=list)

    def hit(self, category: str, detail: str):
        self.findings.append(Finding(category, "hit", detail))
        print(f"  [HIT] {detail}")

    def info(self, category: str, detail: str):
        self.findings.append(Finding(category, "info", detail))
        print(f"  [info] {detail}")

    def ok(self, detail: str):
        print(f"  [ok] {detail}")

    @property
    def hit_count(self):
        return sum(1 for f in self.findings if f.severity == "hit")


def section(title: str):
    print(f"\n== {title} ==")


def load_known_hashes():
    hash_file = IOC_DIR / "hashes.sha256"
    hashes = set()
    if hash_file.exists():
        for line in hash_file.read_text().splitlines():
            m = re.match(r"^([0-9a-f]{64})", line.strip())
            if m:
                hashes.add(m.group(1))
    return hashes


def sha256_of_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def check_filesystem(report: ScanReport, home_dirs):
    section("Filesystem persistence")
    before = report.hit_count
    candidates = list(home_dirs) + ["/root"]
    for h in candidates:
        base = Path(h)
        # gvfsd-user build (first seen 2026-09-04)
        implant = base / ".local/share/.gvfsd/gvfsd-user"
        if implant.exists():
            report.hit("filesystem", f"Implant binary present (gvfsd-user build): {implant}")
        for lock in glob.glob(str(base / ".local/share/.gvfsd/.gvfsd_*.lock")):
            report.hit("filesystem", f"Implant lock file (gvfsd-user build): {lock}")
        # fc-cache build (first seen 2026-09-06)
        fc_implant = base / ".cache/fontconfig/fc-cache"
        if fc_implant.exists():
            report.hit(
                "filesystem",
                f"Implant binary present (fc-cache build): {fc_implant} — verify against "
                f"your distro's real fc-cache path/hash before assuming compromise",
            )
    for lock in glob.glob("/tmp/.gvfsd_*.lock"):
        report.hit("filesystem", f"Implant lock file (second location, gvfsd-user build): {lock}")
    for kw in glob.glob("/tmp/.kw_*"):
        report.hit("filesystem", f"Implant artefact (gvfsd-user build): {kw}")
    for lock in glob.glob("/tmp/.fc_*.lock"):
        report.hit("filesystem", f"Implant lock file (fc-cache build): {lock}")
    for chrony_dir in glob.glob("/tmp/.chrony-*"):
        chronyd_bin = Path(chrony_dir) / "chronyd"
        if chronyd_bin.exists():
            report.hit("filesystem", f"Implant binary present (chronyd build): {chronyd_bin}")
    if report.hit_count == before:
        report.ok(
            "No known persistence file paths found under checked home directories or /tmp "
            "(checked gvfsd-user, fc-cache, and chronyd build locations)."
        )


def check_cron(report: ScanReport):
    section("Cron persistence")
    before = report.hit_count
    pattern = CRON_PATTERN
    spool_dir = Path("/var/spool/cron/crontabs")
    checked_any = False
    if os.geteuid() == 0 and spool_dir.is_dir():
        for spool in spool_dir.iterdir():
            if not spool.is_file():
                continue
            checked_any = True
            try:
                content = spool.read_text(errors="ignore")
            except (OSError, PermissionError):
                continue
            matches = pattern.findall(content)
            if matches:
                report.hit(
                    "cron",
                    f"Malicious cron entry in spool file for '{spool.name}' "
                    f"({len(matches)} matching line(s)) — self-restores if process/binary "
                    f"aren't cleaned first, see docs/INCIDENT_RESPONSE.md",
                )
    else:
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            checked_any = True
            if pattern.search(out.stdout):
                report.hit("cron", "Malicious cron entry in current user's crontab")
        except (FileNotFoundError, subprocess.SubprocessError):
            report.info("cron", "crontab command not found or inaccessible — skipping")
    if checked_any and report.hit_count == before:
        report.ok("No malicious cron entries found.")


def check_processes(report: ScanReport):
    section("Process masquerade ([kworker/u:8:0], fc-cache, or chronyd)")
    suspects = []
    try:
        out = subprocess.run(
            ["ps", "-eo", "user:32,pid,comm,args"], capture_output=True, text=True, timeout=5
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        report.info("process", "'ps' not available — skipping process check")
        return suspects

    for line in out.stdout.splitlines()[1:]:
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        puser, ppid, pcomm = parts[0], parts[1], parts[2]

        if "kworker/u:8:0" in line:
            if puser != "root":
                report.hit(
                    "process",
                    f"Process '{pcomm}' (PID {ppid}) matches known masquerade name "
                    f"but is owned by non-root user '{puser}'",
                )
                suspects.append(ppid)
            else:
                report.info("process", f"Found {pcomm} (PID {ppid}) owned by root — likely genuine, not flagged")
            continue

        if pcomm in ("fc-cache", "chronyd"):
            real_exe = None
            exe_link = Path(f"/proc/{ppid}/exe")
            if exe_link.exists():
                try:
                    real_exe = str(exe_link.resolve())
                except (OSError, RuntimeError):
                    real_exe = None
            if real_exe and not real_exe.startswith(SYSTEM_PATH_PREFIXES):
                report.hit(
                    "process",
                    f"Process '{pcomm}' (PID {ppid}, user '{puser}') running from "
                    f"non-system path {real_exe} — matches fc-cache/chronyd build masquerade",
                )
                suspects.append(ppid)
            elif puser not in STANDARD_TIME_USERS:
                report.hit(
                    "process",
                    f"Process '{pcomm}' (PID {ppid}) owned by unexpected user '{puser}' "
                    f"(not root or a standard time-sync/fontconfig account)",
                )
                suspects.append(ppid)
            else:
                report.info(
                    "process",
                    f"Found {pcomm} (PID {ppid}) owned by '{puser}', exe resolves under a "
                    f"system path — likely genuine, not flagged",
                )

    if not suspects:
        report.ok("No suspicious [kworker/u:8:0], fc-cache, or chronyd processes found.")
    return suspects


def check_hashes(report: ScanReport, home_dirs, suspect_pids):
    section("Hash verification")
    known = load_known_hashes()
    if not known:
        report.info("hash", f"No known hashes loaded from {IOC_DIR / 'hashes.sha256'}")

    candidates = list(home_dirs) + ["/root"]
    for h in candidates:
        bin_path = Path(h) / ".local/share/.gvfsd/gvfsd-user"
        if bin_path.exists():
            digest = sha256_of_file(bin_path)
            if digest is None:
                report.info("hash", f"Could not read {bin_path} to hash it (permissions?)")
            elif digest in known:
                report.hit("hash", f"On-disk binary {bin_path} matches known StyleSmuggler hash: {digest}")
            else:
                report.hit(
                    "hash",
                    f"On-disk binary {bin_path} present but hash NOT in known list "
                    f"({digest}) — possible new/updated variant",
                )

    for pid in suspect_pids:
        exe_link = Path(f"/proc/{pid}/exe")
        if not exe_link.exists():
            continue
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = Path(tmp.name)
            shutil.copy(str(exe_link), tmp_path)
            digest = sha256_of_file(tmp_path)
            tmp_path.unlink(missing_ok=True)
            if digest is None:
                continue
            if digest in known:
                report.hit("hash", f"In-memory image of PID {pid} matches known StyleSmuggler hash: {digest}")
            else:
                report.hit(
                    "hash",
                    f"In-memory image of PID {pid} does NOT match known hashes "
                    f"({digest}) — possible updated/new implant build",
                )
        except (OSError, PermissionError, shutil.Error):
            report.info("hash", f"Could not copy /proc/{pid}/exe for PID {pid} (permission denied?)")


def check_poisoned_files(report: ScanReport, magento_root):
    section("Poisoned log/report files")
    if not magento_root:
        report.info("logs", "No --magento-root given — skipping log/report content scan")
        return
    before = report.hit_count
    targets = [Path(magento_root) / "var/log/system.log", Path(magento_root) / "var/report"]
    for target in targets:
        if not target.exists():
            continue
        files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
        for f in files:
            try:
                content = f.read_text(errors="ignore")
            except (OSError, PermissionError):
                continue
            if PHP_TAG_RE.search(content):
                report.hit("logs", f"Possible PHP injection found in {f} — inspect manually before deleting")
            if TRIGGER_HEADER_RE.search(content):
                report.hit("logs", f"Trigger-header artefact found in {f}")
            if RESPONSE_MARKER_RE.search(content):
                report.hit("logs", f"Execution-proof marker (MG<hex>::...) found in {f} — payload RAN")
    if report.hit_count == before:
        report.ok("No injected PHP, trigger headers, or execution markers found.")


def check_network(report: ScanReport):
    section("Network")
    try:
        out_tcp = subprocess.run(["ss", "-tn"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.SubprocessError):
        report.info("network", "'ss' not available — skipping live network check")
        return

    for ip in C2_IPS:
        if ip in out_tcp.stdout:
            report.hit("network", f"Active connection to known C2/download address {ip}")

    # fc-cache/chronyd build beacons over UDP/123 disguised as NTP traffic
    try:
        out_udp = subprocess.run(["ss", "-un"], capture_output=True, text=True, timeout=5)
        udp123_count = out_udp.stdout.count(":123 ")
        if udp123_count:
            report.info(
                "network",
                f"Found {udp123_count} active UDP/123 (NTP) socket(s) — verify these point "
                f"at your real NTP servers, not {', '.join(NTP_C2_DOMAINS)}. The "
                f"fc-cache/chronyd build's beacon looks like NTP traffic to casual inspection.",
            )
        for domain in NTP_C2_DOMAINS:
            try:
                resolved = socket.gethostbyname(domain)
                if resolved in out_udp.stdout:
                    report.hit(
                        "network",
                        f"Active UDP connection to resolved IP of known NTP-shaped C2 domain "
                        f"{domain} ({resolved})",
                    )
            except OSError:
                pass
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    redis_conns = out_tcp.stdout.count("127.0.0.1:6379")
    if redis_conns > 10:
        report.hit(
            "network",
            f"Unusually high number of local Redis connections ({redis_conns}) — "
            f"matches session-harvesting pattern seen with NO outbound C2 traffic",
        )
    else:
        report.info("network", f"Local Redis connection count: {redis_conns} (adjust threshold for your baseline)")

    print(
        "\n[reminder] At least one confirmed infection made no outbound network traffic "
        "at all, and a newer build's beaconing is deliberately shaped to look like ordinary "
        "NTP traffic on UDP/123. A clean network check alone does NOT mean the host is clean."
    )


def main():
    parser = argparse.ArgumentParser(description="StyleSmuggler compromise scanner")
    parser.add_argument("--magento-root", default=None, help="Path to Magento install root")
    parser.add_argument(
        "--home-dir", action="append", default=None,
        help="Home directory (or glob) to check for implant artefacts; repeatable",
    )
    parser.add_argument("--json", default=None, help="Write JSON report to this path")
    args = parser.parse_args()

    home_dirs = []
    if args.home_dir:
        for pattern in args.home_dir:
            home_dirs.extend(glob.glob(pattern))
    else:
        home_dirs.extend(glob.glob("/home/*"))

    print("StyleSmuggler compromise scanner")
    print("Built from: Sansec advisory 2026-09-05, updated through 2026-09-07 + community IR.")
    print("Reference:  https://sansec.io/research/stylesmuggler-0day")
    print("This is DETECTION ONLY. See docs/INCIDENT_RESPONSE.md before acting on findings.\n")

    if os.geteuid() != 0:
        print(
            "Warning: not running as root. Checks against other users' home directories, "
            "crontabs, and /proc/<pid>/exe for processes you don't own may be incomplete.\n"
        )

    report = ScanReport()
    check_filesystem(report, home_dirs)
    check_cron(report)
    suspect_pids = check_processes(report)
    check_hashes(report, home_dirs, suspect_pids)
    check_poisoned_files(report, args.magento_root)
    check_network(report)

    section("Summary")
    if report.hit_count == 0:
        print("No StyleSmuggler indicators found. Re-run periodically; this incident is still developing.")
        exit_code = 0
    else:
        print(f"{report.hit_count} indicator(s) found. Review docs/INCIDENT_RESPONSE.md before remediating.")
        exit_code = 1

    if args.json:
        payload = {
            "scanner": "stylesmuggler_scan.py",
            "reference": "https://sansec.io/research/stylesmuggler-0day",
            "hit_count": report.hit_count,
            "findings": [asdict(f) for f in report.findings],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"\nJSON report written to {args.json}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
