#!/usr/bin/env python3
"""
Linux Vulnerability Scanner
Scans your local machine for common security misconfigurations AND known CVEs.
Run as root for full coverage: sudo python3 linux_vuln_scanner.py

CVE data is fetched live from the OSV.dev API (free, no key required).
Pass --no-cve to skip the CVE scan and run config checks only.
Pass --max-pkgs N to limit CVE checks to N packages (default: 200).
"""

import os
import subprocess
import stat
import sys
import re
import json
import time
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── ANSI Colors ──────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color, text): return f"{color}{text}{RESET}"

# ─── Result Tracking ──────────────────────────────────────────────────────────

findings     = []
cve_findings = []

def add_finding(severity, category, title, detail):
    findings.append({"severity": severity, "category": category,
                     "title": title, "detail": detail})
    icon  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}[severity]
    color = {"CRITICAL": RED,  "HIGH": RED,   "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}[severity]
    print(f"  {icon} {c(color, severity):20s} {title}")
    if detail:
        for line in detail.strip().splitlines()[:5]:
            print(f"       {c(CYAN, '→')} {line}")

def section(title):
    print(f"\n{c(BOLD, '━' * 60)}")
    print(f"{c(BOLD, f'  {title}')}")
    print(c(BOLD, '━' * 60))

def run(cmd, shell=False, timeout=10):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True,
                                text=True, timeout=timeout, errors="replace")
        return result.stdout.strip()
    except Exception:
        return ""

# ─── Config / Hardening Checks ────────────────────────────────────────────────

def check_users():
    section("User & Account Security")
    uid0 = [line for line in Path("/etc/passwd").read_text().splitlines()
            if line.split(":")[2] == "0" and not line.startswith("root:")]
    if uid0:
        add_finding("CRITICAL", "Users", "Non-root accounts with UID 0", "\n".join(uid0))

    try:
        shadow = Path("/etc/shadow").read_text().splitlines()
        empty_pw = [l.split(":")[0] for l in shadow
                    if len(l.split(":")) > 1 and l.split(":")[1] in ("", "!!", ":")]
        if empty_pw:
            add_finding("HIGH", "Users", "Accounts with no password set", ", ".join(empty_pw))
    except PermissionError:
        add_finding("INFO", "Users", "Cannot read /etc/shadow (run as root for full scan)", "")

    login_users = [l.split(":")[0] for l in Path("/etc/passwd").read_text().splitlines()
                   if l.split(":")[-1] not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")
                   and int(l.split(":")[2]) >= 1000]
    if login_users:
        add_finding("INFO", "Users", f"Interactive user accounts ({len(login_users)})",
                    ", ".join(login_users))

    sshd_config = Path("/etc/ssh/sshd_config")
    if sshd_config.exists():
        content = sshd_config.read_text()
        if re.search(r"^\s*PermitRootLogin\s+yes", content, re.MULTILINE):
            add_finding("HIGH", "Users", "SSH root login is permitted",
                        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config")


def check_ssh():
    section("SSH Configuration")
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        add_finding("INFO", "SSH", "sshd_config not found — SSH may not be installed", "")
        return
    content = cfg.read_text()
    checks = [
        (r"^\s*PasswordAuthentication\s+yes", "HIGH",
         "SSH password authentication enabled", "Set 'PasswordAuthentication no'"),
        (r"^\s*PermitEmptyPasswords\s+yes", "CRITICAL",
         "SSH allows empty passwords", "Set 'PermitEmptyPasswords no'"),
        (r"^\s*X11Forwarding\s+yes", "LOW",
         "SSH X11 forwarding enabled", "Disable if not needed: 'X11Forwarding no'"),
        (r"^\s*Protocol\s+1", "CRITICAL",
         "SSHv1 protocol allowed", "Remove 'Protocol 1' — SSHv1 is broken"),
        (r"^\s*UsePAM\s+no", "MEDIUM",
         "PAM disabled in SSH", "Consider enabling PAM for better auth control"),
    ]
    for pattern, sev, title, detail in checks:
        if re.search(pattern, content, re.MULTILINE):
            add_finding(sev, "SSH", title, detail)
    m = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
    port = m.group(1) if m else "22"
    if port == "22":
        add_finding("LOW", "SSH", "SSH running on default port 22",
                    "Changing the port reduces automated scan noise")
    else:
        add_finding("INFO", "SSH", f"SSH running on non-default port {port}", "")


def check_sudo():
    section("Sudo Configuration")
    def scan_sudoers(path):
        try:
            content = path.read_text()
            if "NOPASSWD" in content:
                lines = [l.strip() for l in content.splitlines()
                         if "NOPASSWD" in l and not l.strip().startswith("#")]
                if lines:
                    add_finding("HIGH", "Sudo", f"NOPASSWD sudo in {path}", "\n".join(lines))
            if re.search(r"ALL\s*=\s*\(ALL\)\s*ALL", content):
                add_finding("MEDIUM", "Sudo", f"Broad sudo ALL grant in {path}",
                            "Review if ALL=(ALL) ALL is necessary")
        except PermissionError:
            add_finding("INFO", "Sudo", f"Cannot read {path} (run as root)", "")

    if Path("/etc/sudoers").exists():
        scan_sudoers(Path("/etc/sudoers"))
    if Path("/etc/sudoers.d").is_dir():
        for f in Path("/etc/sudoers.d").iterdir():
            scan_sudoers(f)


def check_suid_sgid():
    section("SUID / SGID Binaries")
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
        "/usr/bin/chfn", "/usr/bin/chsh", "/bin/ping", "/bin/mount",
        "/bin/umount", "/usr/bin/pkexec",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    }
    suid_files = []
    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in
                   {"/proc", "/sys", "/dev", "/run", "/snap"}]
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID) and path not in known_suid:
                    suid_files.append(path)
            except (PermissionError, OSError):
                pass
    if suid_files:
        add_finding("MEDIUM", "SUID", f"{len(suid_files)} unusual SUID/SGID files found",
                    "\n".join(suid_files[:10]) +
                    ("\n  (truncated...)" if len(suid_files) > 10 else ""))
    else:
        add_finding("INFO", "SUID", "No unusual SUID/SGID files found", "")


def check_world_writable():
    section("World-Writable Files & Directories")
    ww_files = []
    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in
                   {"/proc", "/sys", "/dev", "/run", "/snap", "/tmp"}]
        for name in files + dirs:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                if st.st_mode & stat.S_IWOTH and not (st.st_mode & stat.S_ISVTX):
                    ww_files.append(path)
            except (PermissionError, OSError):
                pass
            if len(ww_files) >= 20:
                break
    if ww_files:
        add_finding("MEDIUM", "Permissions",
                    "World-writable files/dirs found (showing up to 20)",
                    "\n".join(ww_files))
    else:
        add_finding("INFO", "Permissions", "No world-writable files outside /tmp found", "")


def check_open_ports():
    section("Open Network Ports")
    output = run(["ss", "-tlnp"]) or run(["netstat", "-tlnp"])
    if output:
        lines = [l for l in output.splitlines() if "LISTEN" in l or "0.0.0.0" in l]
        risky_ports = {
            "21": "FTP", "23": "Telnet", "25": "SMTP", "110": "POP3",
            "143": "IMAP", "3306": "MySQL", "5432": "PostgreSQL",
            "6379": "Redis", "27017": "MongoDB",
        }
        found_risky = [f"Port {p} ({n})" for p, n in risky_ports.items()
                       if f":{p} " in output or f":{p}\n" in output]
        if found_risky:
            add_finding("HIGH", "Network", "Potentially exposed services",
                        "\n".join(found_risky))
        wildcard = [l for l in lines if "0.0.0.0:" in l or "*:" in l]
        if wildcard:
            add_finding("MEDIUM", "Network",
                        f"{len(wildcard)} services listening on all interfaces",
                        "\n".join(wildcard[:8]))
        add_finding("INFO", "Network", "Open listening ports", "\n".join(lines[:15]))
    else:
        add_finding("INFO", "Network",
                    "Could not enumerate open ports (install ss/netstat)", "")


def check_firewall():
    section("Firewall Status")
    ufw = run(["ufw", "status"])
    if ufw:
        if "inactive" in ufw.lower():
            add_finding("HIGH", "Firewall", "UFW firewall is inactive",
                        "Run: sudo ufw enable")
        else:
            add_finding("INFO", "Firewall", "UFW is active", ufw[:200])
        return
    ipt = run(["iptables", "-L", "-n", "--line-numbers"])
    if ipt:
        if "Chain INPUT (policy ACCEPT)" in ipt:
            add_finding("HIGH", "Firewall",
                        "iptables INPUT chain policy is ACCEPT (no default deny)", "")
        else:
            add_finding("INFO", "Firewall", "iptables rules detected", "")
        return
    if run(["nft", "list", "ruleset"]):
        add_finding("INFO", "Firewall", "nftables ruleset present", "")
        return
    add_finding("HIGH", "Firewall", "No active firewall detected",
                "Install and enable ufw or iptables")


def check_kernel():
    section("Kernel & OS")
    add_finding("INFO", "Kernel", f"Kernel version: {run(['uname', '-r'])}", "")
    sysctl_checks = {
        "kernel.randomize_va_space":          ("2", "HIGH",   "ASLR not fully enabled",
                                               "Set kernel.randomize_va_space=2"),
        "net.ipv4.conf.all.accept_redirects": ("0", "MEDIUM", "ICMP redirects accepted",
                                               "Set net.ipv4.conf.all.accept_redirects=0"),
        "net.ipv4.conf.all.send_redirects":   ("0", "MEDIUM", "Sending ICMP redirects allowed",
                                               "Set net.ipv4.conf.all.send_redirects=0"),
        "net.ipv4.tcp_syncookies":            ("1", "MEDIUM", "SYN flood protection disabled",
                                               "Set net.ipv4.tcp_syncookies=1"),
        "kernel.dmesg_restrict":              ("1", "LOW",    "dmesg accessible to all users",
                                               "Set kernel.dmesg_restrict=1"),
        "kernel.kptr_restrict":               ("2", "MEDIUM", "Kernel pointers exposed",
                                               "Set kernel.kptr_restrict=2"),
        "fs.suid_dumpable":                   ("0", "MEDIUM", "Core dumps from SUID enabled",
                                               "Set fs.suid_dumpable=0"),
        "net.ipv4.conf.all.rp_filter":        ("1", "MEDIUM", "Reverse path filtering disabled",
                                               "Set net.ipv4.conf.all.rp_filter=1"),
    }
    for key, (expected, sev, title, fix) in sysctl_checks.items():
        val = run(["sysctl", "-n", key])
        if val and val.strip() != expected:
            add_finding(sev, "Kernel", title, f"Current: {key}={val}  →  {fix}")


def check_unattended_upgrades():
    section("Automatic Updates")
    auto_upgrade = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if auto_upgrade.exists():
        content = auto_upgrade.read_text()
        if 'APT::Periodic::Unattended-Upgrade "1"' in content:
            add_finding("INFO", "Updates",
                        "Unattended security upgrades are enabled", "")
        else:
            add_finding("MEDIUM", "Updates",
                        "Automatic unattended upgrades not configured",
                        "Enable: sudo dpkg-reconfigure unattended-upgrades")
    elif Path("/etc/dnf/automatic.conf").exists():
        add_finding("INFO", "Updates",
                    "dnf-automatic config found — verify it's enabled", "")
    else:
        add_finding("MEDIUM", "Updates",
                    "No automatic update configuration detected",
                    "Consider enabling automatic security updates")


def check_services():
    section("Running Services")
    output = run(["systemctl", "list-units", "--type=service",
                  "--state=running", "--no-pager"])
    risky = {
        "telnet": "CRITICAL", "rsh": "CRITICAL", "rlogin": "CRITICAL",
        "rexec": "CRITICAL", "tftp": "HIGH", "finger": "HIGH",
        "avahi-daemon": "LOW", "cups": "LOW", "bluetooth": "LOW",
        "nfs": "MEDIUM", "rpcbind": "MEDIUM",
    }
    found = [(sev, name) for name, sev in risky.items() if name in output.lower()]
    for sev, name in sorted(found,
                            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0])):
        add_finding(sev, "Services",
                    f"Potentially unnecessary service running: {name}",
                    f"Disable if not needed: sudo systemctl disable --now {name}")
    if not found:
        add_finding("INFO", "Services", "No obviously risky services detected", "")


def check_cron():
    section("Cron Jobs")
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly"]
    all_jobs = []
    for d in cron_dirs:
        p = Path(d)
        if p.is_dir():
            for f in p.iterdir():
                try:
                    for line in f.read_text().splitlines():
                        if not line.startswith("#") and line.strip():
                            all_jobs.append(f"{f}: {line.strip()}")
                except PermissionError:
                    pass
    try:
        all_jobs += [f"/etc/crontab: {l}"
                     for l in Path("/etc/crontab").read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
    except Exception:
        pass

    ww_cron = []
    for job in all_jobs:
        for token in job.split():
            if token.startswith("/") and Path(token).exists():
                try:
                    if os.stat(token).st_mode & stat.S_IWOTH:
                        ww_cron.append(token)
                except OSError:
                    pass
    if ww_cron:
        add_finding("HIGH", "Cron",
                    "World-writable scripts referenced in cron jobs",
                    "\n".join(ww_cron))
    if all_jobs:
        add_finding("INFO", "Cron", f"{len(all_jobs)} cron job(s) found",
                    "\n".join(all_jobs[:10]))
    else:
        add_finding("INFO", "Cron", "No system cron jobs found", "")


def check_passwd_shadow_perms():
    section("Critical File Permissions")
    file_checks = {
        "/etc/passwd":          (0o644, "MEDIUM"),
        "/etc/shadow":          (0o640, "HIGH"),
        "/etc/sudoers":         (0o440, "HIGH"),
        "/etc/ssh/sshd_config": (0o600, "MEDIUM"),
        "/boot/grub/grub.cfg":  (0o600, "LOW"),
    }
    for path, (expected_mode, sev) in file_checks.items():
        if not Path(path).exists():
            continue
        try:
            actual = stat.S_IMODE(os.stat(path).st_mode)
            if actual > expected_mode:
                add_finding(sev, "File Perms",
                            f"Permissions too permissive on {path}",
                            f"Current: {oct(actual)}  Expected: ≤{oct(expected_mode)}")
        except PermissionError:
            pass


# ─── CVE Scanning via OSV.dev ─────────────────────────────────────────────────

# These packages are checked first — they are the highest-value targets
PRIORITY_PACKAGES = {
    "linux-image", "openssh", "openssh-server", "openssh-client",
    "openssl", "libssl", "libssl3", "libssl1.1",
    "sudo", "bash", "curl", "wget", "python3", "python3-minimal",
    "libc6", "libc-bin", "glibc",
    "nginx", "apache2", "httpd",
    "mysql-server", "mariadb-server", "postgresql",
    "redis", "redis-server",
    "docker", "docker.io", "containerd", "runc",
    "git", "vim", "nano", "perl", "ruby", "php", "nodejs", "npm",
    "libpam0g", "libpam-runtime",
    "zlib1g", "libz", "libexpat1", "libxml2", "libsqlite3-0",
}


def detect_package_manager():
    """Detect installed packages. Returns (ecosystem_string, {name: version})."""
    # Debian / Ubuntu
    out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[1].strip():
                pkgs[parts[0].strip()] = parts[1].strip()
        if pkgs:
            return "Debian", pkgs

    # RPM-based (RHEL, Fedora, CentOS, openSUSE)
    out = run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                pkgs[parts[0].strip()] = parts[1].strip()
        if pkgs:
            return "Red Hat", pkgs

    # Arch Linux
    out = run(["pacman", "-Q"])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                pkgs[parts[0]] = parts[1]
        if pkgs:
            return "Arch Linux", pkgs

    return None, {}


def query_osv(package_name, version, ecosystem, retries=2):
    """
    POST to OSV.dev query API.
    Returns list of vulnerability dicts (may be empty).
    """
    payload = json.dumps({
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem}
    }).encode()

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/query",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode())
                return data.get("vulns", [])
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(2 ** attempt)
            else:
                return []
        except Exception:
            return []
    return []


def cvss_to_severity(score):
    if score is None:   return "MEDIUM"
    if score >= 9.0:    return "CRITICAL"
    if score >= 7.0:    return "HIGH"
    if score >= 4.0:    return "MEDIUM"
    return "LOW"


def extract_cvss(vuln):
    """Pull the highest numeric CVSS base score out of an OSV record."""
    best = None

    def try_update(val):
        nonlocal best
        try:
            f = float(val)
            if best is None or f > best:
                best = f
        except (TypeError, ValueError):
            pass

    for sev in vuln.get("severity", []):
        # Some OSV entries store the score directly as a number
        try_update(sev.get("score"))
        # CVSS v3 vector — extract the base score suffix if present
        score_str = str(sev.get("score", ""))
        m = re.search(r"/(\d+\.\d+)$", score_str)
        if m:
            try_update(m.group(1))

    db = vuln.get("database_specific", {})
    for key in ("cvss", "cvss_score", "severity_score", "cvss_v3", "base_score"):
        try_update(db.get(key))

    return best


def extract_cve_ids(vuln):
    aliases = vuln.get("aliases", []) + [vuln.get("id", "")]
    return [a for a in aliases if a.startswith("CVE-")]


def extract_fix_version(vuln):
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def check_cves(max_pkgs=200):
    section("CVE Vulnerability Scan  (via OSV.dev)")

    ecosystem, all_pkgs = detect_package_manager()
    if not all_pkgs:
        add_finding("INFO", "CVE",
                    "No supported package manager found (dpkg / rpm / pacman)", "")
        return

    total = len(all_pkgs)
    print(f"  {c(CYAN, '→')} {total} installed packages detected  "
          f"({c(BOLD, ecosystem)} ecosystem)")

    # Priority packages first, then alphabetical
    def sort_key(name):
        base = re.split(r"[-:]", name)[0].lower()
        return (0 if base in PRIORITY_PACKAGES or name in PRIORITY_PACKAGES else 1, name)

    sorted_pkgs = sorted(all_pkgs.items(), key=lambda kv: sort_key(kv[0]))
    to_scan     = sorted_pkgs[:max_pkgs]

    if total > max_pkgs:
        print(f"  {c(YELLOW, '→')} Limiting scan to {max_pkgs} packages "
              f"(priority packages checked first). Use --max-pkgs N to increase.")

    print(f"  {c(CYAN, '→')} Querying OSV.dev in parallel — please wait...\n")

    vuln_count = 0
    pkg_count  = 0
    errors     = 0
    checked    = 0
    lock_print = __import__("threading").Lock()

    def scan_one(name_ver):
        name, ver = name_ver
        vulns = query_osv(name, ver, ecosystem)
        return name, ver, vulns

    bar_width = 38
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(scan_one, kv): kv for kv in to_scan}
        for future in as_completed(futures):
            checked += 1
            pct = int(checked / len(to_scan) * bar_width)
            bar = f"[{'█' * pct}{'░' * (bar_width - pct)}] {checked}/{len(to_scan)}"
            print(f"  \r  {bar}", end="", flush=True)

            try:
                name, ver, vulns = future.result()
            except Exception:
                errors += 1
                continue

            if not vulns:
                continue

            pkg_count  += 1
            vuln_count += len(vulns)

            for vuln in vulns:
                cve_ids  = extract_cve_ids(vuln)
                cvss     = extract_cvss(vuln)
                severity = cvss_to_severity(cvss)
                fix_ver  = extract_fix_version(vuln)
                osv_id   = vuln.get("id", "")
                summary  = vuln.get("summary", vuln.get("details", ""))[:220]
                cve_label = ", ".join(cve_ids) if cve_ids else osv_id
                score_str = f"  CVSS: {cvss:.1f}" if cvss is not None else ""

                detail_lines = [
                    f"Package : {name}  {ver}",
                    f"CVE ID  : {cve_label}{score_str}",
                    f"Summary : {summary}" if summary else None,
                    f"Fix     : upgrade to {fix_ver}" if fix_ver else None,
                    (f"Ref     : https://nvd.nist.gov/vuln/detail/{cve_ids[0]}"
                     if cve_ids else
                     f"OSV     : https://osv.dev/vulnerability/{osv_id}"),
                ]
                detail_lines = [l for l in detail_lines if l]

                cve_findings.append({
                    "severity":    severity,
                    "package":     name,
                    "version":     ver,
                    "cve":         cve_label,
                    "cvss":        cvss,
                    "summary":     summary,
                    "fix_version": fix_ver,
                    "osv_id":      osv_id,
                })

                icon  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
                         "LOW":"🟢","INFO":"🔵"}[severity]
                color = {"CRITICAL":RED,"HIGH":RED,"MEDIUM":YELLOW,
                         "LOW":GREEN,"INFO":CYAN}[severity]

                with lock_print:
                    print(f"\n  {icon} {c(color, severity):20s} "
                          f"{name} {ver} — {c(BOLD, cve_label)}")
                    for line in detail_lines[2:]:
                        print(f"       {c(CYAN, '→')} {line}")

    print()  # close progress bar line

    # ── Per-scan summary ──
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cf in cve_findings:
        sev_counts[cf["severity"]] = sev_counts.get(cf["severity"], 0) + 1

    print(f"\n  {c(BOLD, 'CVE scan complete')}")
    print(f"  Packages scanned  : {checked}")
    print(f"  Vulnerable pkgs   : {pkg_count}")
    print(f"  Total CVEs found  : {vuln_count}")
    if errors:
        print(f"  API errors        : {errors}  (network issue or rate limit)")
    if sev_counts["CRITICAL"] or sev_counts["HIGH"]:
        warn_msg = "  ⚠  {} critical  {} high — patch immediately".format(
            sev_counts["CRITICAL"], sev_counts["HIGH"])
        print(f"  {c(RED, warn_msg)}")

    if vuln_count == 0:
        add_finding("INFO", "CVE",
                    f"No known CVEs found in {checked} scanned packages", "")
    else:
        worst = next((s for s in ["CRITICAL","HIGH","MEDIUM","LOW"]
                      if sev_counts[s] > 0), "LOW")
        detail = (
            f"{sev_counts['CRITICAL']} critical, {sev_counts['HIGH']} high, "
            f"{sev_counts['MEDIUM']} medium, {sev_counts['LOW']} low\n"
            "Run 'sudo apt upgrade'  (or dnf/pacman equivalent) to apply patches."
        )
        add_finding(worst, "CVE",
                    f"{vuln_count} CVE(s) found across {pkg_count} package(s)",
                    detail)


# ─── Summary & Report ─────────────────────────────────────────────────────────

def print_summary():
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1

    print(f"\n{c(BOLD, '━' * 60)}")
    print(c(BOLD, "  SCAN SUMMARY"))
    print(c(BOLD, '━' * 60))
    print(f"  Config findings  : {len(findings)}")
    print(f"  CVEs identified  : {len(cve_findings)}")
    print(f"  🔴 Critical : {counts['CRITICAL']}")
    print(f"  🟠 High     : {counts['HIGH']}")
    print(f"  🟡 Medium   : {counts['MEDIUM']}")
    print(f"  🟢 Low      : {counts['LOW']}")
    print(f"  🔵 Info     : {counts['INFO']}")

    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        print(f"\n  {c(RED, '⚠  Action required — address CRITICAL and HIGH findings first.')}")
    elif counts["MEDIUM"] > 0:
        print(f"\n  {c(YELLOW, '⚠  Review MEDIUM findings and apply fixes where feasible.')}")
    else:
        print(f"\n  {c(GREEN, '✔  No high-severity issues detected.')}")


def save_report():
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"vuln_report_{ts}.json"
    with open(report_path, "w") as f:
        json.dump({
            "scan_time":       ts,
            "hostname":        run(["hostname"]),
            "kernel":          run(["uname", "-r"]),
            "config_findings": findings,
            "cve_findings":    cve_findings,
        }, f, indent=2)
    print(f"\n  📄 Full report saved to: {c(CYAN, report_path)}")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Linux Vulnerability Scanner — hardening checks + live CVE lookup")
    parser.add_argument("--no-cve",   action="store_true",
                        help="Skip CVE scanning (config checks only)")
    parser.add_argument("--cve-only", action="store_true",
                        help="Run CVE scan only (skip config hardening checks)")
    parser.add_argument("--max-pkgs", type=int, default=200, metavar="N",
                        help="Max packages to query against OSV.dev (default: 200)")
    args = parser.parse_args()

    print(c(BOLD, "\n╔══════════════════════════════════════════════════════════╗"))
    print(c(BOLD,   "║          Linux Vulnerability Scanner                    ║"))
    print(c(BOLD,   "╚══════════════════════════════════════════════════════════╝"))
    print(f"  Host : {run(['hostname'])}")
    print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  User : {run(['whoami'])}")
    if os.geteuid() != 0:
        print(f"\n  {c(YELLOW, '⚠  Not running as root — some checks will be limited.')}")
        print(f"     Re-run with: {c(CYAN, 'sudo python3 ' + sys.argv[0])}\n")

    if not args.cve_only:
        check_users()
        check_ssh()
        check_sudo()
        check_suid_sgid()
        check_world_writable()
        check_open_ports()
        check_firewall()
        check_kernel()
        check_unattended_upgrades()
        check_services()
        check_cron()
        check_passwd_shadow_perms()

    if not args.no_cve:
        check_cves(max_pkgs=args.max_pkgs)

    print_summary()
    save_report()
    print()


if __name__ == "__main__":
    main()