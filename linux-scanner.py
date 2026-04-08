#!/usr/bin/env python3
"""
Linux Vulnerability Scanner
Scans your local machine for common security misconfigurations and vulnerabilities.
Run as root for full coverage: sudo python3 linux_vuln_scanner.py
"""

import os
import subprocess
import stat
import pwd
import grp
import sys
import re
import json
from datetime import datetime
from pathlib import Path

# ─── ANSI Colors ────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color, text): return f"{color}{text}{RESET}"

# ─── Result Tracking ─────────────────────────────────────────────────────────

findings = []

def add_finding(severity, category, title, detail):
    findings.append({
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail
    })
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}[severity]
    color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}[severity]
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
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return result.stdout.strip()
    except Exception:
        return ""

# ─── Checks ──────────────────────────────────────────────────────────────────

def check_users():
    section("User & Account Security")

    # UID 0 accounts (other than root)
    uid0 = [line for line in Path("/etc/passwd").read_text().splitlines()
            if line.split(":")[2] == "0" and not line.startswith("root:")]
    if uid0:
        add_finding("CRITICAL", "Users", "Non-root accounts with UID 0",
                    "\n".join(uid0))

    # Accounts with empty passwords
    try:
        shadow = Path("/etc/shadow").read_text().splitlines()
        empty_pw = [l.split(":")[0] for l in shadow
                    if len(l.split(":")) > 1 and l.split(":")[1] in ("", "!!", ":")]
        if empty_pw:
            add_finding("HIGH", "Users", "Accounts with no password set",
                        ", ".join(empty_pw))
    except PermissionError:
        add_finding("INFO", "Users", "Cannot read /etc/shadow (run as root for full scan)", "")

    # Users with login shells that are non-system accounts
    login_users = [l.split(":")[0] for l in Path("/etc/passwd").read_text().splitlines()
                   if l.split(":")[-1] not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")
                   and int(l.split(":")[2]) >= 1000]
    if login_users:
        add_finding("INFO", "Users", f"Interactive user accounts ({len(login_users)})",
                    ", ".join(login_users))

    # Root login via SSH
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
        (r"^\s*PasswordAuthentication\s+yes", "HIGH", "SSH password authentication enabled",
         "Use key-based auth: set 'PasswordAuthentication no'"),
        (r"^\s*PermitEmptyPasswords\s+yes", "CRITICAL", "SSH allows empty passwords",
         "Set 'PermitEmptyPasswords no'"),
        (r"^\s*X11Forwarding\s+yes", "LOW", "SSH X11 forwarding enabled",
         "Disable if not needed: 'X11Forwarding no'"),
        (r"^\s*Protocol\s+1", "CRITICAL", "SSHv1 protocol allowed",
         "Remove 'Protocol 1' — SSHv1 is broken"),
        (r"^\s*UsePAM\s+no", "MEDIUM", "PAM disabled in SSH",
         "Consider enabling PAM for better auth control"),
    ]

    for pattern, sev, title, detail in checks:
        if re.search(pattern, content, re.MULTILINE):
            add_finding(sev, "SSH", title, detail)

    # Port
    m = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
    port = m.group(1) if m else "22"
    if port == "22":
        add_finding("LOW", "SSH", "SSH running on default port 22",
                    "Changing the port reduces automated scan noise")
    else:
        add_finding("INFO", "SSH", f"SSH running on non-default port {port}", "")


def check_sudo():
    section("Sudo Configuration")

    sudoers = Path("/etc/sudoers")
    sudoers_d = Path("/etc/sudoers.d")

    def scan_sudoers(path):
        try:
            content = path.read_text()
            if "NOPASSWD" in content:
                lines = [l.strip() for l in content.splitlines()
                         if "NOPASSWD" in l and not l.strip().startswith("#")]
                if lines:
                    add_finding("HIGH", "Sudo", f"NOPASSWD sudo in {path}",
                                "\n".join(lines))
            if re.search(r"ALL\s*=\s*\(ALL\)\s*ALL", content):
                add_finding("MEDIUM", "Sudo", f"Broad sudo ALL grant in {path}",
                            "Review if ALL=(ALL) ALL is necessary")
        except PermissionError:
            add_finding("INFO", "Sudo", f"Cannot read {path} (run as root)", "")

    if sudoers.exists():
        scan_sudoers(sudoers)
    if sudoers_d.is_dir():
        for f in sudoers_d.iterdir():
            scan_sudoers(f)


def check_suid_sgid():
    section("SUID / SGID Binaries")

    known_suid = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
        "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
        "/bin/ping", "/bin/mount", "/bin/umount",
        "/usr/bin/pkexec", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    }

    suid_files = []
    for root, dirs, files in os.walk("/", topdown=True):
        # Skip virtual/irrelevant filesystems
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in
                   {"/proc", "/sys", "/dev", "/run", "/snap"}]
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    if path not in known_suid:
                        suid_files.append(path)
            except (PermissionError, OSError):
                pass

    if suid_files:
        add_finding("MEDIUM", "SUID", f"{len(suid_files)} unusual SUID/SGID files found",
                    "\n".join(suid_files[:10]) + ("\n  (truncated...)" if len(suid_files) > 10 else ""))
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
                if st.st_mode & stat.S_IWOTH:
                    if not (st.st_mode & stat.S_ISVTX):  # exclude sticky bit dirs
                        ww_files.append(path)
            except (PermissionError, OSError):
                pass
            if len(ww_files) >= 20:
                break

    if ww_files:
        add_finding("MEDIUM", "Permissions",
                    f"World-writable files/dirs found (showing up to 20)",
                    "\n".join(ww_files))
    else:
        add_finding("INFO", "Permissions", "No world-writable files outside /tmp found", "")


def check_open_ports():
    section("Open Network Ports")

    output = run(["ss", "-tlnp"])
    if not output:
        output = run(["netstat", "-tlnp"])

    if output:
        lines = [l for l in output.splitlines() if "LISTEN" in l or "0.0.0.0" in l]
        risky_ports = {"21": "FTP", "23": "Telnet", "25": "SMTP",
                       "110": "POP3", "143": "IMAP", "3306": "MySQL",
                       "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB"}

        found_risky = []
        for port, name in risky_ports.items():
            if f":{port} " in output or f":{port}\n" in output:
                found_risky.append(f"Port {port} ({name})")

        if found_risky:
            add_finding("HIGH", "Network", "Potentially exposed services",
                        "\n".join(found_risky))

        # Wildcard listeners
        wildcard = [l for l in lines if "0.0.0.0:" in l or "*:" in l]
        if wildcard:
            add_finding("MEDIUM", "Network",
                        f"{len(wildcard)} services listening on all interfaces",
                        "\n".join(wildcard[:8]))

        add_finding("INFO", "Network", "Open listening ports",
                    "\n".join(lines[:15]))
    else:
        add_finding("INFO", "Network", "Could not enumerate open ports (install ss/netstat)", "")


def check_firewall():
    section("Firewall Status")

    # UFW
    ufw = run(["ufw", "status"])
    if ufw:
        if "inactive" in ufw.lower():
            add_finding("HIGH", "Firewall", "UFW firewall is inactive", "Run: sudo ufw enable")
        else:
            add_finding("INFO", "Firewall", "UFW is active", ufw[:200])
        return

    # iptables
    ipt = run(["iptables", "-L", "-n", "--line-numbers"])
    if ipt:
        if "Chain INPUT (policy ACCEPT)" in ipt:
            add_finding("HIGH", "Firewall",
                        "iptables INPUT chain policy is ACCEPT (no default deny)", "")
        else:
            add_finding("INFO", "Firewall", "iptables rules detected", "")
        return

    # nftables
    nft = run(["nft", "list", "ruleset"])
    if nft:
        add_finding("INFO", "Firewall", "nftables ruleset present", "")
        return

    add_finding("HIGH", "Firewall", "No active firewall detected", "Install and enable ufw or iptables")


def check_kernel():
    section("Kernel & OS")

    uname = run(["uname", "-r"])
    add_finding("INFO", "Kernel", f"Kernel version: {uname}", "")

    # Kernel hardening via sysctl
    sysctl_checks = {
        "kernel.randomize_va_space": ("2", "HIGH", "ASLR not fully enabled",
                                      "Set kernel.randomize_va_space=2"),
        "net.ipv4.conf.all.accept_redirects": ("0", "MEDIUM", "ICMP redirects accepted",
                                                "Set net.ipv4.conf.all.accept_redirects=0"),
        "net.ipv4.conf.all.send_redirects": ("0", "MEDIUM", "Sending ICMP redirects allowed",
                                              "Set net.ipv4.conf.all.send_redirects=0"),
        "net.ipv4.tcp_syncookies": ("1", "MEDIUM", "SYN flood protection disabled",
                                    "Set net.ipv4.tcp_syncookies=1"),
        "kernel.dmesg_restrict": ("1", "LOW", "dmesg accessible to unprivileged users",
                                  "Set kernel.dmesg_restrict=1"),
        "kernel.kptr_restrict": ("2", "MEDIUM", "Kernel pointers exposed",
                                 "Set kernel.kptr_restrict=2"),
        "fs.suid_dumpable": ("0", "MEDIUM", "Core dumps from SUID processes enabled",
                             "Set fs.suid_dumpable=0"),
        "net.ipv4.conf.all.rp_filter": ("1", "MEDIUM", "Reverse path filtering disabled",
                                         "Set net.ipv4.conf.all.rp_filter=1"),
    }

    for key, (expected, sev, title, fix) in sysctl_checks.items():
        val = run(["sysctl", "-n", key])
        if val and val.strip() != expected:
            add_finding(sev, "Kernel", title, f"Current: {key}={val}  →  {fix}")


def check_unattended_upgrades():
    section("Automatic Updates")

    auto_upgrade = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    unattended   = Path("/etc/apt/apt.conf.d/50unattended-upgrades")

    if auto_upgrade.exists():
        content = auto_upgrade.read_text()
        if 'APT::Periodic::Unattended-Upgrade "1"' in content:
            add_finding("INFO", "Updates", "Unattended security upgrades are enabled", "")
        else:
            add_finding("MEDIUM", "Updates", "Automatic unattended upgrades not configured",
                        "Enable: sudo dpkg-reconfigure unattended-upgrades")
    else:
        # Check dnf/yum
        dnf_auto = Path("/etc/dnf/automatic.conf")
        if dnf_auto.exists():
            add_finding("INFO", "Updates", "dnf-automatic config found — verify it's enabled", "")
        else:
            add_finding("MEDIUM", "Updates", "No automatic update configuration detected",
                        "Consider enabling automatic security updates")


def check_services():
    section("Running Services")

    output = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
    risky = {
        "telnet": "CRITICAL", "rsh": "CRITICAL", "rlogin": "CRITICAL",
        "rexec": "CRITICAL", "tftp": "HIGH", "finger": "HIGH",
        "avahi-daemon": "LOW", "cups": "LOW", "bluetooth": "LOW",
        "nfs": "MEDIUM", "rpcbind": "MEDIUM",
    }

    found = []
    for name, sev in risky.items():
        if name in output.lower():
            found.append((sev, name))

    for sev, name in sorted(found, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0])):
        add_finding(sev, "Services", f"Potentially unnecessary service running: {name}",
                    f"Disable if not needed: sudo systemctl disable --now {name}")

    if not found:
        add_finding("INFO", "Services", "No obviously risky services detected", "")


def check_cron():
    section("Cron Jobs")

    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly"
    ]

    all_jobs = []
    for d in cron_dirs:
        p = Path(d)
        if p.is_dir():
            for f in p.iterdir():
                try:
                    content = f.read_text()
                    for line in content.splitlines():
                        if not line.startswith("#") and line.strip():
                            all_jobs.append(f"{f}: {line.strip()}")
                except PermissionError:
                    pass

    # /etc/crontab
    try:
        all_jobs += [f"/etc/crontab: {l}" for l in Path("/etc/crontab").read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
    except Exception:
        pass

    # World-writable cron scripts
    ww_cron = []
    for job in all_jobs:
        # Extract path-like tokens
        for token in job.split():
            if token.startswith("/") and Path(token).exists():
                try:
                    st = os.stat(token)
                    if st.st_mode & stat.S_IWOTH:
                        ww_cron.append(token)
                except OSError:
                    pass

    if ww_cron:
        add_finding("HIGH", "Cron", "World-writable scripts referenced in cron jobs",
                    "\n".join(ww_cron))

    if all_jobs:
        add_finding("INFO", "Cron", f"{len(all_jobs)} cron job(s) found",
                    "\n".join(all_jobs[:10]))
    else:
        add_finding("INFO", "Cron", "No system cron jobs found", "")


def check_passwd_shadow_perms():
    section("Critical File Permissions")

    file_checks = {
        "/etc/passwd":  (0o644, "MEDIUM"),
        "/etc/shadow":  (0o640, "HIGH"),
        "/etc/sudoers": (0o440, "HIGH"),
        "/etc/ssh/sshd_config": (0o600, "MEDIUM"),
        "/boot/grub/grub.cfg":  (0o600, "LOW"),
    }

    for path, (expected_mode, sev) in file_checks.items():
        p = Path(path)
        if not p.exists():
            continue
        try:
            actual = stat.S_IMODE(os.stat(path).st_mode)
            if actual > expected_mode:
                add_finding(sev, "File Perms",
                            f"Permissions too permissive on {path}",
                            f"Current: {oct(actual)}  Expected: ≤{oct(expected_mode)}")
        except PermissionError:
            pass


# ─── Summary ──────────────────────────────────────────────────────────────────

def print_summary():
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1

    print(f"\n{c(BOLD, '━' * 60)}")
    print(c(BOLD, "  SCAN SUMMARY"))
    print(c(BOLD, '━' * 60))
    print(f"  Total findings: {len(findings)}")
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
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"vuln_report_{ts}.json"
    with open(report_path, "w") as f:
        json.dump({
            "scan_time": ts,
            "hostname": run(["hostname"]),
            "kernel": run(["uname", "-r"]),
            "findings": findings
        }, f, indent=2)
    print(f"\n  📄 Full report saved to: {c(CYAN, report_path)}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(c(BOLD, "\n╔══════════════════════════════════════════════════════════╗"))
    print(c(BOLD,   "║          Linux Vulnerability Scanner                    ║"))
    print(c(BOLD,   "╚══════════════════════════════════════════════════════════╝"))
    print(f"  Host : {run(['hostname'])}")
    print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  User : {run(['whoami'])}")
    if os.geteuid() != 0:
        print(f"\n  {c(YELLOW, '⚠  Not running as root — some checks will be limited.')}")
        print(f"     Re-run with: {c(CYAN, 'sudo python3 ' + sys.argv[0])}\n")

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

    print_summary()
    save_report()
    print()


if __name__ == "__main__":
    main()
