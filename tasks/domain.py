"""
tasks/domain.py - DOMAIN Area
Checks: Active Directory (SRV records, LDAP ports), mDNS, NetBIOS.
"""

import os
import re
import subprocess
import logging

log = logging.getLogger(__name__)
AREA = "DOMAIN"


def _run(cmd, out_file=None, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        if out_file:
            open(out_file, "w").write(out)
        return out
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        log.error(f"_run {cmd[0]}: {e}")
        return ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_ad_srv(cfg, out_dir, alerter):
    """Interroga record SRV tipici di Active Directory."""
    findings = []
    # Ricava il dominio di ricerca da resolv.conf
    try:
        resolv = open("/etc/resolv.conf").read()
        m = re.search(r'search\s+(\S+)', resolv)
        domain = m.group(1) if m else "local"
    except Exception:
        domain = "local"

    srv_records = [
        f"_ldap._tcp.{domain}",
        f"_kerberos._tcp.{domain}",
        f"_gc._tcp.{domain}",
        f"_kpasswd._tcp.{domain}",
    ]
    found = []
    with open(f"{out_dir}/ad_srv.txt", "w") as f:
        for rec in srv_records:
            out = _run(["dig", rec, "SRV", "+short", "+time=3"])
            f.write(f"=== {rec} ===\n{out}\n")
            if out.strip():
                found.append(rec)

    if found:
        msg = f"Active Directory SRV records trovati: {found}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_ldap_ports(cfg, out_dir, alerter):
    """Scansione porte LDAP sulla subnet locale."""
    findings = []
    subnet = cfg["General"]["local_subnet"]
    out = _run(
        ["nmap", "-p", "389,636,3268,3269", "--open", "-T4",
         "-oG", f"{out_dir}/ldap_scan.gnmap", subnet],
        timeout=120
    )
    # Leggi il gnmap per host trovati
    gnmap = ""
    try:
        gnmap = open(f"{out_dir}/ldap_scan.gnmap").read()
    except Exception:
        pass

    hosts_with_ldap = re.findall(r'Host:\s+(\d+\.\d+\.\d+\.\d+)[^\n]+open', gnmap)
    if hosts_with_ldap:
        msg = f"Porte LDAP/AD aperte su: {hosts_with_ldap}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_mdns_netbios(cfg, out_dir, alerter):
    """Rileva servizi mDNS e NetBIOS per fingerprinting OS/host."""
    findings = []
    subnet = cfg["General"]["local_subnet"]
    # nmap con script smb e mdns
    out = _run(
        ["nmap", "-p", "5353,137,138,139,445", "--open", "-T4",
         "--script", "nbstat,dns-service-discovery",
         "-oN", f"{out_dir}/mdns_netbios.txt", subnet],
        timeout=120
    )
    if "445/open" in out or "139/open" in out:
        hosts = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?445/open', out)
        msg = f"Servizi SMB/NetBIOS attivi: {hosts}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CHECKS = [check_ad_srv, check_ldap_ports, check_mdns_netbios]

def run(cfg, out_dir, alerter):
    all_findings = []
    for check in CHECKS:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                all_findings.extend(result)
        except Exception as e:
            msg = f"`{check.__name__}` errore: {e}"
            log.error(msg)
            alerter.finding(AREA, msg, level="error")
    return all_findings
