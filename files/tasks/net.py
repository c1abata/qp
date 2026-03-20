"""
tasks/net.py - NET Area
Checks: IP config, VLAN, IPv6, ARP scan, MAC spoofing, ARP sniffing + OUI lookup.

Ogni check è una funzione autonoma. Aggiungere un check = aggiungere una funzione
e inserirla nella lista CHECKS in fondo. Zero magia, zero dipendenze nascoste.
"""

import os
import re
import subprocess
import logging
import requests

log = logging.getLogger(__name__)

AREA = "NET"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run(cmd, out_file=None, timeout=30):
    """Esegui comando, scrivi output su file se specificato. Ritorna stdout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        if out_file:
            with open(out_file, "w") as f:
                f.write(output)
        return output
    except subprocess.TimeoutExpired:
        log.warning(f"Timeout: {' '.join(cmd)}")
        return ""
    except Exception as e:
        log.error(f"_run {cmd[0]}: {e}")
        return ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_ip_config(cfg, out_dir, alerter):
    """IP, route, DNS resolver."""
    findings = []
    out = ""
    out += _run(["ip", "addr"])
    out += _run(["ip", "route"])
    out += _run(["cat", "/etc/resolv.conf"])
    with open(f"{out_dir}/ipconfig.txt", "w") as f:
        f.write(out)

    # Cerca IP multipli (multihoming)
    ips = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', out)
    public_ips = [ip for ip in ips if not ip.startswith(("10.", "192.168.", "172.", "127.", "169.254."))]
    if public_ips:
        msg = f"IP pubblici rilevati sull'host: {public_ips}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_vlan(cfg, out_dir, alerter):
    """VLAN tagging."""
    findings = []
    out = _run(["ip", "-d", "link", "show"], out_file=f"{out_dir}/vlan.txt")
    if "vlan" in out.lower() or "802.1q" in out.lower():
        msg = "VLAN tagging rilevato sull'interfaccia"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    return findings


def check_ipv6(cfg, out_dir, alerter):
    """IPv6 addresses e route."""
    findings = []
    out = _run(["ip", "-6", "addr"], out_file=f"{out_dir}/ipv6.txt")
    _run(["ip", "-6", "route"], out_file=f"{out_dir}/ipv6_route.txt")
    addrs = re.findall(r'inet6\s+([^\s]+)', out)
    global_v6 = [a for a in addrs if not a.startswith("fe80") and not a.startswith("::1")]
    if global_v6:
        msg = f"Indirizzi IPv6 globali attivi: {global_v6}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    return findings


def check_arp_scan(cfg, out_dir, alerter):
    """ARP scan della subnet locale per scoprire host attivi."""
    findings = []
    subnet = cfg["General"]["local_subnet"]
    out = _run(["arp-scan", "--localnet", subnet],
               out_file=f"{out_dir}/arp_scan.txt", timeout=60)

    # Conta host
    hosts = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})', out.lower())
    if hosts:
        msg = f"Host L2 rilevati: {len(hosts)} — {[h[0] for h in hosts]}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")

    # Host con vendor sconosciuto o "UNKNOWN"
    unknowns = [h[0] for h in hosts if "unknown" in out.lower()]
    if unknowns:
        msg = f"Host con vendor MAC sconosciuto: {unknowns}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_mac_spoof(cfg, out_dir, alerter):
    """Verifica se il MAC spoofing è fattibile (capability check)."""
    findings = []
    iface = cfg["General"]["interface"]
    out = _run(["macchanger", "-s", iface], out_file=f"{out_dir}/mac_spoof.txt")
    if "permanent" in out.lower() and "current" in out.lower():
        perm    = re.search(r'Permanent MAC:\s+([0-9a-f:]{17})', out, re.I)
        current = re.search(r'Current MAC:\s+([0-9a-f:]{17})', out, re.I)
        if perm and current and perm.group(1).lower() != current.group(1).lower():
            msg = f"MAC già modificato su {iface}: perm={perm.group(1)}, current={current.group(1)}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")
        else:
            msg = f"MAC spoofing praticabile su {iface} (macchanger disponibile)"
            findings.append(msg)
            alerter.finding(AREA, msg, level="warning")
    return findings


def check_arp_sniff(cfg, out_dir, alerter):
    """
    Cattura ARP per 30 sec, identifica pacchetti non destinati a noi.
    Usa tcpdump invece di scapy per ridurre le dipendenze.
    """
    findings = []
    iface  = cfg["General"]["interface"]
    pcap   = f"{out_dir}/arp_sniff.pcap"
    report = f"{out_dir}/foreign_arp.txt"

    # Leggi il nostro MAC
    try:
        my_mac = open(f"/sys/class/net/{iface}/address").read().strip().lower()
    except Exception:
        my_mac = ""

    # Cattura con tcpdump per 30 sec
    _run(["tcpdump", "-i", iface, "-w", pcap, "arp", "-G", "30", "-W", "1"],
         timeout=35)

    # Analizza con tcpdump in modalità lettura
    out = _run(["tcpdump", "-r", pcap, "-e", "-n", "arp"], timeout=10)
    lines = out.splitlines()

    foreign = []
    for line in lines:
        # Cerca pacchetti ARP con destinazione MAC diversa dalla nostra
        m = re.search(r'> ([0-9a-f:]{17})', line.lower())
        if m and my_mac and m.group(1) not in (my_mac, "ff:ff:ff:ff:ff:ff"):
            foreign.append(line.strip())

    with open(report, "w") as f:
        f.write(f"Nostro MAC: {my_mac}\n")
        f.write(f"ARP packet totali: {len(lines)}\n")
        f.write(f"Pacchetti non diretti a noi: {len(foreign)}\n\n")
        f.write("\n".join(foreign))

    if foreign:
        msg = f"Sniffing ARP promiscuo: {len(foreign)} pacchetti altrui ricevuti"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CHECKS = [
    check_ip_config,
    check_vlan,
    check_ipv6,
    check_arp_scan,
    check_mac_spoof,
    check_arp_sniff,
]

def run(cfg, out_dir, alerter):
    """Esegui tutti i check NET. Ritorna lista di findings."""
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
