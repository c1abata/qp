"""
tasks/udp.py - UDP Area
Checks: UDP random scan, QUIC, common UDP.
"""

import random
import re
import subprocess
import logging

log = logging.getLogger(__name__)
AREA = "UDP"


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        log.warning(f"Timeout: {' '.join(str(c) for c in cmd)}")
        return ""
    except Exception as e:
        log.error(f"_run: {e}")
        return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pick_ports(ranges_str, n_per_range=5):
    """Selected N random port from range in config.ini ."""
    ports = []
    for r in ranges_str.split(","):
        r = r.strip()
        if "-" in r:
            lo, hi = map(int, r.split("-"))
            sample = random.sample(range(lo, hi + 1), min(n_per_range, hi - lo + 1))
            ports.extend(sample)
        else:
            ports.append(int(r))
    return ports


COMMON_UDP = {
    53:   "DNS",
    67:   "DHCP",
    123:  "NTP",
    161:  "SNMP",
    500:  "IKE/VPN",
    4500: "NAT-T VPN",
    443:  "QUIC",
    1194: "OpenVPN",
    5353: "mDNS",
}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_udp_random_scan(cfg, out_dir, alerter):
    """Random UDP to external target."""
    findings = []
    target  = cfg["General"]["target_external"]
    ranges  = cfg.get("Scan", "udp_port_ranges", fallback="1-1024,40000-60000")
    ports   = _pick_ports(ranges, n_per_range=6)
    # Aggiungi sempre le porte UDP notevoli
    ports   = list(set(ports + list(COMMON_UDP.keys())))
    random.shuffle(ports)
    port_str = ",".join(map(str, ports))

    log.info(f"UDP scan su {target}: {port_str}")
    out = _run(
        ["nmap", "-sU", "-p", port_str,
         "--max-retries=1", "--host-timeout=60s",
         "-oN", f"{out_dir}/udp_scan.txt", target],
        timeout=180
    )

    # Analisi risultati
    open_ports   = re.findall(r'(\d+)/udp\s+open\b', out)
    filtered_ports = re.findall(r'(\d+)/udp\s+open\|filtered', out)

    with open(f"{out_dir}/udp_summary.txt", "w") as f:
        f.write(f"Target: {target}\n")
        f.write(f"Porte testate: {port_str}\n")
        f.write(f"Aperte: {open_ports}\n")
        f.write(f"Open|Filtered: {filtered_ports}\n")

    if open_ports:
        named = [f"{p}({COMMON_UDP.get(int(p), '?')})" for p in open_ports]
        msg = f"UDP aperte verso {target}: {named}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_quic(cfg, out_dir, alerter):
    """Verifica se QUIC (UDP/443) è raggiungibile."""
    findings = []
    target = cfg["General"]["target_external"]
    # curl con HTTP/3 per testare QUIC
    out = _run(
        ["curl", "-sf", "--http3", f"https://{target}", "-o", "/dev/null",
         "-w", "%{http_version}", "--max-time", "10"],
        timeout=15
    )
    with open(f"{out_dir}/quic.txt", "w") as f:
        f.write(out)

    if "3" in out:
        msg = f"QUIC (HTTP/3) disponibile verso {target}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    else:
        msg = f"QUIC non disponibile verso {target}"
        findings.append(msg)

    return findings


def check_ntp(cfg, out_dir, alerter):
    """Verifica NTP (UDP/123) - possibile amplification vector."""
    findings = []
    target = cfg["General"]["target_external"]
    out = _run(
        ["ntpdate", "-q", "-u", target],
        timeout=10
    )
    with open(f"{out_dir}/ntp.txt", "w") as f:
        f.write(out)

    if "stratum" in out.lower() or "offset" in out.lower():
        msg = f"NTP risponde su {target} (UDP/123)"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CHECKS = [check_udp_random_scan, check_quic, check_ntp]

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
