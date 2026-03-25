"""
tasks/presec.py - PRE-SEC Area
Checks: traceroute, UDP outbound filtering, TCP scan subnet, NAT hairpinning,
        firewall detection, egress filtering.
"""

import re
import random
import subprocess
import logging

log = logging.getLogger(__name__)
AREA = "PRESEC"


def _run(cmd, out_file=None, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        if out_file:
            open(out_file, "w").write(out)
        return out
    except subprocess.TimeoutExpired:
        log.warning(f"Timeout: {' '.join(str(c) for c in cmd)}")
        return ""
    except Exception as e:
        log.error(f"_run: {e}")
        return ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_traceroute(cfg, out_dir, alerter):
    """Traceroute external. Recon hop anomaly o asimmetric."""
    findings = []
    target = cfg["General"]["target_external"]
    out = _run(
        ["traceroute", "-I", "-n", "-w", "2", "-q", "1", target],
        out_file=f"{out_dir}/traceroute.txt",
        timeout=60
    )
    hops = re.findall(r'^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)', out, re.M)
    hop_count = len([h for h in hops if h[1] != "*"])

    if hop_count == 0:
        msg = f"Traceroute fallito verso {target} (firewall block ICMP?)"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")
    elif hop_count > 15:
        msg = f"Path too long: {hop_count} hop to {target}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    else:
        log.info(f"Traceroute: {hop_count} hop verso {target}")

    return findings


def check_udp_outbound(cfg, out_dir, alerter):
    """
    Check UDP.
    """
    findings = []
    target = cfg["General"]["target_external"]
    test_ports = [53, 123, 443, 500, 4500, 1194] + random.sample(range(1024, 10000), 4)
    port_str = ",".join(map(str, test_ports))

    out = _run(
        ["nmap", "-sU", "-n", "-T2", "-p", port_str, "--max-retries=1",
         "--host-timeout=30s", target,
         "-oN", f"{out_dir}/udp_outbound.txt"],
        timeout=90
    )
    open_ports     = re.findall(r'(\d+)/udp\s+open\b', out)
    filtered_ports = re.findall(r'(\d+)/udp\s+open\|filtered', out)

    msg = (f"UDP outbound: open={open_ports or 'nothing'}, "
           f"filtered={filtered_ports or 'nothing'}")
    findings.append(msg)
    if open_ports:
        alerter.finding(AREA, msg, level="info")
    else:
        alerter.finding(AREA, "Tutto il traffico UDP outbound sembra filtrato", level="warning")

    return findings


def check_tcp_services(cfg, out_dir, alerter):
    """TCP scan local subnet - Find Service Exposed"""
    findings = []
    subnet = cfg["General"]["local_subnet"]
    ports  = cfg.get("Scan", "tcp_service_ports",
                     fallback="21,22,23,25,80,443,8080,8443,8181,3389,4444,5900")

    out = _run(
        ["nmap", "-sS", "-n", "-T2", "-p", ports, "--open", "--max-retries=1",
         "-oG", f"{out_dir}/tcp_services.gnmap", subnet],
        timeout=300
    )
    # Leggi il gnmap
    try:
        gnmap = open(f"{out_dir}/tcp_services.gnmap").read()
    except Exception:
        gnmap = ""

    DANGEROUS = {"23": "Telnet", "4444": "Metasploit?", "3389": "RDP",
                 "5900": "VNC", "21": "FTP"}
    for port, name in DANGEROUS.items():
        if f"{port}/open" in gnmap:
            hosts = re.findall(rf'Host:\s+(\S+).*?{port}/open', gnmap)
            msg = f"Porta risk {port}/{name} listening on: {hosts}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")

    # Conteggio totale host con porte aperte
    all_hosts = re.findall(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', gnmap)
    if all_hosts:
        msg = f"TCP Open: {len(set(all_hosts))}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")

    return findings


def check_nat_hairpin(cfg, out_dir, alerter):
    """NAT hairpinning with STUN."""
    findings = []
    out = _run(
        ["stunclient", "--mode", "full", "stun.l.google.com", "19302"],
        out_file=f"{out_dir}/nat_hairpin.txt",
        timeout=15
    )
    if not out:
        # Fallback: usa nc per testare connettività STUN base
        out = _run(["nc", "-zu", "-w3", "stun.l.google.com", "19302"])
        open(f"{out_dir}/nat_hairpin.txt", "w").write(out or "stunclient not available")

    if "hairpin" in out.lower() or "reflection" in out.lower():
        msg = "NAT hairpinning (reflection) found"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    elif "nat type" in out.lower():
        nat_type = re.search(r'nat type[:\s]+([^\n]+)', out, re.I)
        if nat_type:
            msg = f"NAT type: {nat_type.group(1).strip()}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="info")

    return findings


def check_egress_tcp(cfg, out_dir, alerter):
    """
    Verifica quali porte TCP uscenti sono permesse.
    Check TCP Outbound.
    """
    findings = []
    target = cfg["General"]["target_external"]
    test_ports = [80, 443, 8080, 8443, 25, 465, 587, 22, 53, 21, 5061, ]

    results = {"open": [], "filtered": []}
    with open(f"{out_dir}/egress_tcp.txt", "w") as f:
        for port in test_ports:
            out = _run(
                ["nc", "-zv", "-w2", target, str(port)],
                timeout=5
            )
            status = "open" if "succeeded" in out.lower() or "connected" in out.lower() else "filtered"
            results[status].append(port)
            f.write(f"TCP {port}: {status}\n")

    msg = f"Egress TCP — open: {results['open']}, filtered: {results['filtered']}"
    findings.append(msg)

    # Porte pericolose uscenti aperte
    risky_out = [p for p in results["open"] if p in (25, 587)]
    if risky_out:
        alerter.finding(AREA, f"Porta SMTP: {risky_out} (relay/spam risk)", level="warning")
    else:
        alerter.finding(AREA, msg, level="info")

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

PASSIVE_CHECKS = [
    check_traceroute,
    check_udp_outbound,
    check_nat_hairpin,
    check_egress_tcp,
]

ACTIVE_ONLY_CHECKS = [
    check_tcp_services,
]

def run(cfg, out_dir, alerter, mode="active"):
    all_findings = []
    checks = list(PASSIVE_CHECKS)
    if mode == "active":
        checks.extend(ACTIVE_ONLY_CHECKS)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                all_findings.extend(result)
        except Exception as e:
            msg = f"`{check.__name__}` errore: {e}"
            log.error(msg)
            alerter.finding(AREA, msg, level="error")
    return all_findings
