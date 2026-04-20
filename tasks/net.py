"""tasks/net.py - fast network posture checks.

Design goals:
- low false positives
- bounded runtime
- useful output for operators
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess


AREA = "NET"


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def _write(path: str, content: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError:
        pass


def _is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def check_interface_snapshot(cfg, out_dir, alerter):
    findings = []

    iface = cfg["General"].get("interface", "")
    ip_out = _run(["ip", "-4", "addr", "show", iface] if iface else ["ip", "-4", "addr", "show"])
    route_out = _run(["ip", "route", "show"])
    resolv_out = _run(["cat", "/etc/resolv.conf"])

    _write(os.path.join(out_dir, "interface_snapshot.txt"), f"{ip_out}\n\n{route_out}\n\n{resolv_out}\n")

    public_ips = []
    for ip in re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_out):
        if ip.startswith("127."):
            continue
        if not _is_private_ipv4(ip):
            public_ips.append(ip)

    if public_ips:
        msg = f"Public IPv4 assigned on local interface: {sorted(set(public_ips))}"
        findings.append({"type": "net_public_ip", "severity": "info", "message": msg, "source": "net"})
        # info by default to avoid false alarms on cloud hosts.
        alerter.finding(AREA, msg, level="info")

    return findings


def check_vlan_presence(cfg, out_dir, alerter):
    findings = []

    out = _run(["ip", "-d", "link", "show"])
    _write(os.path.join(out_dir, "vlan_link.txt"), out)

    if " vlan " in out.lower() or "802.1q" in out.lower():
        msg = "VLAN tagging detected on one or more interfaces"
        findings.append({"type": "vlan_detect", "severity": "info", "message": msg, "source": "net"})
        alerter.finding(AREA, msg, level="info")

    return findings


def check_arp_consistency(cfg, out_dir, alerter):
    findings = []

    out = _run(["arp", "-an"])
    _write(os.path.join(out_dir, "arp_table.txt"), out)

    mac_to_ips = {}
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line.lower())
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        mac_to_ips.setdefault(mac, set()).add(ip)

    suspicious = {mac: sorted(ips) for mac, ips in mac_to_ips.items() if len(ips) >= 3}
    if suspicious:
        msg = f"ARP mapping anomaly (same MAC mapped to >=3 IPs): {suspicious}"
        findings.append({"type": "arp_anomaly", "severity": "warning", "message": msg, "source": "net"})
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_l2_visibility(cfg, out_dir, alerter):
    """Optional quick L2 probe using tcpdump in active mode only."""
    findings = []

    iface = cfg["General"].get("interface", "")
    if not iface:
        return findings

    if not shutil.which("tcpdump"):
        return findings

    out = _run(["tcpdump", "-n", "-e", "-i", iface, "-c", "25"], timeout=15)
    _write(os.path.join(out_dir, "l2_probe.txt"), out)

    if "0x888e" in out or "EAPOL" in out.upper():
        msg = "802.1X/EAPOL frames observed"
        findings.append({"type": "dot1x", "severity": "info", "message": msg, "source": "net"})
        alerter.finding(AREA, msg, level="info")

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []

    checks = [
        check_interface_snapshot,
        check_vlan_presence,
        check_arp_consistency,
    ]

    if mode == "active":
        checks.append(check_l2_visibility)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                findings.extend(result)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings
