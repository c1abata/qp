"""Detect potential rogue DHCP servers from live capture."""

from __future__ import annotations

import re
import shutil
import subprocess


def _extract_source(line: str) -> str:
    match = re.search(r"IP\s+(\d+\.\d+\.\d+\.\d+)\.67", line)
    return match.group(1) if match else ""


def run(net):
    iface = net.get("iface")
    gateway = net.get("gateway")

    if not iface:
        return []

    if not shutil.which("tcpdump"):
        return [{"type": "dhcp_rogue", "severity": "info", "message": "tcpdump not installed, dhcp_rogue skipped", "source": "dhcp_rogue"}]

    try:
        out = subprocess.check_output(
            ["tcpdump", "-n", "-i", iface, "port", "67", "-c", "20"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=22,
        )
    except Exception:
        return []

    servers = {src for src in (_extract_source(line) for line in out.splitlines()) if src}
    if not servers:
        return []

    if len(servers) > 1:
        rogue = sorted(s for s in servers if gateway and s != gateway)
        return [{
            "type": "dhcp_rogue",
            "severity": "critical",
            "message": f"Multiple DHCP servers detected: {sorted(servers)} rogue_candidates={rogue}",
            "source": "dhcp_rogue",
        }]

    server = next(iter(servers))
    severity = "info" if not gateway or server == gateway else "warning"
    return [{
        "type": "dhcp_rogue",
        "severity": severity,
        "message": f"DHCP server observed: {server}",
        "source": "dhcp_rogue",
    }]
