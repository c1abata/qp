"""Simple ARP table anomaly detector."""

from __future__ import annotations

import re
import subprocess


def run(net):
    try:
        out = subprocess.check_output(["arp", "-an"], text=True, stderr=subprocess.DEVNULL, timeout=8)
    except Exception:
        return []

    mac_to_ips = {}
    for line in out.splitlines():
        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line.lower())
        if not match:
            continue
        ip, mac = match.group(1), match.group(2)
        mac_to_ips.setdefault(mac, set()).add(ip)

    suspicious = {mac: sorted(ips) for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if not suspicious:
        return []

    return [{
        "type": "arp_spoof",
        "severity": "warning",
        "message": f"Duplicate MAC entries found in ARP table: {suspicious}",
        "source": "mitm_detect",
    }]
