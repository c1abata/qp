"""Discover live hosts on local subnet."""

from __future__ import annotations

import re
import shutil
import subprocess


def run(net):
    events = []
    subnet = net.get("subnet")
    if not subnet:
        return [{"type": "net_scan", "severity": "warning", "message": "No subnet available", "source": "net_discovery"}]

    if not shutil.which("nmap"):
        return [{"type": "net_scan", "severity": "info", "message": "nmap not installed, net_discovery skipped", "source": "net_discovery"}]

    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-n", "-T2", subnet],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=75,
        )
    except Exception as exc:
        return [{"type": "net_scan", "severity": "warning", "message": f"nmap ping scan failed: {exc}", "source": "net_discovery"}]

    hosts = re.findall(r"Nmap scan report for\s+(\S+)", out)
    events.append({
        "type": "net_scan",
        "severity": "info",
        "message": f"Hosts discovered: {len(hosts)}",
        "source": "net_discovery",
    })
    return events
