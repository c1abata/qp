"""Passive packet observation using tcpdump."""

from __future__ import annotations

import shutil
import subprocess


def run(net):
    iface = net.get("iface")
    if not iface:
        return [{"type": "passive", "severity": "warning", "message": "No interface selected", "source": "passive_scan"}]

    if not shutil.which("tcpdump"):
        return [{"type": "passive", "severity": "info", "message": "tcpdump not installed, passive_scan skipped", "source": "passive_scan"}]

    try:
        out = subprocess.check_output(
            ["tcpdump", "-n", "-i", iface, "-c", "60"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=65,
        )
    except Exception as exc:
        return [{"type": "passive", "severity": "warning", "message": f"tcpdump passive scan failed: {exc}", "source": "passive_scan"}]

    events = []
    if " ARP," in out or "ARP," in out:
        events.append({"type": "passive", "severity": "info", "message": "ARP traffic observed", "source": "passive_scan"})
    if " DHCP" in out:
        events.append({"type": "passive", "severity": "info", "message": "DHCP traffic observed", "source": "passive_scan"})
    if not events:
        events.append({"type": "passive", "severity": "info", "message": "No notable L2/L3 chatter in sample window", "source": "passive_scan"})
    return events
