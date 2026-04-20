"""Detect VLAN tags and 802.1X/EAPOL frames."""

from __future__ import annotations

import shutil
import subprocess


def run(net):
    iface = net.get("iface")
    if not iface:
        return []

    if not shutil.which("tcpdump"):
        return [{"type": "vlan_detect", "severity": "info", "message": "tcpdump not installed, vlan_8021x skipped", "source": "vlan_8021x"}]

    events = []

    try:
        vlan_out = subprocess.check_output(
            ["tcpdump", "-n", "-e", "-i", iface, "vlan", "-c", "30"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        if vlan_out.strip():
            events.append({"type": "vlan_detect", "severity": "info", "message": "802.1Q VLAN tagged traffic detected", "source": "vlan_8021x"})
    except Exception:
        pass

    try:
        eapol_out = subprocess.check_output(
            ["tcpdump", "-n", "-e", "-i", iface, "ether", "proto", "0x888e", "-c", "20"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        if eapol_out.strip():
            events.append({"type": "vlan_detect", "severity": "info", "message": "802.1X/EAPOL authentication frames detected", "source": "vlan_8021x"})
    except Exception:
        pass

    return events
