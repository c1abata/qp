"""Heuristic DNS tunneling detector based on packet sample length."""

from __future__ import annotations

import shutil
import subprocess


def run(net):
    iface = net.get("iface")
    if not iface:
        return []

    if not shutil.which("tcpdump"):
        return [{"type": "dns_tunnel", "severity": "info", "message": "tcpdump not installed, dns_tunnelling skipped", "source": "dns_tunnelling"}]

    try:
        out = subprocess.check_output(
            ["tcpdump", "-n", "-l", "-i", iface, "udp", "port", "53", "-c", "80"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=35,
        )
    except Exception:
        return []

    for line in out.splitlines():
        # Long DNS payloads can indicate data encoding/exfiltration patterns.
        if len(line) > 190:
            return [{
                "type": "dns_tunnel",
                "severity": "warning",
                "message": "Possible DNS tunneling pattern (long DNS packet lines)",
                "source": "dns_tunnelling",
            }]

    return []
