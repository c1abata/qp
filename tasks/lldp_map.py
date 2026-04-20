"""LLDP neighbor discovery."""

from __future__ import annotations

import shutil
import subprocess


def run(net):
    if not shutil.which("lldpcli"):
        return [{"type": "lldp", "severity": "info", "message": "lldpcli not installed, lldp map skipped", "source": "lldp_map"}]

    try:
        out = subprocess.check_output(["lldpcli", "show", "neighbors"], text=True, stderr=subprocess.DEVNULL, timeout=10)
    except Exception:
        return []

    if not out.strip():
        return []

    return [{
        "type": "lldp",
        "severity": "info",
        "message": "LLDP neighbors discovered",
        "source": "lldp_map",
    }]
