"""Check reachability of Tor Project endpoint."""

from __future__ import annotations

import urllib.request


def run(net):
    try:
        with urllib.request.urlopen("https://check.torproject.org", timeout=8) as resp:
            ok = resp.status == 200
    except Exception:
        ok = False

    if ok:
        return [{"type": "tor", "severity": "info", "message": "Tor website reachable", "source": "tor"}]

    return [{"type": "tor", "severity": "warning", "message": "Tor endpoint unreachable or filtered", "source": "tor"}]
