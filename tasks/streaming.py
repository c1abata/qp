"""Connectivity probe for common streaming services."""

from __future__ import annotations

import urllib.request


SERVICES = {
    "youtube": "https://www.youtube.com",
    "netflix": "https://www.netflix.com",
    "twitch": "https://www.twitch.tv",
}


def run(net):
    events = []
    for name, url in SERVICES.items():
        try:
            with urllib.request.urlopen(url, timeout=6) as resp:
                ok = 200 <= int(resp.status) < 400
        except Exception:
            ok = False

        if ok:
            events.append({"type": "stream", "severity": "info", "message": f"{name} reachable", "source": "streaming"})
        else:
            events.append({"type": "stream", "severity": "warning", "message": f"{name} blocked or unreachable", "source": "streaming"})
    return events
